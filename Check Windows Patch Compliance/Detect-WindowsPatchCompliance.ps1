<#
.SYNOPSIS
    Intune custom compliance discovery script - Windows quality update (patch) compliance.
.DESCRIPTION
    Based on Gowdhaman Karthikeyan's WindowsUpdateComplianceScript.ps1
    (blogs.gowdhaman.in / github.com/gowdhamankarthikeyan/IntuneScripts), rewritten and fixed.

    How it works
      1. Reads the device's OS (Windows 10 / 11) and build (CurrentBuild.UBR).
      2. Downloads Microsoft's release-health page for that OS and parses the
         per-version release history tables.
      3. Keeps the monthly security (B) and out-of-band (OOB) releases from the
         last 12 months for the device's feature version. Preview (D) releases are
         ignored. OOB releases are kept only if their KB page applies to this OS.
      4. Counts how many of those releases are newer than the installed build
         (CurrentPatchLevel: 0 = current, 1 = one behind, ...).
      5. Reads the Windows Update deferral / deadline / grace period policies and
         works out how many releases the device is still allowed to be missing
         (RequiredPatchLevel), then sets isLatestForThisDevice.

    Two JSON rule files ship with this script:
      WindowsPatchCompliance-Basic.json     - fixed day threshold (DaysBehindLatest)
      WindowsPatchCompliance-RingAware.json - follows your update ring (isLatestForThisDevice)
    Intune allows one discovery script per policy, so to run both (or two thresholds)
    upload this script twice under different names.

    Results are also written to HKLM\SOFTWARE\WindowsUpdateCompliance for troubleshooting.

    Requirements
      - Device must reach learn.microsoft.com and support.microsoft.com as SYSTEM.
        If it can't, Status = CatalogUnavailable (non-compliant under the shipped rules).
      - Windows Insider builds report Status = BuildNotInCatalog.

    Upload settings: Run as logged-on user = No | Signature check = No | 64-bit host = Yes
    Returns a single line of compressed JSON only.
#>

# ---------------------------------------------------------------- settings
$LookbackMonths   = 12   # releases older than this are ignored
$MinimumGraceDays = 7    # floor on the grace window so a device isn't flagged on Patch Tuesday itself
$LogKey           = 'SOFTWARE\WindowsUpdateCompliance'
# -------------------------------------------------------------------------

$ProgressPreference    = 'SilentlyContinue'   # Invoke-WebRequest is very slow with progress on in PS 5.1
$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$ReleasePages = @{
    'Windows 11' = 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information'
    'Windows 10' = 'https://learn.microsoft.com/en-us/windows/release-health/release-information'
}

function Get-HKLM64 {
    # Always read/write the 64-bit registry view, even from a 32-bit PowerShell host
    [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
}

function Get-PolicyDays([string]$Name) {
    try {
        $key = (Get-HKLM64).OpenSubKey('SOFTWARE\Microsoft\PolicyManager\current\device\Update')
        if ($key) {
            $v = $key.GetValue($Name)
            if ($null -ne $v) { return [int]$v }
        }
    } catch {}
    return 0
}

function ConvertFrom-ReleaseHtml([string]$Html) {
    # Parse every release history table (the ones with an "Update type" column)
    $html = [System.Net.WebUtility]::HtmlDecode($Html)
    $opt  = [System.Text.RegularExpressions.RegexOptions]::Singleline
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($table in [regex]::Matches($html, '<table[^>]*>.*?</table>', $opt)) {
        $trs = [regex]::Matches($table.Value, '<tr[^>]*>(.*?)</tr>', $opt)
        if ($trs.Count -lt 2) { continue }

        $headers = @([regex]::Matches($trs[0].Groups[1].Value, '<t[hd][^>]*>(.*?)</t[hd]>', $opt) |
                     ForEach-Object { ($_.Groups[1].Value -replace '<[^>]+>', '').Trim() })
        $iType  = [array]::IndexOf($headers, 'Update type')
        $iDate  = [array]::IndexOf($headers, 'Availability date')
        $iBuild = [array]::IndexOf($headers, 'Build')
        $iKB    = [array]::IndexOf($headers, 'KB article')
        if ($iType -lt 0 -or $iDate -lt 0 -or $iBuild -lt 0) { continue }
        # Hotpatch calendar tables have an extra "Type" column (Baseline / Hotpatch).
        # They repeat each month's release under a hotpatch build number.
        $isHotpatch = ([array]::IndexOf($headers, 'Type') -ge 0)

        for ($r = 1; $r -lt $trs.Count; $r++) {
            $cells = @([regex]::Matches($trs[$r].Groups[1].Value, '<t[hd][^>]*>(.*?)</t[hd]>', $opt) |
                       ForEach-Object { $_.Groups[1].Value })
            if ($cells.Count -le [Math]::Max($iType, [Math]::Max($iDate, $iBuild))) { continue }

            $buildText = ($cells[$iBuild] -replace '<[^>]+>', '').Trim()
            $dateText  = ($cells[$iDate]  -replace '<[^>]+>', '').Trim()
            $build = $null; $date = [datetime]::MinValue
            if (-not [version]::TryParse($buildText, [ref]$build)) { continue }
            if (-not [datetime]::TryParseExact($dateText, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::None, [ref]$date)) { continue }

            $kb = ''; $link = ''
            if ($iKB -ge 0 -and $iKB -lt $cells.Count -and
                $cells[$iKB] -match 'href=["'']([^"'']+)["''][^>]*>\s*([^<]+?)\s*</a>') {
                $link = $Matches[1]; $kb = $Matches[2]
            }

            $rows.Add([pscustomobject]@{
                UpdateType = ($cells[$iType] -replace '<[^>]+>', '').Trim()
                Date       = $date
                Build      = $build
                KB         = $kb
                Link       = $link
                IsHotpatch = $isHotpatch
            })
        }
    }
    return $rows
}

function Test-OobAppliesTo([string]$Url, [string]$OsTag) {
    # OOB releases sometimes target only Server SKUs that share the build number.
    # If the KB page can't be read, the release is excluded (lenient: avoids false non-compliance).
    if (-not $Url) { return $false }
    try {
        $html = [System.Net.WebUtility]::HtmlDecode((Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 60).Content)
        $items = [regex]::Matches($html, '<span class="appliesToItem"[^>]*>(.*?)</span>',
                                  [System.Text.RegularExpressions.RegexOptions]::Singleline) |
                 ForEach-Object { $_.Groups[1].Value }
        return [bool](@($items) -match [regex]::Escape($OsTag))
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------- defaults
$Result = [ordered]@{
    OSName                            = ''
    OSBuildNumber                     = ''
    OSDisplayVersion                  = ''
    Status                            = 'Unknown'
    CurrentPatchLevel                 = [int64]-1
    RequiredPatchLevel                = [int64]0
    isLatestForThisDevice             = $false
    DaysBehindLatest                  = [int64]-1
    DaysSinceCurrentUpdateReleaseDate = [int64]-1
    DaysSinceLatestUpdateReleaseDate  = [int64]-1
    LatestApplicableBuild             = ''
    LatestApplicableKB                = ''
    TotalGraceDays                    = [int64]0
    EvaluatedAtUtc                    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

try {
    # ------------------------------------------------------------ device info
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cv = (Get-HKLM64).OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
    $currentBuild = [int]$cv.GetValue('CurrentBuild')
    $ubr          = [int]$cv.GetValue('UBR')
    $deviceBuild  = [version]"$currentBuild.$ubr"

    $Result.OSName           = [string]$os.Caption
    $Result.OSBuildNumber    = $deviceBuild.ToString()
    $Result.OSDisplayVersion = [string]$cv.GetValue('DisplayVersion')

    $osTag = $null
    if     ($os.Caption -match 'Windows 11') { $osTag = 'Windows 11' }
    elseif ($os.Caption -match 'Windows 10') { $osTag = 'Windows 10' }

    if (-not $osTag) {
        $Result.Status = 'UnsupportedOS'
    } else {
        # ------------------------------------------------------- catalog
        $catalog = $null
        try {
            $page    = Invoke-WebRequest -Uri $ReleasePages[$osTag] -UseBasicParsing -TimeoutSec 60
            $catalog = ConvertFrom-ReleaseHtml $page.Content
        } catch {
            $catalog = $null
        }

        if (-not $catalog -or $catalog.Count -eq 0) {
            $Result.Status = 'CatalogUnavailable'
        } else {
            # Standard releases for this feature version, de-duplicated (GA and LTSC tables share
            # builds). Hotpatch rows are kept aside so they aren't counted as extra releases.
            $forBuild = @($catalog | Where-Object { $_.Build.Major -eq $currentBuild -and -not $_.IsHotpatch } |
                          Group-Object { $_.Build.ToString() } | ForEach-Object { $_.Group[0] })
            $hotpatch = $catalog | Where-Object { $_.IsHotpatch -and $_.Build -eq $deviceBuild } | Select-Object -First 1

            if ($forBuild.Count -eq 0) {
                $Result.Status = 'BuildNotInCatalog'   # e.g. Insider build
            } else {
                $now    = Get-Date
                $cutoff = $now.Date.AddMonths(-$LookbackMonths)

                # Security (B) and out-of-band (OOB) releases only; preview (D) ignored
                $candidates = @($forBuild | Where-Object {
                    $_.UpdateType -match '(^|\s)(B|OOB)$' -and $_.Date -ge $cutoff
                })

                $installed = $forBuild | Where-Object { $_.Build -eq $deviceBuild } | Select-Object -First 1
                if (-not $installed) { $installed = $hotpatch }

                # A release is missing if it's newer than the installed build. A hotpatch build
                # has its own numbering, so for hotpatch devices compare by release date instead.
                $isMissing = if ($hotpatch) { { param($u) $u.Date -gt $hotpatch.Date } }
                             else           { { param($u) $u.Build -gt $deviceBuild } }

                # Only releases that could be missing affect the result, so only those
                # OOB KB pages are fetched.
                $applicable = @($candidates | Where-Object {
                    if ($_.UpdateType -notmatch 'OOB$' -or -not (& $isMissing $_)) { $true }
                    else { Test-OobAppliesTo -Url $_.Link -OsTag $osTag }
                } | Sort-Object Build -Descending)

                if ($installed) {
                    $Result.DaysSinceCurrentUpdateReleaseDate = [int64][Math]::Floor(($now - $installed.Date).TotalDays)
                }

                $missing = @($applicable | Where-Object { & $isMissing $_ })
                $Result.CurrentPatchLevel = [int64]$missing.Count

                if ($applicable.Count -gt 0) {
                    $Result.LatestApplicableBuild            = $applicable[0].Build.ToString()
                    $Result.LatestApplicableKB               = $applicable[0].KB
                    $Result.DaysSinceLatestUpdateReleaseDate = [int64][Math]::Floor(($now - $applicable[0].Date).TotalDays)
                }

                # How long the device has been out of date = age of the oldest release it's missing
                if ($missing.Count -eq 0) {
                    $Result.DaysBehindLatest = [int64]0
                } else {
                    $oldestMissing = $missing | Sort-Object Date | Select-Object -First 1
                    $Result.DaysBehindLatest = [int64][Math]::Floor(($now - $oldestMissing.Date).TotalDays)
                }

                # Update ring allowance: deferral + deadline + grace period (quality updates)
                $grace = (Get-PolicyDays 'DeferQualityUpdatesPeriodInDays') +
                         (Get-PolicyDays 'ConfigureDeadlineForQualityUpdates') +
                         (Get-PolicyDays 'ConfigureDeadlineGracePeriod')
                $grace = [Math]::Max($grace, $MinimumGraceDays)
                $Result.TotalGraceDays = [int64]$grace

                # Releases still inside their grace window may be missing
                $Result.RequiredPatchLevel = [int64]@($applicable | Where-Object {
                    ($now - $_.Date).TotalDays -lt $grace
                }).Count

                $Result.isLatestForThisDevice = ($Result.CurrentPatchLevel -le $Result.RequiredPatchLevel)
                $Result.Status = 'Evaluated'
            }
        }
    }
} catch {
    $Result.Status = 'ScriptError'
}

# ---------------------------------------------------------------- log to registry (best effort)
try {
    $hklm = Get-HKLM64
    try { $hklm.DeleteSubKeyTree($LogKey, $false) } catch {}
    $log = $hklm.CreateSubKey($LogKey)
    foreach ($k in $Result.Keys) { $log.SetValue($k, [string]$Result[$k], [Microsoft.Win32.RegistryValueKind]::String) }
    $log.Close()
} catch {}

return $Result | ConvertTo-Json -Compress
