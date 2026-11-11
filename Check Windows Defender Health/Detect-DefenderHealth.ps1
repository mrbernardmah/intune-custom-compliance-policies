<#
.SYNOPSIS
    Intune custom compliance discovery script - Microsoft Defender Antivirus health + Windows Firewall.
.DESCRIPTION
    Based on the endusersupports.com custom compliance example (Oct 2023), with its bugs fixed:
      - The original "DefenderServiceStatus" check actually queried the BITS service.
        It is replaced with real checks: Defender running mode, real-time protection,
        and Windows Firewall on every profile (which the original's comment intended).
      - The original "OSVersion" read the HAL version, not the Windows build. Removed -
        patch level is covered properly by policy 06.
      - Booleans are returned as real booleans, not the strings "$true"/"$false".
      - Each check has its own remediation message.

    Settings returned
      DefenderServiceEnabled    Boolean  AMServiceEnabled
      DefenderAntivirusEnabled  Boolean  AntivirusEnabled
      DefenderRealTimeEnabled   Boolean  RealTimeProtectionEnabled
      DefenderRunningMode       String   AMRunningMode ("Normal" when Defender is the active AV)
      DefenderTamperProtected   Boolean  IsTamperProtected
      DefenderPlatformVersion   Version  AMProductVersion
      DefenderSignatureAgeDays  Int64    AntivirusSignatureAge (999 if unknown)
      FirewallAllProfilesOn     Boolean  Domain, Private and Public profiles all enabled

    Scope: devices where Defender is the primary antivirus. With a third-party AV,
    Defender runs in Passive mode and the running-mode / real-time rules will fail by design.

    Upload settings: Run as logged-on user = No | Signature check = No | 64-bit host = Yes
    Returns a single line of compressed JSON only.
#>

$hash = [ordered]@{
    DefenderServiceEnabled   = $false
    DefenderAntivirusEnabled = $false
    DefenderRealTimeEnabled  = $false
    DefenderRunningMode      = 'Unknown'
    DefenderTamperProtected  = $false
    DefenderPlatformVersion  = '0.0.0.0'
    DefenderSignatureAgeDays = [int64]999
    FirewallAllProfilesOn    = $false
}

try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $hash.DefenderServiceEnabled   = [bool]$mp.AMServiceEnabled
    $hash.DefenderAntivirusEnabled = [bool]$mp.AntivirusEnabled
    $hash.DefenderRealTimeEnabled  = [bool]$mp.RealTimeProtectionEnabled
    $hash.DefenderTamperProtected  = [bool]$mp.IsTamperProtected
    if ($mp.AMRunningMode) { $hash.DefenderRunningMode = [string]$mp.AMRunningMode }

    $v = $null
    if ([version]::TryParse([string]$mp.AMProductVersion, [ref]$v)) { $hash.DefenderPlatformVersion = $v.ToString() }

    # 65535 / UInt32 max are reported when signatures have never been updated
    $age = [int64]$mp.AntivirusSignatureAge
    if ($age -ge 0 -and $age -lt 65535) { $hash.DefenderSignatureAgeDays = $age }
} catch {
    # Defender not available - defaults stand (non-compliant)
}

try {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    $hash.FirewallAllProfilesOn = ($profiles.Count -ge 3) -and
                                  (@($profiles | Where-Object { "$($_.Enabled)" -ne 'True' }).Count -eq 0)
} catch {
    $hash.FirewallAllProfilesOn = $false
}

return $hash | ConvertTo-Json -Compress
