<#
.SYNOPSIS
    Intune custom compliance discovery script - CrowdStrike Falcon sensor installed,
    running, and at or above a minimum version.
.DESCRIPTION
    Implements the article's "EDR deployment" scenario:
      executable exists + CSFalconService running + sensor version >= minimum.
    The minimum version itself lives in the JSON rule (Operand), not here, so you can
    raise it without editing the script.
    Returns a single line of compressed JSON only.
    Upload settings: Run as logged-on user = No | Signature check = No | 64-bit host = Yes
#>

$FalconExe     = 'C:\Program Files\CrowdStrike\CSFalconService.exe'
$FalconService = 'CSFalconService'

$fileExists     = $false
$serviceRunning = $false
$version        = '0.0.0.0'   # reported when the sensor is missing, so the version rule fails cleanly

try {
    $fileExists = Test-Path -LiteralPath $FalconExe -PathType Leaf -ErrorAction Stop
    if ($fileExists) {
        $vi = (Get-Item -LiteralPath $FalconExe -ErrorAction Stop).VersionInfo
        $raw = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
        $parsed = $null
        if ([version]::TryParse($raw, [ref]$parsed)) { $version = $parsed.ToString() }
    }
} catch {
    $fileExists = $false
}

try {
    $svc = Get-Service -Name $FalconService -ErrorAction Stop
    $serviceRunning = ($svc.Status -eq 'Running')
} catch {
    $serviceRunning = $false
}

$hash = @{
    FalconFileExists     = [bool]$fileExists
    FalconServiceRunning = [bool]$serviceRunning
    FalconSensorVersion  = [string]$version
}

return $hash | ConvertTo-Json -Compress
