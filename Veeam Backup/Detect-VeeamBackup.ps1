<#
.SYNOPSIS
    Intune custom compliance discovery script - Veeam Agent installed AND service running.
.DESCRIPTION
    Returns a single line of compressed JSON only.
    Upload settings: Run as logged-on user = No | Signature check = No | 64-bit host = Yes
    Verify the executable path and service name on a reference device - they differ
    between Veeam Agent for Microsoft Windows versions.
#>

$VeeamExe     = 'C:\Program Files\Veeam\Endpoint Backup\Veeam.EndPoint.Manager.exe'
$VeeamService = 'VeeamEndpointBackupSvc'

$fileExists     = $false
$serviceRunning = $false

try {
    $fileExists = Test-Path -LiteralPath $VeeamExe -PathType Leaf -ErrorAction Stop
} catch {
    $fileExists = $false
}

try {
    $svc = Get-Service -Name $VeeamService -ErrorAction Stop
    $serviceRunning = ($svc.Status -eq 'Running')
} catch {
    $serviceRunning = $false
}

$hash = @{
    VeeamFileExists     = [bool]$fileExists
    VeeamServiceRunning = [bool]$serviceRunning
}

return $hash | ConvertTo-Json -Compress
