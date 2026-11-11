<#
.SYNOPSIS
    Intune custom compliance discovery script - Microsoft Defender Antivirus service running.
.DESCRIPTION
    Checks the WinDefend service is Running and set to Automatic start.
    Returns a single line of compressed JSON only.
    Upload settings: Run as logged-on user = No | Signature check = No | 64-bit host = Yes
#>

$running   = $false
$automatic = $false

try {
    $svc = Get-Service -Name 'WinDefend' -ErrorAction Stop
    $running   = ($svc.Status -eq 'Running')
    $automatic = ($svc.StartType -eq 'Automatic')
} catch {
    # Service not present - both stay $false (non-compliant)
}

$hash = @{
    WindowsDefenderRunning   = [bool]$running
    WindowsDefenderAutoStart = [bool]$automatic
}

return $hash | ConvertTo-Json -Compress
