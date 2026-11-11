<#
.SYNOPSIS
    Intune custom compliance discovery script - Print Spooler stopped AND disabled.
.DESCRIPTION
    A stopped spooler with Manual/Automatic start type can come back on its own,
    so this checks both the current state and the start type.
    A missing service counts as compliant.
    Returns a single line of compressed JSON only.
    Upload settings: Run as logged-on user = No | Signature check = No | 64-bit host = Yes
    WARNING: only assign to devices that do not need to print (e.g. kiosks, servers, high-security groups).
#>

$stopped  = $true
$disabled = $true

try {
    $svc = Get-Service -Name 'Spooler' -ErrorAction Stop
    $stopped  = ($svc.Status -eq 'Stopped')
    $disabled = ($svc.StartType -eq 'Disabled')
} catch {
    # Service not present - compliant
}

$hash = @{
    PrintSpoolerStopped  = [bool]$stopped
    PrintSpoolerDisabled = [bool]$disabled
}

return $hash | ConvertTo-Json -Compress
