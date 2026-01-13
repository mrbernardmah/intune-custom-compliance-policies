$CloudProtection = Get-MpPreference | Select-object MAPSReporting
$AntivirusEnabled = Get-MpComputerStatus | Select-Object AntivirusEnabled
$NetworkProtectionEnabled= Get-MpPreference | select-object EnableNetworkProtection

$output = @{
    CloudProtection = $CloudProtection.MAPSReporting
    AntivirusEnabled = $AntivirusEnabled.AntivirusEnabled
    NetworkProtectionEnabled = $NetworkProtectionEnabled.EnableNetworkProtection
}

return $output | ConvertTo-Json -Compress
