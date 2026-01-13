$TamperProtection = Get-MpComputerStatus | Select-Object IsTamperProtected
$CloudProtection = Get-MpPreference | Select-object MAPSReporting
$RealTimeProtection = Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled
$AntivirusEnabled = Get-MpComputerStatus | Select-Object AntivirusEnabled
$CloudBlockLevel = Get-MpPreference | Select-object CloudBlockLevel
$CloudExtendedTimeout = Get-MpPreference | Select-object CloudExtendedTimeout
$NetworkProtectionEnabled= Get-MpPreference | select-object EnableNetworkProtection

$output = @{
    TamperProtectionEnabled = $TamperProtection.IsTamperProtected
    CloudProtection = $CloudProtection.MAPSReporting
    RealTimeProtectionEnabled = $RealTimeProtection.RealTimeProtectionEnabled
    AntivirusEnabled = $AntivirusEnabled.AntivirusEnabled
    CloudBlockLevel = $CloudBlockLevel.CloudBlockLevel
    CloudExtendedTimeout = $CloudExtendedTimeout.CloudExtendedTimeout
    NetworkProtectionEnabled = $NetworkProtectionEnabled.EnableNetworkProtection
}

return $output | ConvertTo-Json -Compress
