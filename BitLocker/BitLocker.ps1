$BLinfo = Get-Bitlockervolume 
$hash = @{Percentage= $BLinfo.EncryptionPercentage; ProtectionStatus = $BLinfo.ProtectionStatus}
return $hash | ConvertTo-Json -Compress