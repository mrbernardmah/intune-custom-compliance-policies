$firewallStatus = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'True' }
$firewall = $false
if ($firewallStatus) {
    # Return True if the firewall is enabled
    $firewall =  $true
}
$output = @{ Firewall = $firewall}
return $output | ConvertTo-Json -Compress