
[array]$applicationName = @("BeyondTrust Privilege Management Package Manager (x64)")
[array]$myAppRegEntries = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion
[array]$appInfo = ForEach ($application in $applicationName) {    
    $appInstalled = $false
    If ($myAppRegEntries) {
        Foreach ($myAppReg in $myAppRegEntries) {
            if ($myAppReg.DisplayName -eq $application) {
                $appInstalled = $true
                [string]$displayName = $myAppReg.DisplayName
                [string]$displayVersion = $myAppReg.DisplayVersion
                break
            }            
        }
    }
    if (-not $appInstalled) {
        $displayName = $application
        $displayVersion = "0.0.0.0"
    }
    
    @{
        $displayName = $displayVersion                    
    }
}

$objectJSONoutput = @{ }
foreach ($app in $appInfo) {
    $objectJSONoutput += $app
}
$hash = $objectJSONoutput
return $hash | ConvertTo-Json -Compress
