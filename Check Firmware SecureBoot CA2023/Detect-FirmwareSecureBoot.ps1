<#
.SYNOPSIS
    Intune custom compliance discovery script - minimum BIOS/UEFI firmware per model,
    Secure Boot on, and the Windows UEFI CA 2023 certificate present.
.DESCRIPTION
    Based on the zerotruststories.com Surface Book 3 firmware example, extended:
      - Per-model minimums are compared inside the script, so one policy can cover many
        models (a JSON rule only holds one Operand, so the original could only serve one model).
      - Models not in the table no longer report 0.0.0 and fail; set $UnlistedModelsCompliant.
      - Version numbers are extracted from vendor BIOS strings that aren't plain versions
        (e.g. Lenovo "N2HET73W (1.56 )" -> 1.56, HP "S70 Ver. 01.12.00" -> 1.12.0).
      - Adds the Secure Boot checks the original's firmware minimum was protecting:
        Secure Boot enabled, and "Windows UEFI CA 2023" in the Secure Boot db
        (the Microsoft 2011 Secure Boot certificates began expiring in June 2026).

    Settings returned
      FirmwareVersion          String   raw SMBIOSBIOSVersion (for reporting)
      FirmwareMinimumVersion   String   minimum for this model, or "" if not listed
      FirmwareModelInScope     Boolean  model is in the table
      FirmwareMeetsMinimum     Boolean  firmware >= minimum (or unlisted and allowed)
      SecureBootEnabled        Boolean  Confirm-SecureBootUEFI
      SecureBootDbHasCA2023    Boolean  "Windows UEFI CA 2023" in db
      SecureBootKekHasCA2023   Boolean  "Microsoft Corporation KEK 2K CA 2023" in KEK (informational)

    Upload settings: Run as logged-on user = No | Signature check = No | 64-bit host = Yes
    Returns a single line of compressed JSON only.
#>

# ---------------------------------------------------------------- settings
# Key: "<Manufacturer> <Model>" exactly as WMI reports them. For Lenovo, the friendly name
# from Win32_ComputerSystemProduct.Version also works, e.g. "LENOVO ThinkPad X1 Carbon Gen 9".
# Get the real values on a device with:
#   Get-CimInstance Win32_ComputerSystem | Select Manufacturer, Model
#   (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
# Take minimum versions from the vendor's Secure Boot / firmware advisories.
$MinimumFirmware = @{
    'Microsoft Corporation Surface Book 3' = '17.200.140.0'   # from the source article
    # 'Dell Inc. Latitude 7440'                     = '1.20.0'      # example - verify with vendor
    # 'HP HP EliteBook 840 G9 Notebook PC'          = '1.12.0'      # example - verify with vendor
    # 'LENOVO ThinkPad X1 Carbon Gen 9'             = '1.56'        # example - verify with vendor
}

# $true  = models not in the table pass the firmware check (they're still reported as out of scope)
# $false = models not in the table fail (strict, as in the source article)
$UnlistedModelsCompliant = $true
# -------------------------------------------------------------------------

function ConvertTo-FirmwareVersion([string]$Text) {
    if ($Text -match '\d+(\.\d+){1,3}') {
        $v = $null
        if ([version]::TryParse($Matches[0], [ref]$v)) { return $v }
    }
    return $null
}

$hash = [ordered]@{
    FirmwareVersion        = ''
    FirmwareMinimumVersion = ''
    FirmwareModelInScope   = $false
    FirmwareMeetsMinimum   = $false
    SecureBootEnabled      = $false
    SecureBootDbHasCA2023  = $false
    SecureBootKekHasCA2023 = $false
}

# ---------------------------------------------------------------- firmware
try {
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $csp  = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue

    $hash.FirmwareVersion = [string]$bios.SMBIOSBIOSVersion

    $keys = @(
        ('{0} {1}' -f $cs.Manufacturer, $cs.Model).Trim()
        if ($csp -and $csp.Version) { ('{0} {1}' -f $cs.Manufacturer, $csp.Version).Trim() }
    )
    $match = $keys | Where-Object { $MinimumFirmware.ContainsKey($_) } | Select-Object -First 1

    if ($match) {
        $hash.FirmwareModelInScope   = $true
        $hash.FirmwareMinimumVersion = $MinimumFirmware[$match]
        $installed = ConvertTo-FirmwareVersion $bios.SMBIOSBIOSVersion
        $required  = ConvertTo-FirmwareVersion $MinimumFirmware[$match]
        $hash.FirmwareMeetsMinimum = ($null -ne $installed -and $null -ne $required -and $installed -ge $required)
    } else {
        $hash.FirmwareMeetsMinimum = [bool]$UnlistedModelsCompliant
    }
} catch {
    $hash.FirmwareMeetsMinimum = $false
}

# ---------------------------------------------------------------- Secure Boot
try { $hash.SecureBootEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $hash.SecureBootEnabled = $false }

try {
    $db = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name db -ErrorAction Stop).Bytes)
    $hash.SecureBootDbHasCA2023 = ($db -match 'Windows UEFI CA 2023')
} catch { $hash.SecureBootDbHasCA2023 = $false }

try {
    $kek = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name KEK -ErrorAction Stop).Bytes)
    $hash.SecureBootKekHasCA2023 = ($kek -match 'Microsoft Corporation KEK 2K CA 2023')
} catch { $hash.SecureBootKekHasCA2023 = $false }

return $hash | ConvertTo-Json -Compress
