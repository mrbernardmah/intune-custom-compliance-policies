<#
.SYNOPSIS
    Intune custom compliance discovery script - TeamViewer QuickSupport present.
.DESCRIPTION
    Returns a single line of compressed JSON. Nothing else may be written to the
    output stream, otherwise Intune cannot parse the result.
    Upload settings: Run as logged-on user = No | Signature check = No | 64-bit host = Yes
#>

$FilePath = 'C:\Temp\TeamViewerQS_x64.exe'   # <-- change to your deployed location

$fileExists = $false
try {
    $fileExists = Test-Path -LiteralPath $FilePath -PathType Leaf -ErrorAction Stop
} catch {
    $fileExists = $false
}

$hash = @{
    TeamViewerFileExists = [bool]$fileExists
}

return $hash | ConvertTo-Json -Compress
