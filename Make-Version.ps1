# Refreshes the SHA-256 hashes in version.json after you change any app file.
param([string]$Version, [string]$Notes)
$dir = $PSScriptRoot
$j = Get-Content (Join-Path $dir 'version.json') -Raw | ConvertFrom-Json
if ($Version) { $j.version = $Version }
if ($Notes) { $j.notes = $Notes }
$files = [ordered]@{}
foreach ($f in 'PC_Optimizer.ps1', 'Setup.ps1', 'Uninstall.ps1', 'PC_Optimizer.ico') {
    $files[$f] = (Get-FileHash -LiteralPath (Join-Path $dir $f) -Algorithm SHA256).Hash.ToLower()
}
$j.files = $files
$j | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dir 'version.json') -Encoding UTF8
"version.json updated to $($j.version)"
