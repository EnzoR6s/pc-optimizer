#Requires -Version 5.1
<#  PC Optimizer - uninstaller (also used by Settings > Apps)  #>

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    try { Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`"") } catch {}
    exit
}

Add-Type -AssemblyName PresentationFramework
$r = [System.Windows.MessageBox]::Show("Uninstall PC Optimizer?`n`nThis also deletes its encrypted change log. Changes it made to Windows stay as they are (use System Restore to roll them back).", 'Uninstall PC Optimizer', 'YesNo', 'Question')
if ($r -ne 'Yes') { exit }

$dir = $PSScriptRoot

# a gaming preset changed NVIDIA settings? give a chance to restore them first
if (Test-Path -LiteralPath (Join-Path $dir 'gpu_backup.json')) {
    $g = [System.Windows.MessageBox]::Show("A gaming preset changed your NVIDIA Control Panel settings.`n`nUninstall anyway?`n`nClick No to cancel, then use PC Optimizer > Gaming > 'Restore my original GPU settings' first.", 'Uninstall PC Optimizer', 'YesNo', 'Warning')
    if ($g -ne 'Yes') { exit }
}

# close the app
Get-Process -Name 'PC Optimizer' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'PC_Optimizer\.ps1' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 600

# scheduled tasks (start with Windows, weekly clean)
try { Get-ScheduledTask -TaskPath '\PC Optimizer\' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue } catch {}

# shortcuts
foreach ($lnk in @(
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'PC Optimizer.lnk'),
    (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'PC Optimizer.lnk'))) {
    Remove-Item -LiteralPath $lnk -Force -ErrorAction SilentlyContinue
}

# registry
Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PCOptimizer' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'HKCU:\Software\PCOptimizerApp' -Recurse -Force -ErrorAction SilentlyContinue

# files (including Logs)
Set-Location -LiteralPath $env:TEMP
Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue

[void][System.Windows.MessageBox]::Show('PC Optimizer was removed.', 'Uninstall PC Optimizer', 'OK', 'Information')
