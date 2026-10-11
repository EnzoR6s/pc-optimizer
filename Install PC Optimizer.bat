@echo off
:: Installs (or updates) PC Optimizer. Windows will ask for admin - click Yes.
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0Setup.ps1"
