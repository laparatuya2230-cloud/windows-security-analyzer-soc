Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> Build portable (.exe)..." -ForegroundColor Cyan
pyinstaller main.spec

if (-not (Test-Path "dist\WindowsVulnScanner.exe")) {
    throw "No se encontro dist\\WindowsVulnScanner.exe"
}

New-Item -ItemType Directory -Path "release" -Force | Out-Null
Copy-Item "dist\WindowsVulnScanner.exe" "release\WindowsVulnScanner-portable.exe" -Force

Write-Host "OK: release\\WindowsVulnScanner-portable.exe" -ForegroundColor Green

