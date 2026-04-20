Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> Build portable (carpeta)..." -ForegroundColor Cyan
pyinstaller --noconfirm --clean portable_folder.spec

if (-not (Test-Path "dist\WinVulnScan\WinVulnScan.exe")) {
    throw "No se encontro dist\\WinVulnScan\\WinVulnScan.exe"
}

New-Item -ItemType Directory -Path "release" -Force | Out-Null
if (Test-Path "release\WinVulnScan-portable") {
    Remove-Item -LiteralPath "release\WinVulnScan-portable" -Recurse -Force
}
Copy-Item "dist\WinVulnScan" "release\WinVulnScan-portable" -Recurse -Force

Write-Host "OK carpeta: release\\WinVulnScan-portable" -ForegroundColor Green
