Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> Build installer (.exe setup)..." -ForegroundColor Cyan

if (-not (Test-Path "dist\WindowsVulnScanner.exe")) {
    Write-Host "No existe ejecutable portable. Construyendo primero..." -ForegroundColor Yellow
    pyinstaller main.spec
}

$isccCandidates = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
    "${env:LOCALAPPDATA}\Programs\Inno Setup 6\ISCC.exe"
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    throw "Inno Setup no encontrado. Instala Inno Setup 6 y vuelve a intentar."
}

& $iscc "installer.iss"
if ($LASTEXITCODE -ne 0) {
    throw "Error construyendo el instalador."
}

Write-Host "OK: release\\WindowsVulnScanner-Setup.exe" -ForegroundColor Green
