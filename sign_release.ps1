param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath,

    [Parameter(Mandatory=$true)]
    [string]$CertThumbprint,

    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

if (-not (Test-Path $ExePath)) {
    Write-Error "No se encontro el ejecutable: $ExePath"
    exit 1
}

$signtool = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\x64\signtool.exe"
if (-not (Test-Path $signtool)) {
    Write-Error "No se encontro signtool.exe. Instala Windows SDK."
    exit 1
}

& $signtool sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $ExePath
if ($LASTEXITCODE -ne 0) {
    Write-Error "Error firmando el ejecutable."
    exit $LASTEXITCODE
}

Write-Host "Firma aplicada correctamente a $ExePath"
