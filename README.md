# Windows Vuln Scanner v2.0 PRO

Herramienta de auditoria de seguridad para Windows con:
- Escaneo local (usuarios, politicas, puertos, SMB, procesos, servicios, persistencia, updates).
- Clasificacion por severidad + score de riesgo.
- Reportes HTML / JSON / TXT.
- Remediacion guiada desde UI con boton `Fix`.

## Versiones de entrega

### 1) Portable
Ejecutable directo, no instala nada.

```powershell
.\build_portable.ps1
```

Salida:
- `release\WindowsVulnScanner-portable.exe`

### 2) Instalable
Instalador tipo Setup (Inno Setup).

Requisito:
- Instalar [Inno Setup 6](https://jrsoftware.org/isdl.php)

Comando:
```powershell
.\build_installer.ps1
```

Salida:
- `release\WindowsVulnScanner-Setup.exe`

## Ejecutar en desarrollo

```powershell
python main.py
```

## Build manual

```powershell
pyinstaller main.spec
```

Salida:
- `dist\WindowsVulnScanner.exe`

## Firma digital (opcional para release)

Ya incluido script:
- `sign_release.ps1`

Uso:
```powershell
.\sign_release.ps1 -ExePath "dist\WindowsVulnScanner.exe" -CertThumbprint "TU_THUMBPRINT"
```

## Subir a GitHub

### 1) Inicializar repo local
```powershell
git init
git add .
git commit -m "feat: release portable + installer setup"
```

### 2) Crear repo en GitHub y conectar remoto
```powershell
git branch -M main
git remote add origin https://github.com/TU_USUARIO/windows-vuln-scanner.git
git push -u origin main
```

## Notas
- El modo `Auditoria` no ejecuta correcciones.
- El modo `Remediacion` habilita el boton `Fix`.
- Los fixes pueden requerir permisos de administrador (UAC).

Uso solo en entornos autorizados.

