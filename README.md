# Windows Vuln Scanner v2.0 PRO

Herramienta de auditoria de seguridad para Windows.

## Distribucion recomendada (portable en carpeta)

Este proyecto ahora se entrega en formato portable:
- Descargas una carpeta.
- Dentro esta `WinVulnScan.exe` junto con sus archivos necesarios.
- No requiere instalacion.

### Build portable

```powershell
.\build_portable.ps1
```

Salida:
- Carpeta: `release\WinVulnScan-portable\`
- Ejecutable principal: `release\WinVulnScan-portable\WinVulnScan.exe`
- ZIP listo para compartir: `release\WinVulnScan-portable.zip`

## Ejecutar en desarrollo

```powershell
python main.py
```

## Notas
- Modo `Auditoria`: no ejecuta correcciones.
- Modo `Remediacion`: habilita boton `Fix` (puede requerir UAC).
- Uso solo en entornos autorizados.

