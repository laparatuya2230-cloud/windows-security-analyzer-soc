# Windows Vuln Scanner v2.0 PRO

> Herramienta de auditoría de seguridad para Windows. Escanea el sistema en busca de vulnerabilidades, malas configuraciones y riesgos de seguridad, y genera reportes detallados en HTML, JSON y TXT.

![Python](https://img.shields.io/badge/Python-3.14-blue?logo=python) ![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue?logo=windows) ![License](https://img.shields.io/badge/License-MIT-green)

---

## Descarga rápida

**[⬇ Descargar Portable v2.0.1](https://github.com/laparatuya2230-cloud/windows-security-analyzer-soc/releases/tag/v2.0.1)**

Descomprime el ZIP y ejecuta `WinVulnScanner.exe` como **Administrador**.

---

## Características

- **Dashboard SOC** — Score de riesgo, métricas por severidad y gráfico donut en tiempo real
- **13 módulos de escaneo** — system info, usuarios, política de contraseñas, red, SMB, procesos, firmas digitales, tareas, servicios, registro, startup, firewall, Windows Update
- **Detección de usuarios sin contraseña** — revisa todas las cuentas del sistema (activas y deshabilitadas)
- **Detección de LOLBins** — identifica binarios legítimos usados maliciosamente fuera de rutas del sistema
- **Verificación de firmas digitales** — detecta ejecutables no firmados en rutas no estándar
- **Exportación de reportes** — HTML, JSON y TXT
- **Historial de escaneos** — comparativa entre sesiones
- **Temas dark / light**
- **Escaneo automático programado** — cada 30 min, 1 hora o 6 horas
- **UI responsive** — se adapta a cualquier tamaño de ventana
- **MITRE ATT&CK** — cada hallazgo incluye su técnica asociada

---

## Módulos de detección

| Módulo | Qué detecta |
|---|---|
| `users` | Cuentas sin contraseña requerida, cuenta invitado habilitada |
| `password_policy` | Longitud mínima, historial, bloqueo de cuenta |
| `network` | Puertos expuestos (RPC, SMB, RDP, WinRM...) |
| `smb_shares` | Sesiones nulas, SMBv1 habilitado |
| `processes` | LOLBins activos fuera de rutas del sistema |
| `signatures` | Ejecutables sin firma en rutas no estándar |
| `firewall` | Firewall deshabilitado |
| `registry_run` | Entradas sospechosas en Run/RunOnce |
| `startup` | Programas de inicio no reconocidos |
| `windows_update` | Actualizaciones pendientes |

---

## Instalación y uso

### Portable (recomendado)

1. Descarga el ZIP desde [Releases](https://github.com/laparatuya2230-cloud/windows-security-analyzer-soc/releases)
2. Descomprime en cualquier carpeta
3. Clic derecho en `WinVulnScanner.exe` → **Ejecutar como administrador**

### Desde el código fuente

```powershell
# Clonar repositorio
git clone https://github.com/laparatuya2230-cloud/windows-security-analyzer-soc.git
cd windows-security-analyzer-soc

# Crear entorno virtual e instalar dependencias
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt   # o instalar: pillow

# Ejecutar
python main.py
```

### Compilar portable

```powershell
.venv\Scripts\pyinstaller --clean -y WinVulnScanner.spec
# Resultado en dist\WinVulnScanner\WinVulnScanner.exe
```

---

## Severidades

| Nivel | Color | Descripción |
|---|---|---|
| `CRITICAL` | 🔴 Rojo | Riesgo inmediato, requiere acción urgente |
| `HIGH` | 🟠 Naranja | Riesgo alto, corregir a la brevedad |
| `MEDIUM` | 🟡 Amarillo | Riesgo moderado |
| `LOW` | 🟢 Verde | Riesgo bajo o cuenta deshabilitada |
| `REVIEW` | 🔵 Azul | Requiere revisión manual |

---

## Requisitos

- Windows 10 / 11 (64-bit)
- Ejecutar como **Administrador** para escaneo completo
- Python 3.14+ (solo si se ejecuta desde el código fuente)

---

## Aviso legal

Uso exclusivo en sistemas propios o con autorización expresa del propietario. El autor no se responsabiliza del uso indebido de esta herramienta.
