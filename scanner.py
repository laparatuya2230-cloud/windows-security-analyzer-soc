import locale
import subprocess
import sys
import json
from datetime import datetime


def _si():
    """STARTUPINFO para ocultar ventanas en Windows."""
    if sys.platform != "win32":
        return None
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return si


_NO_WIN = 0x08000000 if sys.platform == "win32" else 0


class WindowsScanner:
    def __init__(self, logger):
        self.logger = logger
        self.encoding = locale.getpreferredencoding(False) or "cp850"

    def run_command(self, args):
        try:
            result = subprocess.run(
                args,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding=self.encoding,
                errors="replace",
                timeout=30,
                startupinfo=_si(),
                creationflags=_NO_WIN,
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout: {args}")
            return ""
        except Exception as e:
            self.logger.error(f"Command error: {e}")
            return ""

    def run_powershell(self, script):
        return self.run_command([
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle", "Hidden",
            "-Command", script
        ])

    # =========================
    # 🧠 USERS
    # =========================
    def collect_users(self):
        import csv, io

        raw = self.run_powershell(
            "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired | ConvertTo-Csv -NoTypeInformation"
        )
        users_full = []
        users_str  = []
        users_without_password = []

        try:
            reader = csv.DictReader(io.StringIO(raw))
            for row in reader:
                name             = (row.get("Name") or "").strip()
                enabled          = (row.get("Enabled") or "").strip().lower() == "true"
                password_required = (row.get("PasswordRequired") or "").strip().lower() == "true"
                if not name:
                    continue
                users_full.append({"name": name, "enabled": enabled,
                                   "password_required": password_required})
                users_str.append(name)
                if not password_required:
                    users_without_password.append(name)
        except Exception:
            pass

        # Miembros del grupo Administradores (nombre varía por idioma)
        admins = []
        for group_name in ("Administrators", "Administradores"):
            admin_raw = self.run_powershell(
                f"try {{ Get-LocalGroupMember -Group '{group_name}' | "
                "Select-Object -ExpandProperty Name }} catch {}"
            )
            members = [l.strip().split("\\")[-1] for l in admin_raw.splitlines() if l.strip()]
            if members:
                admins = members
                break

        return {
            "users": users_str,
            "users_full": users_full,
            "users_without_password": users_without_password,
            "admins": admins,
        }

    # =========================
    # 🔐 PASSWORD POLICY
    # =========================
    def collect_password_policy(self):
        raw = self.run_command(["net", "accounts"])
        policy = {
            "min_length": 0,
            "max_age": 0,
            "min_age": 0,
            "history": 0,
            "lockout_threshold": 0,
            "raw": raw
        }
        for line in raw.splitlines():
            l = line.lower()
            if "minimum password length" in l or "longitud" in l:
                parts = line.split(":")
                if len(parts) >= 2:
                    val = parts[-1].strip()
                    try:
                        policy["min_length"] = int(val)
                    except ValueError:
                        policy["min_length"] = 0
            elif "maximum password age" in l or "máxima" in l or "maxima" in l:
                parts = line.split(":")
                if len(parts) >= 2:
                    val = parts[-1].strip().split()[0]
                    try:
                        policy["max_age"] = int(val)
                    except ValueError:
                        policy["max_age"] = 999
            elif "lockout threshold" in l or "bloqueo" in l:
                parts = line.split(":")
                if len(parts) >= 2:
                    val = parts[-1].strip().split()[0]
                    try:
                        policy["lockout_threshold"] = int(val)
                    except ValueError:
                        policy["lockout_threshold"] = 0
            elif "password history" in l or "historial" in l:
                parts = line.split(":")
                if len(parts) >= 2:
                    val = parts[-1].strip().split()[0]
                    try:
                        policy["history"] = int(val)
                    except ValueError:
                        policy["history"] = 0
        return policy

    # =========================
    # 🌐 NETWORK
    # =========================
    def collect_network(self):
        raw = self.run_command(["netstat", "-ano"])
        unique = list(set(raw.splitlines()))
        return {"listening_ports": unique}

    # =========================
    # 📂 SMB SHARES
    # =========================
    def collect_smb_shares(self):
        raw = self.run_powershell(
            "Get-SmbShare | Select Name,Path,Description | ConvertTo-Csv -NoTypeInformation"
        )
        shares = []
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        for line in lines[1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 2:
                shares.append({
                    "name": parts[0],
                    "path": parts[1] if len(parts) > 1 else "",
                    "description": parts[2] if len(parts) > 2 else ""
                })

        # Check anonymous access
        anon_raw = self.run_powershell(
            "Get-SmbServerConfiguration | Select EnableSMB1Protocol,RestrictNullSessAccess | ConvertTo-Csv -NoTypeInformation"
        )
        smb1 = False
        null_sess = True
        anon_lines = [l.strip() for l in anon_raw.splitlines() if l.strip()]
        if len(anon_lines) >= 2:
            parts = [p.strip('"') for p in anon_lines[1].split(",")]
            if len(parts) >= 2:
                smb1 = parts[0].lower() == "true"
                null_sess = parts[1].lower() == "true"

        return {
            "shares": shares,
            "smb1_enabled": smb1,
            "null_session_restricted": null_sess
        }

    # =========================
    # 🦠 PROCESSES
    # =========================
    def collect_processes(self):
        raw = self.run_powershell(
            "Get-Process | Select Name,Path,Id | ConvertTo-Csv -NoTypeInformation"
        )
        processes = []
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        for line in lines[1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 3:
                processes.append({
                    "name": parts[0],
                    "path": parts[1],
                    "pid": parts[2]
                })

        # LOLBins running
        lolbins_raw = self.run_powershell(
            "Get-Process | Where-Object {$_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic'} "
            "| Select Name,Path,Id | ConvertTo-Csv -NoTypeInformation"
        )
        lolbins = []
        lb_lines = [l.strip() for l in lolbins_raw.splitlines() if l.strip()]
        for line in lb_lines[1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 3:
                lolbins.append({"name": parts[0], "path": parts[1], "pid": parts[2]})

        return {"processes": processes, "lolbins": lolbins}

    # =========================
    # 🔏 DIGITAL SIGNATURES
    # =========================
    def collect_signatures(self):
        import csv, io, os, sys

        # Nombre del propio ejecutable para excluirlo (evita que la app se detecte a sí misma)
        own_name = os.path.splitext(os.path.basename(sys.executable))[0]

        ps = (
            "Get-Process | Where-Object { "
            "  $_.Path -and "
            "  $_.Path -notlike '*\\WindowsApps\\*' -and "      # Store apps: catalog signing
            "  $_.Path -notlike '*\\Windows\\System32\\*' -and "
            "  $_.Path -notlike '*\\Windows\\SysWOW64\\*' -and "
            "  $_.Path -notlike '*\\Program Files\\*' -and "     # Software comercial instalado
            "  $_.Path -notlike '*\\Program Files (x86)\\*' -and "
            "  $_.Path -notlike '*\\Riot Games\\*' -and "        # Riot / League of Legends
            "  $_.Path -notlike '*\\Steam\\*' -and "             # Steam / juegos
            "  $_.Path -notlike '*\\Epic Games\\*' -and "
            f"  $_.Name -ne '{own_name}' "
            "} | ForEach-Object { "
            "  $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue; "
            "  [PSCustomObject]@{Name=$_.Name; Path=$_.Path; Status=$sig.Status} "
            "} | Where-Object {$_.Status -ne 'Valid'} "
            "| Select-Object Name,Path,Status | ConvertTo-Csv -NoTypeInformation"
        )
        raw = self.run_powershell(ps)
        unsigned = []
        try:
            reader = csv.DictReader(io.StringIO(raw))
            for row in reader:
                name   = (row.get("Name")   or "").strip()
                path   = (row.get("Path")   or "").strip()
                status = (row.get("Status") or "").strip()
                if name and path and status:
                    unsigned.append({"name": name, "path": path, "status": status})
        except Exception:
            pass
        return unsigned

    # =========================
    # 🔄 WINDOWS UPDATE
    # =========================
    def collect_pending_updates(self):
        raw = self.run_powershell(
            "try { "
            "  $updates = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0 and Type=''Software''').Updates; "
            "  $updates | ForEach-Object { $_.Title } "
            "} catch { Write-Output 'ERROR' }"
        )
        updates = []
        if "ERROR" not in raw:
            updates = [l.strip() for l in raw.splitlines() if l.strip()]

        # Last update date
        last_raw = self.run_powershell(
            "Get-HotFix | Sort-Object InstalledOn -Descending | "
            "Select -First 1 | Select InstalledOn | ConvertTo-Csv -NoTypeInformation"
        )
        last_update = "Desconocido"
        lu_lines = [l.strip() for l in last_raw.splitlines() if l.strip()]
        if len(lu_lines) >= 2:
            last_update = lu_lines[1].strip('"')

        return {
            "pending": updates,
            "pending_count": len(updates),
            "last_update": last_update
        }

    # =========================
    # 💀 TASKS
    # =========================
    def collect_tasks(self):
        raw = self.run_command(["schtasks", "/query", "/fo", "LIST", "/v"])
        return list(set(raw.split("\n\n")))

    # =========================
    # ⚙️ SERVICES
    # =========================
    def collect_services(self):
        raw = self.run_powershell(
            "Get-CimInstance Win32_Service | Select Name,PathName,StartMode,State | ConvertTo-Csv -NoTypeInformation"
        )
        services = []
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        for line in lines[1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 4:
                services.append({
                    "name": parts[0],
                    "path": parts[1],
                    "start_mode": parts[2],
                    "state": parts[3]
                })
        return services

    # =========================
    # 💀 REGISTRY
    # =========================
    def collect_registry_run(self):
        raw = self.run_command([
            "reg", "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        ])
        return list(set(raw.splitlines()))

    # =========================
    # 💀 STARTUP
    # =========================
    def collect_startup(self):
        raw = self.run_command([
            "cmd", "/c",
            "dir %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        ])
        return list(set(raw.splitlines()))

    # =========================
    # 🔥 FIREWALL
    # =========================
    def collect_firewall(self):
        raw = self.run_powershell(
            "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Block | "
            "Get-NetFirewallPortFilter | Select LocalPort,Protocol | ConvertTo-Csv -NoTypeInformation"
        )
        blocked_ports = set()
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        for line in lines[1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 1:
                blocked_ports.add(parts[0])
        return blocked_ports

    # =========================
    # 🖥️ SYSTEM INFO
    # =========================
    def collect_system_info(self):
        raw = self.run_powershell(
            "Get-ComputerInfo | Select WindowsProductName,OsVersion,CsName,OsArchitecture,OsLastBootUpTime "
            "| ConvertTo-Csv -NoTypeInformation"
        )
        info = {
            "os": "Windows",
            "version": "",
            "hostname": "",
            "arch": "",
            "last_boot": "",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        if len(lines) >= 2:
            parts = [p.strip('"') for p in lines[1].split(",")]
            if len(parts) >= 5:
                info["os"]        = parts[0]
                info["version"]   = parts[1]
                info["hostname"]  = parts[2]
                info["arch"]      = parts[3]
                info["last_boot"] = parts[4]
        return info

    # =========================
    # 🚀 MASTER
    # =========================
    def collect_all(self, progress_callback=None):
        modules = [
            ("system_info",      self.collect_system_info),
            ("users",            self.collect_users),
            ("password_policy",  self.collect_password_policy),
            ("network",          self.collect_network),
            ("smb_shares",       self.collect_smb_shares),
            ("processes",        self.collect_processes),
            ("signatures",       self.collect_signatures),
            ("tasks",            self.collect_tasks),
            ("services",         self.collect_services),
            ("registry_run",     self.collect_registry_run),
            ("startup",          self.collect_startup),
            ("firewall",         self.collect_firewall),
            ("windows_update",   self.collect_pending_updates),
        ]

        results = {}
        for i, (name, func) in enumerate(modules, 1):
            try:
                results[name] = func()
                self.logger.info(f"✅ Módulo completado: {name}")
            except Exception as e:
                self.logger.error(f"❌ Error en módulo {name}: {e}")
                results[name] = None

            if progress_callback:
                progress_callback(i, len(modules), name)

        return results