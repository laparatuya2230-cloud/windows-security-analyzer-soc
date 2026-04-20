import locale
import subprocess
import json
from datetime import datetime


class WindowsScanner:
    def __init__(self, logger):
        self.logger = logger
        self.encoding = locale.getpreferredencoding(False) or "cp850"

    def run_command(self, args):
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding=self.encoding,
                errors="replace",
                timeout=30
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout: {args}")
            return ""
        except Exception as e:
            self.logger.error(f"Command error: {e}")
            return ""

    def run_powershell(self, script):
        return self.run_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])

    @staticmethod
    def unique_preserve(lines):
        seen = set()
        out = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                out.append(line)
        return out

    # =========================
    # 🧠 USERS
    # =========================
    def collect_users(self):
        raw = self.run_powershell(
            "Get-LocalUser | Select Name,Enabled,PasswordRequired | ConvertTo-Csv -NoTypeInformation"
        )
        users_full = []
        users_str = []
        users_without_password = []

        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        for line in lines[1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 3:
                name = parts[0]
                enabled = parts[1].lower() == "true"
                password_required = parts[2].lower() == "true"
                users_full.append({"name": name, "enabled": enabled,
                                   "password_required": password_required})
                users_str.append(name)
                if not password_required:
                    users_without_password.append(name)

        admins_raw = self.run_powershell(
            "Get-LocalGroupMember -SID 'S-1-5-32-544' | Select Name | ConvertTo-Csv -NoTypeInformation"
        )
        admins = []
        admin_lines = [l.strip() for l in admins_raw.splitlines() if l.strip()]
        for line in admin_lines[1:]:
            full_name = line.strip('"')
            # Convert DESKTOP\\user -> user for consistent comparisons.
            simple_name = full_name.split("\\")[-1].strip()
            if simple_name:
                admins.append(simple_name)

        return {
            "users": users_str,
            "users_full": users_full,
            "users_without_password": users_without_password,
            "admins": self.unique_preserve(admins),
            "admin_group": "Administradores",
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
        unique = self.unique_preserve(raw.splitlines())
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
        raw = self.run_powershell(
            "Get-Process | Where-Object {$_.Path} | ForEach-Object { "
            "  $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue; "
            "  [PSCustomObject]@{Name=$_.Name; Path=$_.Path; Status=$sig.Status; Issuer=$sig.SignerCertificate.Issuer} "
            "} | Where-Object {$_.Status -ne 'Valid'} | Select Name,Path,Status | ConvertTo-Csv -NoTypeInformation"
        )
        unsigned = []
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        for line in lines[1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 3:
                unsigned.append({
                    "name": parts[0],
                    "path": parts[1],
                    "status": parts[2]
                })
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
        return self.unique_preserve(raw.split("\n\n"))

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
        return self.unique_preserve(raw.splitlines())

    # =========================
    # 💀 STARTUP
    # =========================
    def collect_startup(self):
        raw = self.run_command([
            "cmd", "/c",
            "dir %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        ])
        return self.unique_preserve(raw.splitlines())

    # =========================
    # 🔥 FIREWALL
    # =========================
    def collect_firewall(self):
        blocked_raw = self.run_powershell(
            "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Block | "
            "Get-NetFirewallPortFilter | Select LocalPort,Protocol | ConvertTo-Csv -NoTypeInformation"
        )
        blocked_ports = set()
        lines = [l.strip() for l in blocked_raw.splitlines() if l.strip()]
        for line in lines[1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 1:
                blocked_ports.add(parts[0])

        profile_raw = self.run_powershell(
            "Get-NetFirewallProfile | Select Name,Enabled | ConvertTo-Csv -NoTypeInformation"
        )
        profiles = []
        p_lines = [l.strip() for l in profile_raw.splitlines() if l.strip()]
        for line in p_lines[1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 2:
                profiles.append({
                    "name": parts[0],
                    "enabled": parts[1].lower() == "true",
                })

        return {
            "blocked_ports": blocked_ports,
            "profiles": profiles,
        }

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
