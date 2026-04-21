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
    # 📋 EVENT LOGS
    # =========================
    def collect_event_logs(self):
        import json

        def _int(raw):
            try:
                return int(raw.strip() or 0)
            except Exception:
                return 0

        def _count(flt, max_events=500):
            raw = self.run_powershell(
                f"try {{ (Get-WinEvent -FilterHashtable {flt} "
                f"-MaxEvents {max_events} -EA SilentlyContinue | Measure-Object).Count "
                "}} catch { 0 }"
            )
            return _int(raw)

        s24 = "@{LogName='Security';StartTime=(Get-Date).AddHours(-24)"
        s1  = "@{LogName='Security';StartTime=(Get-Date).AddHours(-1)"

        failed_24h  = _count(s24 + ";Id=4625}")
        failed_1h   = _count(s1  + ";Id=4625}")
        lockouts    = _count(s24 + ";Id=4740}")
        created     = _count(s24 + ";Id=4720}")

        # 4672 — excluir cuentas de servicio del sistema
        priv_raw = self.run_powershell(
            "try { $e=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672;"
            "StartTime=(Get-Date).AddHours(-24)} -MaxEvents 500 -EA SilentlyContinue; "
            "$skip=@('SYSTEM','LOCAL SERVICE','NETWORK SERVICE'); "
            "($e|Where-Object{$skip -notcontains $_.Properties[1].Value}|Measure-Object).Count "
            "} catch { 0 }"
        )
        priv = _int(priv_raw)

        # 4624 fuera de horario (23:00-07:00)
        offhours_raw = self.run_powershell(
            "try { $e=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;"
            "StartTime=(Get-Date).AddHours(-24)} -MaxEvents 500 -EA SilentlyContinue; "
            "($e|Where-Object{$_.TimeCreated.Hour -lt 7 -or $_.TimeCreated.Hour -ge 23}|Measure-Object).Count "
            "} catch { 0 }"
        )
        offhours = _int(offhours_raw)

        # 4624 LogonType=10 (RemoteInteractive / RDP)
        remote_raw = self.run_powershell(
            "try { $e=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;"
            "StartTime=(Get-Date).AddHours(-24)} -MaxEvents 500 -EA SilentlyContinue; "
            "($e|Where-Object{$_.Properties[8].Value -eq 10}|Measure-Object).Count "
            "} catch { 0 }"
        )
        remote = _int(remote_raw)

        # Cuentas únicas objetivo en 4625 (password spray)
        spray_raw = self.run_powershell(
            "try { $e=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;"
            "StartTime=(Get-Date).AddHours(-24)} -MaxEvents 100 -EA SilentlyContinue; "
            "($e|ForEach-Object{$_.Properties[5].Value}|Where-Object{$_}|Sort-Object -Unique) -join ',' "
            "} catch { '' }"
        )
        unique_targets = [a.strip() for a in spray_raw.strip().split(",") if a.strip()]

        log_info_raw = self.run_powershell(
            "try { $l=Get-WinEvent -ListLog 'Security' -EA Stop; "
            "@{IsEnabled=$l.IsEnabled;MaxSizeMB=[math]::Round($l.MaximumSizeInBytes/1MB)} | ConvertTo-Json "
            "} catch { '{\"IsEnabled\":false,\"MaxSizeMB\":0}' }"
        )
        log_info = {"IsEnabled": True, "MaxSizeMB": 0}
        try:
            log_info = json.loads(log_info_raw.strip()) if log_info_raw.strip() else log_info
        except Exception:
            pass

        return {
            "failed_logins_24h":     failed_24h,
            "failed_logins_1h":      failed_1h,
            "lockouts_24h":          lockouts,
            "users_created_24h":     created,
            "priv_logons_24h":       priv,
            "offhours_logons_24h":   offhours,
            "remote_logons_24h":     remote,
            "unique_failed_accounts": unique_targets,
            "security_log_enabled":  bool(log_info.get("IsEnabled", True)),
            "security_log_max_mb":   int(log_info.get("MaxSizeMB", 0) or 0),
        }

    # =========================
    # 🔑 AUTO-LOGIN
    # =========================
    def collect_autologin(self):
        import json
        raw = self.run_powershell(
            "$p='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'; "
            "try { $r=Get-ItemProperty $p -EA Stop; "
            "@{ AutoAdminLogon=$r.AutoAdminLogon; DefaultUserName=$r.DefaultUserName; "
            "   DefaultPassword=if($r.DefaultPassword){'SET'}else{''} } | ConvertTo-Json "
            "} catch { '{}' }"
        )
        try:
            return json.loads(raw.strip()) if raw.strip() else {}
        except Exception:
            return {}

    # =========================
    # 🔒 BITLOCKER
    # =========================
    def collect_bitlocker(self):
        import csv, io
        raw = self.run_powershell(
            "try { Get-BitLockerVolume | "
            "Select MountPoint,ProtectionStatus,EncryptionMethod,VolumeStatus "
            "| ConvertTo-Csv -NoTypeInformation } catch { '' }"
        )
        volumes = []
        try:
            reader = csv.DictReader(io.StringIO(raw))
            for row in reader:
                volumes.append({
                    "mount":      (row.get("MountPoint")      or "").strip(),
                    "status":     (row.get("ProtectionStatus") or "").strip(),
                    "method":     (row.get("EncryptionMethod") or "").strip(),
                    "vol_status": (row.get("VolumeStatus")    or "").strip(),
                })
        except Exception:
            pass
        return volumes

    # =========================
    # 🖧 RDP / NTLM CONFIG
    # =========================
    def collect_rdp_config(self):
        import json
        raw = self.run_powershell(
            "$r = @{}; "
            "try { $v = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
            "  -Name fDenyTSConnections -EA Stop).fDenyTSConnections; $r['RDPEnabled']=($v -eq 0) } "
            "catch { $r['RDPEnabled']=$false }; "
            "try { $v = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
            "  -Name UserAuthenticationRequired -EA Stop).UserAuthenticationRequired; $r['NLARequired']=($v -eq 1) } "
            "catch { $r['NLARequired']=$true }; "
            "try { $v = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
            "  -Name LmCompatibilityLevel -EA Stop).LmCompatibilityLevel; $r['NTLMLevel']=[int]$v } "
            "catch { $r['NTLMLevel']=3 }; "
            "try { $v = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
            "  -Name UseLogonCredential -EA Stop).UseLogonCredential; $r['WDigest']=([int]$v -eq 1) } "
            "catch { $r['WDigest']=$false }; "
            "try { $v = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' "
            "  -Name EnableVirtualizationBasedSecurity -EA Stop).EnableVirtualizationBasedSecurity; $r['CredentialGuard']=([int]$v -eq 1) } "
            "catch { $r['CredentialGuard']=$false }; "
            "$r | ConvertTo-Json"
        )
        try:
            return json.loads(raw.strip()) if raw.strip() else {}
        except Exception:
            return {}

    # =========================
    # 🦠 SUSPICIOUS PROCESSES
    # =========================
    def collect_suspicious_processes(self):
        import csv, io
        ps = (
            "Get-Process | Where-Object { "
            "  $_.Path -and ("
            "    $_.Path -like '*\\AppData\\Local\\Temp\\*' -or "
            "    $_.Path -like '*\\AppData\\Roaming\\*' -or "
            "    $_.Path -like '*\\Downloads\\*' -or "
            "    $_.Path -like '*\\Desktop\\*' -or "
            "    $_.Path -like '*\\Public\\*' "
            "  ) "
            "} | Select Name,Path,Id | ConvertTo-Csv -NoTypeInformation"
        )
        raw = self.run_powershell(ps)
        procs = []
        try:
            reader = csv.DictReader(io.StringIO(raw))
            for row in reader:
                name = (row.get("Name") or "").strip()
                path = (row.get("Path") or "").strip()
                pid  = (row.get("Id")   or "").strip()
                if name and path:
                    procs.append({"name": name, "path": path, "pid": pid})
        except Exception:
            pass
        return procs

    # =========================
    # 🐚 POWERSHELL LOGS
    # =========================
    def collect_powershell_logs(self):
        import json
        ps = (
            "try { "
            "$log='Microsoft-Windows-PowerShell/Operational'; "
            "$evts=Get-WinEvent -LogName $log -MaxEvents 300 -EA SilentlyContinue "
            "  | Where-Object {$_.Id -eq 4104}; "
            "$pat='Invoke-Expression|IEX |IEX\\(|DownloadString|DownloadFile|"
            "FromBase64String|-EncodedCommand|-Enc |WebClient|Invoke-WebRequest|"
            "Start-BitsTransfer|WindowStyle.*Hidden|http://|https://'; "
            "$hits=$evts | Where-Object {$_.Message -match $pat}; "
            "$samples=$hits | Select-Object -First 10 | ForEach-Object { "
            "  @{Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss');"
            "    Snippet=(($_.Message -split \"`n\")[0..1] -join ' ').Substring(0,[math]::Min(200,($_.Message).Length))} "
            "}; "
            "@{Count=($hits|Measure-Object).Count;Enabled=$true;Samples=$samples} | ConvertTo-Json -Depth 3 "
            "} catch { '{\"Count\":0,\"Enabled\":false,\"Samples\":[]}' }"
        )
        raw = self.run_powershell(ps)
        try:
            return json.loads(raw.strip()) if raw.strip() else {}
        except Exception:
            return {}

    # =========================
    # 🛡️ WINDOWS DEFENDER
    # =========================
    def collect_defender(self):
        import json

        status_raw = self.run_powershell(
            "try { Get-MpComputerStatus | Select "
            "AMServiceEnabled,RealTimeProtectionEnabled,AntispywareEnabled,AntivirusSignatureAge "
            "| ConvertTo-Json } catch { '{}' }"
        )
        excl_raw = self.run_powershell(
            "try { $p=Get-MpPreference; "
            "@{Paths=@($p.ExclusionPath);Processes=@($p.ExclusionProcess);Extensions=@($p.ExclusionExtension)} "
            "| ConvertTo-Json } catch { '{}' }"
        )

        status = {}
        try:
            status = json.loads(status_raw.strip()) if status_raw.strip() else {}
        except Exception:
            pass

        excl = {}
        try:
            excl = json.loads(excl_raw.strip()) if excl_raw.strip() else {}
        except Exception:
            pass

        def _list(val):
            if not val:
                return []
            return [v for v in (val if isinstance(val, list) else [val]) if v]

        excl_paths = _list(excl.get("Paths"))
        excl_procs = _list(excl.get("Processes"))
        susp_kw    = ("temp", "appdata", "public", "downloads", "desktop", "programdata", "tmp")
        susp_paths = [p for p in excl_paths if any(k in p.lower() for k in susp_kw)]

        return {
            "service_enabled":          bool(status.get("AMServiceEnabled",        False)),
            "realtime_enabled":         bool(status.get("RealTimeProtectionEnabled", False)),
            "antispyware_enabled":      bool(status.get("AntispywareEnabled",       False)),
            "signature_age_days":       int(status.get("AntivirusSignatureAge",     0) or 0),
            "exclusion_paths":          excl_paths,
            "exclusion_processes":      excl_procs,
            "suspicious_exclusion_paths": susp_paths,
        }

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
    # 🛡️ UAC
    # =========================
    def collect_uac(self):
        import json
        raw = self.run_powershell(
            "$p = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; "
            "try { "
            "  $r = Get-ItemProperty -Path $p -ErrorAction Stop; "
            "  @{ "
            "    EnableLUA                    = [int]$r.EnableLUA; "
            "    ConsentPromptBehaviorAdmin   = [int]$r.ConsentPromptBehaviorAdmin; "
            "    ConsentPromptBehaviorUser    = [int]$r.ConsentPromptBehaviorUser; "
            "    PromptOnSecureDesktop        = [int]$r.PromptOnSecureDesktop "
            "  } | ConvertTo-Json "
            "} catch { '{}' }"
        )
        try:
            return json.loads(raw.strip()) if raw.strip() else {}
        except Exception:
            return {}

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
            ("firewall",              self.collect_firewall),
            ("windows_update",        self.collect_pending_updates),
            ("uac",                   self.collect_uac),
            ("event_logs",            self.collect_event_logs),
            ("rdp_config",            self.collect_rdp_config),
            ("suspicious_processes",  self.collect_suspicious_processes),
            ("autologin",             self.collect_autologin),
            ("bitlocker",             self.collect_bitlocker),
            ("powershell_logs",       self.collect_powershell_logs),
            ("defender",              self.collect_defender),
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