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
        import os
        _exe = os.path.abspath(sys.executable)
        self._own_exe  = _exe.replace("'", "''")
        self._own_name = os.path.splitext(os.path.basename(_exe))[0]
        self._own_dir  = os.path.dirname(os.path.dirname(_exe))

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

        # SMBv1
        smb1_raw = self.run_powershell(
            "try { (Get-SmbServerConfiguration -EA Stop).EnableSMB1Protocol } catch { 'False' }"
        ).strip().lower()
        smb1 = smb1_raw == "true"

        # Sesiones nulas — verificar registro directamente (fuente autoritativa)
        null_reg_raw = self.run_powershell(
            "try { (Get-ItemProperty "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
            "-Name RestrictNullSessAccess -EA Stop).RestrictNullSessAccess "
            "} catch { '1' }"
        ).strip()
        try:
            null_sess = int(null_reg_raw) == 1
        except Exception:
            null_sess = True  # si no se puede leer, asumir seguro

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
        import csv, io
        own_exe, own_name, own_dir = self._own_exe, self._own_name, self._own_dir

        ps = (
            "Get-Process | Where-Object { "
            "  $_.Path -and "
            "  $_.Path -notlike '*\\WindowsApps\\*' -and "
            "  $_.Path -notlike '*\\Windows\\System32\\*' -and "
            "  $_.Path -notlike '*\\Windows\\SysWOW64\\*' -and "
            "  $_.Path -notlike '*\\Program Files\\*' -and "
            "  $_.Path -notlike '*\\Program Files (x86)\\*' -and "
            "  $_.Path -notlike '*\\Riot Games\\*' -and "
            "  $_.Path -notlike '*\\Steam\\*' -and "
            "  $_.Path -notlike '*\\Epic Games\\*' -and "
            "  $_.Path -notlike '*.venv\\*' -and "
            "  $_.Path -notlike '*\\Python*\\Scripts\\*' -and "
            f"  $_.Path -ne '{own_exe}' -and "
            f"  $_.Path -notlike '{own_dir}\\*' -and "
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

        # Estado del log de seguridad
        log_info_raw = self.run_powershell(
            "try { $l=Get-WinEvent -ListLog 'Security' -EA Stop; "
            "@{IsEnabled=$l.IsEnabled;MaxSizeMB=[math]::Round($l.MaximumSizeInBytes/1MB);ReadError=$false} | ConvertTo-Json "
            "} catch { '{\"IsEnabled\":null,\"MaxSizeMB\":0,\"ReadError\":true}' }"
        )
        log_info = {"IsEnabled": None, "MaxSizeMB": 0, "ReadError": True}
        try:
            log_info = json.loads(log_info_raw.strip()) if log_info_raw.strip() else log_info
        except Exception:
            pass

        # Estado del servicio Windows Event Log
        svc_raw = self.run_powershell(
            "try { (Get-Service -Name EventLog -EA Stop).Status } catch { 'Unknown' }"
        ).strip()
        eventlog_svc_running = svc_raw.lower() == "running"

        # auditpol: GUIDs de Logon/Logoff/Special Logon (independientes del idioma)
        # Parseo por posición de columna (col 4 = GUID, col 5 = setting) porque
        # los nombres de columna del CSV están localizados y varían según el idioma del SO.
        auditpol_raw = self.run_powershell(
            "try { "
            "$target = @('0CCE9215','0CCE9216','0CCE921B'); "
            "$lines = auditpol /get /category:* /r 2>$null | Select-Object -Skip 1; "
            "$found = $false; "
            "foreach ($line in $lines) { "
            "  foreach ($g in $target) { "
            "    if ($line -match $g) { "
            "      $parts = $line -split ','; "
            "      if ($parts.Count -ge 5) { "
            "        $setting = $parts[4].Trim().Trim('\"'); "
            "        if ($setting -and $setting -notmatch 'No Auditing|Sin auditor|^$') { "
            "          $found = $true; break "
            "        } "
            "      } "
            "    } "
            "  }; "
            "  if ($found) { break } "
            "}; "
            "if ($found) { 'enabled' } else { 'disabled' } "
            "} catch { 'unknown' }"
        ).strip().lower()
        auditpol_ok      = auditpol_raw == "enabled"
        auditpol_unknown = auditpol_raw == "unknown"

        is_enabled  = log_info.get("IsEnabled")   # None = error, True/False = real value
        read_error  = bool(log_info.get("ReadError", True))

        return {
            "failed_logins_24h":      failed_24h,
            "failed_logins_1h":       failed_1h,
            "lockouts_24h":           lockouts,
            "users_created_24h":      created,
            "priv_logons_24h":        priv,
            "offhours_logons_24h":    offhours,
            "remote_logons_24h":      remote,
            "unique_failed_accounts": unique_targets,
            "security_log_enabled":   is_enabled,
            "security_log_read_error": read_error,
            "security_log_max_mb":    int(log_info.get("MaxSizeMB", 0) or 0),
            "eventlog_svc_running":   eventlog_svc_running,
            "auditpol_ok":            auditpol_ok,
            "auditpol_unknown":       auditpol_unknown,
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
        import json
        raw = self.run_powershell(
            "try { "
            "  Get-BitLockerVolume | ForEach-Object { "
            "    $protectors = ($_.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ','; "
            "    @{ "
            "      Mount=$_.MountPoint; "
            "      ProtectionStatus=$_.ProtectionStatus.ToString(); "
            "      VolumeStatus=$_.VolumeStatus.ToString(); "
            "      EncryptionPercentage=$_.EncryptionPercentage; "
            "      EncryptionMethod=$_.EncryptionMethod.ToString(); "
            "      KeyProtectors=$protectors "
            "    } "
            "  } | ConvertTo-Json -Depth 2 "
            "} catch { '[]' }"
        )
        volumes = []
        try:
            data = json.loads(raw.strip()) if raw.strip() else []
            if isinstance(data, dict):
                data = [data]
            for v in data:
                volumes.append({
                    "mount":       (v.get("Mount")               or "").strip(),
                    "status":      str(v.get("ProtectionStatus") or "").strip(),
                    "vol_status":  str(v.get("VolumeStatus")     or "").strip(),
                    "pct":         int(v.get("EncryptionPercentage") or 0),
                    "method":      str(v.get("EncryptionMethod") or "").strip(),
                    "protectors":  str(v.get("KeyProtectors")    or "").strip(),
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
        import csv, io, os, sys
        own_exe  = os.path.abspath(sys.executable).replace("'", "''")
        own_name = os.path.splitext(os.path.basename(sys.executable))[0]
        own_dir  = os.path.dirname(os.path.dirname(os.path.abspath(sys.executable)))
        ps = (
            # Step 1: filter by suspicious paths, excluding own process and dev environment
            "$procs = Get-Process | Where-Object { "
            "  $_.Path -and "
            f"  $_.Path -ne '{own_exe}' -and "
            f"  $_.Name -ne '{own_name}' -and "
            f"  $_.Path -notlike '{own_dir}\\*' -and "
            "  $_.Path -notlike '*.venv\\*' -and "
            "  $_.Path -notlike '*\\Python*\\Scripts\\*' -and "
            "  ("
            "    $_.Path -like '*\\AppData\\Local\\Temp\\*' -or "
            "    $_.Path -like '*\\AppData\\Roaming\\*' -or "
            "    $_.Path -like '*\\Downloads\\*' -or "
            "    $_.Path -like '*\\Desktop\\*' -or "
            "    $_.Path -like '*\\Public\\*' "
            "  ) "
            # Deduplicate by executable path (multiple instances of same exe = one finding)
            "} | Sort-Object Path -Unique; "
            # Step 2: only report processes that are explicitly unsigned or tampered.
            # 'Valid' → trusted embedded sig. 'UnknownError' → catalog-signed (also trusted).
            # Only 'NotSigned' or 'HashMismatch' are genuinely suspicious.
            "$result = $procs | ForEach-Object { "
            "  $sig = Get-AuthenticodeSignature $_.Path -EA SilentlyContinue; "
            "  $status = if ($sig) { $sig.Status.ToString() } else { 'NotSigned' }; "
            "  if ($status -eq 'NotSigned' -or $status -eq 'HashMismatch') { "
            "    [PSCustomObject]@{Name=$_.Name; Path=$_.Path; Id=$_.Id} "
            "  } "
            "}; "
            "if ($result) { $result | ConvertTo-Csv -NoTypeInformation } else { '\"Name\",\"Path\",\"Id\"' }"
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
            "} catch { '{\"Count\":0,\"Enabled\":false,\"ReadError\":true,\"Samples\":[]}' }"
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
        # Estado de perfiles (Domain, Private, Public)
        profiles_raw = self.run_powershell(
            "try { "
            "Get-NetFirewallProfile | Select Name,Enabled | ConvertTo-Csv -NoTypeInformation"
            " } catch { '' }"
        )
        profiles = []
        for line in [l.strip() for l in profiles_raw.splitlines() if l.strip()][1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 2:
                profiles.append({"name": parts[0], "enabled": parts[1].lower() == "true"})

        # Puertos con regla ALLOW inbound explícita (los que firewall deja pasar)
        allowed_raw = self.run_powershell(
            "try { "
            "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow "
            "| Get-NetFirewallPortFilter "
            "| Where-Object { $_.LocalPort -match '^\\d+$' } "
            "| Select-Object -ExpandProperty LocalPort "
            "} catch { '' }"
        )
        allowed_ports = {p.strip() for p in allowed_raw.splitlines() if p.strip().isdigit()}

        return {
            "profiles":             profiles,
            "allowed_inbound_ports": list(allowed_ports),
        }

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
    def collect_all(self, progress_callback=None, enabled_modules=None):
        all_modules = [
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

        # system_info always runs (needed for UI info panel)
        if enabled_modules is not None:
            modules = [(n, f) for n, f in all_modules
                       if n == "system_info" or n in enabled_modules]
        else:
            modules = all_modules

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