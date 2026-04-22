import re
import hashlib

MITRE_MAP = {
    "SMB": ["T1021.002 - SMB/Windows Admin Shares"],
    "RDP": ["T1021.001 - Remote Desktop Protocol"],
    "RPC": ["T1046 - Network Service Discovery"],
    "NetBIOS": ["T1046 - Network Service Discovery"],
}

LOLBINS = {
    "powershell": "T1059.001 - PowerShell",
    "wscript": "T1059.005 - Visual Basic",
    "cscript": "T1059.005 - Visual Basic",
    "mshta": "T1218.005 - Mshta",
    "rundll32": "T1218.011 - Rundll32",
    "regsvr32": "T1218.010 - Regsvr32",
    "certutil": "T1140 - Deobfuscate/Decode",
    "bitsadmin": "T1197 - BITS Jobs",
    "wmic": "T1047 - Windows Management Instrumentation",
}


class SecurityAnalyzer:
    def __init__(self, logger):
        self.logger = logger

    def build(self, severity, title, details, recommendation, mitre=None):
        norm  = re.sub(r'\b\d+\b', '#', title.lower().strip())
        fid   = hashlib.md5(f"{severity.lower()}:{norm}".encode()).hexdigest()[:12]
        return {
            "id":             fid,
            "severity":       severity.lower(),
            "title":          title,
            "details":        details,
            "recommendation": recommendation,
            "mitre":          mitre or [],
        }

    def _extract_port_from_netstat_line(self, line):
        # Example: TCP 0.0.0.0:445 0.0.0.0:0 LISTENING 4
        match = re.search(r":(\d+)\s+\S+\s+LISTENING\b", line, re.IGNORECASE)
        return match.group(1) if match else None

    # Ports
    def analyze_ports(self, results):
        findings = []
        firewall = results.get("firewall", {}) or {}
        allowed_ports  = set(firewall.get("allowed_inbound_ports", []) or [])
        fw_profiles    = firewall.get("profiles", []) or []
        firewall_on    = any(p.get("enabled", True) for p in fw_profiles) if fw_profiles else True

        ports = results.get("network", {}).get("listening_ports", []) or []

        high_risk_ports = {
            "21":   "FTP",
            "23":   "Telnet",
            "445":  "SMB",
            "3389": "RDP",
            "139":  "NetBIOS",
            "135":  "RPC",
            "5900": "VNC",
        }
        seen_ports = set()

        for line in ports:
            if "LISTENING" not in line.upper():
                continue

            port = self._extract_port_from_netstat_line(line)
            if not port or port not in high_risk_ports or port in seen_ports:
                continue
            seen_ports.add(port)

            name  = high_risk_ports[port]
            mitre = MITRE_MAP.get(name, ["T1046 - Network Service Discovery"])
            exposed_to_all = (
                f"0.0.0.0:{port}" in line
                or f"[::]:{port}" in line
                or f"*:{port}" in line
            )

            # Protocolos inseguros — siempre crítico independientemente del firewall
            if name in ("FTP", "Telnet"):
                findings.append(self.build(
                    "critical",
                    f"Protocolo inseguro activo: {name} (puerto {port})",
                    f"Puerto {port} en escucha. {line.strip()}",
                    f"Deshabilitar {name} y usar alternativas seguras (SSH/SFTP).",
                    ["T1021 - Remote Services"],
                ))
                continue

            # Determinar exposición real considerando firewall
            fw_allows    = port in allowed_ports
            fw_protected = firewall_on and not fw_allows  # firewall ON y sin regla ALLOW → bloqueado

            if fw_protected:
                # Puerto activo pero bloqueado por firewall — riesgo bajo
                findings.append(self.build(
                    "low",
                    f"Puerto {name} ({port}) activo pero bloqueado por firewall",
                    f"El servicio {name} está en escucha localmente pero el firewall no tiene regla "
                    f"ALLOW inbound para el puerto {port}.",
                    f"Verificar que el servicio {name} sea necesario. Si no, deshabilitarlo.",
                    mitre,
                ))
            elif exposed_to_all and not firewall_on:
                # Sin firewall + expuesto → alta severidad
                sev = "critical" if name == "SMB" else "high"
                findings.append(self.build(
                    sev,
                    f"Puerto {name} ({port}) expuesto a red sin protección de firewall",
                    f"El servicio {name} acepta conexiones desde cualquier dirección y el firewall "
                    f"no está activo. Riesgo de acceso remoto no autorizado.",
                    f"Activar el firewall de Windows y restringir el puerto {port} a hosts autorizados.",
                    mitre,
                ))
            else:
                # Firewall ON + regla ALLOW → puerto realmente accesible
                sev = "high" if name in ("SMB", "RDP") else "medium"
                findings.append(self.build(
                    sev,
                    f"Puerto {name} ({port}) expuesto con regla ALLOW en firewall",
                    f"El puerto {port} ({name}) tiene una regla de entrada explícita que permite "
                    f"conexiones entrantes.",
                    f"Restringir la regla de firewall del puerto {port} a IPs o subredes autorizadas.",
                    mitre,
                ))

        return findings

    # Firewall
    def analyze_firewall(self, results):
        findings = []
        firewall = results.get("firewall", {}) or {}

        if not isinstance(firewall, dict):
            return findings

        profiles = firewall.get("profiles", []) or []
        if not profiles:
            return findings

        disabled_profiles = [p.get("name", "Unknown") for p in profiles if not p.get("enabled", True)]
        if len(disabled_profiles) == len(profiles):
            findings.append(
                self.build(
                    "critical",
                    "Firewall desactivado en todos los perfiles",
                    f"Perfiles: {', '.join(disabled_profiles)}",
                    "Activar firewall en Domain, Private y Public.",
                    ["T1562.004 - Disable or Modify System Firewall"],
                )
            )
        elif disabled_profiles:
            findings.append(
                self.build(
                    "medium",
                    "Firewall desactivado parcialmente",
                    f"Perfiles sin proteccion: {', '.join(disabled_profiles)}",
                    "Revisar configuracion y habilitar los perfiles faltantes.",
                    ["T1562.004 - Disable or Modify System Firewall"],
                )
            )
        return findings

    # Users
    def analyze_users(self, results):
        findings = []
        users_data = results.get("users", {}) or {}
        users = users_data.get("users_full", []) or []
        admins = {u.lower() for u in (users_data.get("admins", []) or [])}

        # Cuentas gestionadas por el sistema donde PasswordRequired=False es normal
        system_builtin = {"defaultaccount", "wdagutilityaccount"}

        for user in users:
            name = user.get("name", "").strip()
            if not name:
                continue

            name_l = name.lower()
            enabled = bool(user.get("enabled", True))
            password_required = bool(user.get("password_required", True))

            if name_l in ("guest", "invitado") and enabled:
                findings.append(
                    self.build(
                        "high",
                        f"Cuenta invitado habilitada: {name}",
                        "La cuenta Invitado esta activa.",
                        "Deshabilitar la cuenta Invitado si no es estrictamente necesaria.",
                        ["T1078 - Valid Accounts"],
                    )
                )

            # Revisar password_required (omitir cuentas gestionadas por el sistema)
            if not password_required and name_l not in system_builtin:
                if name_l in admins:
                    severity = "high"
                else:
                    severity = "medium"  # siempre medium para que aparezca el botón Fix

                findings.append(
                    self.build(
                        severity,
                        f"Usuario sin contrasena requerida: {name}",
                        f"El usuario '{name}' tiene PasswordRequired=False "
                        f"({'activo' if enabled else 'deshabilitado'}).",
                        f'Ejecutar: net user "{name}" /passwordreq:yes',
                        ["T1078 - Valid Accounts"],
                    )
                )

            if not enabled:
                continue
        return findings

    # Password Policy
    def analyze_password_policy(self, results):
        findings = []
        policy = results.get("password_policy", {}) or {}
        if not policy:
            return findings

        max_age = int(policy.get("max_age", 0) or 0)
        lockout_threshold = int(policy.get("lockout_threshold", 0) or 0)
        history = int(policy.get("history", 0) or 0)

        if max_age == 0 or max_age > 90:
            findings.append(
                self.build(
                    "medium",
                    f"Contrasenas sin rotacion adecuada ({max_age} dias)",
                    f"max_age = {max_age}",
                    "Configurar expiracion entre 60 y 90 dias.",
                    ["T1078 - Valid Accounts"],
                )
            )

        if lockout_threshold == 0:
            findings.append(
                self.build(
                    "high",
                    "Sin bloqueo de cuenta por intentos fallidos",
                    "lockout_threshold = 0",
                    "Establecer bloqueo tras 5-10 intentos fallidos.",
                    ["T1110.001 - Password Guessing"],
                )
            )

        if history < 5:
            findings.append(
                self.build(
                    "low",
                    f"Historial de contrasenas bajo ({history})",
                    f"history = {history}",
                    "Configurar historial minimo de 10 contrasenas.",
                    ["T1078 - Valid Accounts"],
                )
            )

        return findings

    # SMB Shares
    def analyze_smb(self, results):
        findings = []
        smb = results.get("smb_shares", {}) or {}
        if not smb:
            return findings

        if smb.get("smb1_enabled"):
            findings.append(
                self.build(
                    "critical",
                    "SMBv1 habilitado",
                    "EnableSMB1Protocol = True",
                    "Deshabilitar SMBv1 inmediatamente.",
                    ["T1210 - Exploitation of Remote Services", "T1021.002 - SMB"],
                )
            )

        if not smb.get("null_session_restricted", True):
            findings.append(
                self.build(
                    "high",
                    "SMB: sesiones nulas sin restricción (RestrictNullSessAccess = 0)",
                    "Cualquier usuario anónimo puede conectarse a recursos compartidos IPC$ sin "
                    "credenciales, permitiendo enumeración de usuarios, grupos y políticas del dominio.",
                    "Establecer RestrictNullSessAccess = 1: "
                    "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
                    "-Name RestrictNullSessAccess -Value 1. "
                    "Si SMB no es necesario en red, bloquearlo en el firewall (puerto 445).",
                    ["T1135 - Network Share Discovery", "T1087 - Account Discovery"],
                )
            )

        default_admin_shares = {"ADMIN$", "IPC$", "C$", "D$"}
        custom_shares = [
            s.get("name", "")
            for s in (smb.get("shares", []) or [])
            if s.get("name", "").upper() not in default_admin_shares
        ]
        if custom_shares:
            findings.append(
                self.build(
                    "medium",
                    "Recursos compartidos adicionales detectados",
                    f"Shares detectados: {', '.join(sorted(set(custom_shares)))}",
                    "Validar permisos y necesidad de cada recurso compartido.",
                    ["T1135 - Network Share Discovery"],
                )
            )

        return findings

    # Processes / LOLBins
    def analyze_processes(self, results):
        findings = []
        procs = results.get("processes", {}) or {}
        if not procs:
            return findings

        suspicious_paths = ("appdata\\local\\temp", "\\temp\\", "\\public\\", "\\downloads\\")

        for proc in procs.get("processes", []) or []:
            path = (proc.get("path") or "").lower()
            if path and any(sp in path for sp in suspicious_paths):
                findings.append(
                    self.build(
                        "high",
                        f"Proceso ejecutandose desde ruta sospechosa: {proc.get('name', 'Unknown')}",
                        f"PID {proc.get('pid', '?')} - {proc.get('path', '')}",
                        "Investigar el proceso y su origen.",
                        ["T1059 - Command and Scripting Interpreter"],
                    )
                )

        # Rutas legítimas donde LOLBins son normales (OS los usa constantemente)
        system_lolbin_paths = ("\\system32\\", "\\syswow64\\", "\\systemapps\\")

        grouped_lolbins = {}
        for lolbin in procs.get("lolbins", []) or []:
            name = (lolbin.get("name") or "").lower()
            mitre_tag = LOLBINS.get(name, "T1218 - System Binary Proxy Execution")
            path = (lolbin.get("path") or "").lower()

            # Skip si es un LOLBin corriendo desde su ruta legítima del sistema
            if any(sp in path for sp in system_lolbin_paths):
                continue

            suspicious = bool(path) and any(sp in path for sp in suspicious_paths)
            key = (name, path)
            if key not in grouped_lolbins:
                grouped_lolbins[key] = {
                    "name": lolbin.get("name", "Unknown"),
                    "path": lolbin.get("path", "desconocida"),
                    "count": 0,
                    "suspicious": suspicious,
                    "mitre": mitre_tag,
                }
            grouped_lolbins[key]["count"] += 1

        for entry in grouped_lolbins.values():
            findings.append(
                self.build(
                    "high" if entry["suspicious"] else "review",
                    f"LOLBin activo: {entry['name']} ({entry['count']} proceso(s))",
                    f"Ruta: {entry['path']}",
                    "Verificar si su ejecucion corresponde al comportamiento esperado.",
                    [entry["mitre"]],
                )
            )

        return findings

    # Digital Signatures
    def analyze_signatures(self, results):
        findings = []
        unsigned = results.get("signatures", []) or []
        if not unsigned:
            return findings

        for item in unsigned[:10]:
            status = item.get("status", "Unknown")
            if status in ("NotSigned", "HashMismatch", "NotTrusted"):
                severity = "high" if status == "HashMismatch" else "medium"
                findings.append(
                    self.build(
                        severity,
                        f"Ejecutable con firma invalida: {item.get('name', 'Unknown')} ({status})",
                        item.get("path", ""),
                        "Validar integridad y origen del binario.",
                        ["T1036 - Masquerading", "T1574 - Hijack Execution Flow"],
                    )
                )

        return findings

    # Windows Update
    def analyze_updates(self, results):
        findings = []
        updates = results.get("windows_update", {}) or {}
        if not updates:
            return findings

        count = int(updates.get("pending_count", 0) or 0)
        last = updates.get("last_update", "Desconocido")

        if count > 20:
            findings.append(
                self.build(
                    "critical",
                    f"Sistema desactualizado: {count} actualizaciones pendientes",
                    f"Ultima actualizacion: {last}",
                    "Aplicar actualizaciones de seguridad inmediatamente.",
                    ["T1190 - Exploit Public-Facing Application"],
                )
            )
        elif count > 5:
            findings.append(
                self.build(
                    "high",
                    f"{count} actualizaciones pendientes de Windows",
                    f"Ultima actualizacion: {last}",
                    "Aplicar actualizaciones pendientes.",
                    ["T1190 - Exploit Public-Facing Application"],
                )
            )
        elif count > 0:
            findings.append(
                self.build(
                    "medium",
                    f"{count} actualizaciones menores pendientes",
                    f"Ultima actualizacion: {last}",
                    "Completar ciclo de actualizacion.",
                )
            )
        return findings

    # Persistence
    def analyze_persistence(self, results):
        findings = []
        whitelist = ("onedrive.exe", "teams.exe", "spotify.exe")
        suspicious_paths = ("appdata\\local\\temp", "\\public\\")

        for line in results.get("registry_run", []) or []:
            low = line.lower()
            if any(w in low for w in whitelist):
                continue
            if any(p in low for p in suspicious_paths):
                findings.append(
                    self.build(
                        "critical",
                        "Persistencia sospechosa en registro (Run key)",
                        line,
                        "Eliminar o deshabilitar la entrada sospechosa.",
                        ["T1547.001 - Registry Run Keys"],
                    )
                )

        for line in results.get("startup", []) or []:
            low = line.lower()
            if any(w in low for w in whitelist):
                continue
            if ".ps1" in low or any(p in low for p in suspicious_paths):
                findings.append(
                    self.build(
                        "high",
                        "Persistencia sospechosa en carpeta Startup",
                        line,
                        "Investigar y remover el artefacto si no es legitimo.",
                        ["T1547.001 - Boot or Logon Autostart"],
                    )
                )
        return findings

    # Services
    def analyze_services(self, results):
        findings = []
        services = results.get("services", []) or []
        if not isinstance(services, list):
            return findings

        suspicious_paths = ("\\appdata\\", "\\temp\\", "\\public\\")
        trusted_prefixes = (
            "c:\\windows\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
            "c:\\programdata\\microsoft\\windows defender\\platform\\",
        )
        trusted_service_names = {"windefend", "wdnissvc", "mdcoresvc"}

        seen_unquoted = set()
        for svc in services:
            if not isinstance(svc, dict):
                continue

            name = svc.get("name", "Unknown")
            raw_path = (svc.get("path") or "").strip()
            if not raw_path:
                continue
            if name.lower() in trusted_service_names:
                continue

            # Parse executable path with or without quotes.
            exe_path = ""
            if raw_path.startswith('"'):
                parts = raw_path.split('"')
                exe_path = parts[1] if len(parts) > 1 else raw_path
                is_quoted = True
            else:
                m = re.match(r"^(.+?\.exe)\b", raw_path, re.IGNORECASE)
                exe_path = m.group(1) if m else raw_path.split(" ")[0]
                is_quoted = False

            exe_low = exe_path.lower()

            has_space = " " in exe_path
            trusted_path = exe_low.startswith(trusted_prefixes)
            if has_space and not is_quoted and not trusted_path:
                key = (name.lower(), exe_low)
                if key not in seen_unquoted:
                    seen_unquoted.add(key)
                    findings.append(
                        self.build(
                            "medium",
                            f"Ruta de servicio sin comillas: {name}",
                            raw_path,
                            "Encerrar la ruta del ejecutable entre comillas.",
                            ["T1574.009 - Path Interception by Unquoted Path"],
                        )
                    )

            if any(p in exe_low for p in suspicious_paths):
                findings.append(
                    self.build(
                        "high",
                        f"Servicio desde ruta sospechosa: {name}",
                        raw_path,
                        "Validar legitimidad y origen del servicio.",
                        ["T1543 - Create or Modify System Process"],
                    )
                )

        return findings

    # Master
    # UAC
    def analyze_uac(self, results):
        findings = []
        uac = results.get("uac", {}) or {}
        if not uac:
            return findings

        enable_lua          = int(uac.get("EnableLUA", 1))
        consent_admin       = int(uac.get("ConsentPromptBehaviorAdmin", 5))
        consent_user        = int(uac.get("ConsentPromptBehaviorUser", 3))
        secure_desktop      = int(uac.get("PromptOnSecureDesktop", 1))

        # ConsentPromptBehaviorAdmin values:
        # 0 = Elevar sin solicitud        → CRITICAL
        # 1 = Pedir credenciales (escritorio seguro) → SECURE
        # 2 = Pedir consentimiento (escritorio seguro) → MEDIUM
        # 3 = Pedir credenciales          → SECURE
        # 4 = Pedir consentimiento        → MEDIUM
        # 5 = Pedir consentimiento solo apps no-Windows → MEDIUM (default)

        if enable_lua == 0:
            findings.append(self.build(
                "critical",
                "UAC deshabilitado: escalada de privilegios sin restriccion (EnableLUA=0)",
                "El Control de Cuentas de Usuario esta completamente desactivado. Cualquier proceso "
                "en ejecucion puede adquirir privilegios de SYSTEM sin ninguna interaccion del usuario, "
                "eliminando la barrera de separacion entre sesiones de usuario y administrador.",
                "Habilitar UAC via GPO o registro: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
                "\\Policies\\System -> EnableLUA = 1. Requiere reinicio.",
                ["T1548.002 - Bypass User Account Control"],
            ))
            return findings  # sin UAC el resto no aplica

        if consent_admin == 0:
            findings.append(self.build(
                "high",
                "UAC: elevacion automatica sin confirmacion para administradores (ConsentPromptBehaviorAdmin=0)",
                "Los procesos ejecutados por cuentas administrativas obtienen tokens elevados de forma "
                "silenciosa. Un malware con contexto de administrador escala a SYSTEM sin friction.",
                "Establecer ConsentPromptBehaviorAdmin=1 (solicitar credenciales en escritorio seguro) "
                "o al menos =2 (solicitar consentimiento). Valor 0 solo es aceptable en entornos kiosko.",
                ["T1548.002 - Bypass User Account Control"],
            ))
        elif consent_admin in (2, 4, 5):
            findings.append(self.build(
                "medium",
                f"UAC: prompt de confirmacion sin credenciales para administradores (ConsentPromptBehaviorAdmin={consent_admin})",
                f"ConsentPromptBehaviorAdmin={consent_admin}: el administrador aprueba la elevacion "
                "con un clic en 'Si', sin necesidad de introducir contrasena. Esto no verifica la "
                "identidad del usuario y es vulnerable a ataques de clickjacking si el escritorio seguro esta desactivado.",
                "Configurar ConsentPromptBehaviorAdmin=1 para exigir autenticacion completa en cada elevacion.",
                ["T1548.002 - Bypass User Account Control"],
            ))
        # consent_admin in (1, 3) → pide credenciales → configuracion segura, no se reporta

        if consent_user == 0:
            findings.append(self.build(
                "high",
                "UAC: usuarios estandar pueden elevar privilegios sin credenciales (ConsentPromptBehaviorUser=0)",
                "ConsentPromptBehaviorUser=0: las cuentas sin privilegios administrativos obtienen "
                "elevacion sin presentar credenciales de administrador, anulando el modelo de minimo privilegio.",
                "Establecer ConsentPromptBehaviorUser=3 para requerir credenciales de administrador "
                "en cada solicitud de elevacion desde cuentas estandar.",
                ["T1548.002 - Bypass User Account Control"],
            ))

        if secure_desktop == 0:
            findings.append(self.build(
                "medium",
                "UAC: prompt de elevacion expuesto fuera del escritorio seguro (PromptOnSecureDesktop=0)",
                "El dialogo UAC se muestra en el escritorio interactivo del usuario en lugar del "
                "escritorio seguro aislado. Esto permite ataques de UI spoofing donde un proceso "
                "malicioso simula el prompt para capturar la aprobacion del usuario.",
                "Habilitar PromptOnSecureDesktop=1 en HKLM\\SOFTWARE\\Microsoft\\Windows\\"
                "CurrentVersion\\Policies\\System para aislar el dialogo UAC del resto de procesos.",
                ["T1548.002 - Bypass User Account Control"],
            ))

        return findings

    # Event Logs
    def analyze_event_logs(self, results):
        findings = []
        ev = results.get("event_logs", {}) or {}
        if not ev:
            return findings

        failed_24h  = int(ev.get("failed_logins_24h",    0) or 0)
        failed_1h   = int(ev.get("failed_logins_1h",     0) or 0)
        lockouts    = int(ev.get("lockouts_24h",          0) or 0)
        created     = int(ev.get("users_created_24h",     0) or 0)
        priv        = int(ev.get("priv_logons_24h",       0) or 0)
        offhours    = int(ev.get("offhours_logons_24h",   0) or 0)
        remote      = int(ev.get("remote_logons_24h",     0) or 0)
        targets     = ev.get("unique_failed_accounts",    []) or []
        log_enabled  = ev.get("security_log_enabled")   # None=error, True/False=real
        read_error   = bool(ev.get("security_log_read_error", True))
        log_mb       = int(ev.get("security_log_max_mb",   0) or 0)
        svc_running  = ev.get("eventlog_svc_running", True)
        auditpol_ok      = ev.get("auditpol_ok", True)
        auditpol_unknown = ev.get("auditpol_unknown", False)

        # Estado del registro — solo CRITICAL si hay evidencia real de que está deshabilitado
        if svc_running is False:
            findings.append(self.build("critical",
                "Servicio Windows Event Log detenido",
                "El servicio EventLog no está en ejecución — ningún evento del sistema se registra.",
                "Iniciar el servicio: Start-Service EventLog y configurar inicio automático.",
                ["T1562.002 - Disable Windows Event Logging"]))
        elif log_enabled is False and not read_error:
            findings.append(self.build("critical",
                "Registro de seguridad de Windows deshabilitado",
                "El canal Security Event Log está desactivado — sin auditoría de eventos de autenticación.",
                "auditpol /set /category:* /success:enable /failure:enable",
                ["T1562.002 - Disable Windows Event Logging"]))
        elif auditpol_unknown:
            findings.append(self.build("review",
                "Auditoría (auditpol): no se pudo verificar el estado",
                "No se pudo leer la configuración de auditpol para Logon/Logoff/Special Logon.",
                "Verificar manualmente: auditpol /get /category:* como Administrador.",
                ["T1562.002 - Disable Windows Event Logging"]))
        elif not auditpol_ok:
            findings.append(self.build("high",
                "Auditoría de eventos de seguridad deshabilitada (auditpol)",
                "Las subcategorías Logon, Logoff y Special Logon no registran eventos de autenticación.",
                "Ejecutar: auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
                ["T1562.002 - Disable Windows Event Logging"]))
        elif read_error:
            findings.append(self.build("review",
                "Registro de seguridad: no se pudo verificar el estado",
                "No se pudo leer la configuración del Security Event Log (posible falta de permisos).",
                "Verificar con: Get-WinEvent -ListLog Security y auditpol /get /category:* como Admin.",
                ["T1562.002 - Disable Windows Event Logging"]))
        elif log_mb > 0 and log_mb < 20:
            findings.append(self.build("medium",
                f"Registro de seguridad muy pequeño ({log_mb} MB)",
                "El tamaño máximo del log es insuficiente y se sobreescribe rápidamente, perdiendo evidencia forense.",
                "Aumentar el tamaño del Security Log a 128 MB o más en el Visor de Eventos.",
                ["T1562.002 - Disable Windows Event Logging"]))

        # Brute force — ventana corta (1h) es indicador más preciso de ataque activo
        if failed_1h > 20:
            findings.append(self.build("critical",
                f"Ataque de fuerza bruta activo: {failed_1h} fallos en la ultima hora (4625)",
                f"{failed_1h} intentos fallidos de autenticacion en 60 minutos.",
                "Bloquear IP origen, aplicar lockout policy inmediatamente.",
                ["T1110.001 - Password Guessing", "T1110 - Brute Force"]))
        elif failed_24h > 100:
            findings.append(self.build("critical",
                f"Posible fuerza bruta: {failed_24h} fallos en 24h (4625)",
                f"{failed_24h} intentos fallidos acumulados.",
                "Revisar origenes e implementar lockout threshold.",
                ["T1110 - Brute Force"]))
        elif failed_24h > 20:
            findings.append(self.build("high",
                f"{failed_24h} intentos fallidos de login en 24h (4625)",
                "Actividad de autenticacion elevada.",
                "Investigar origenes.",
                ["T1110 - Brute Force"]))

        # Password spray (muchas cuentas distintas atacadas)
        if len(targets) > 5 and failed_24h > 10:
            preview = ", ".join(targets[:8]) + ("..." if len(targets) > 8 else "")
            findings.append(self.build("high",
                f"Posible password spray: {len(targets)} cuentas distintas atacadas (4625)",
                f"Cuentas objetivo detectadas: {preview}",
                "Revisar IP origen comun; considerar bloqueo a nivel de red.",
                ["T1110.003 - Password Spraying"]))

        # Bloqueos de cuenta
        if lockouts > 5:
            findings.append(self.build("high",
                f"{lockouts} bloqueos de cuenta en 24h (4740)",
                "Multiples cuentas bloqueadas, posible ataque activo.",
                "Revisar origen con Event ID 4740.",
                ["T1110 - Brute Force"]))

        # Creacion de usuario
        if created > 0:
            findings.append(self.build("critical",
                f"Cuenta de usuario creada en las ultimas 24h (4720) x{created}",
                f"{created} cuenta(s) nueva(s) detectada(s).",
                "Verificar si la creacion fue autorizada.",
                ["T1136.001 - Create Account: Local Account"]))

        # Privilegios especiales (4672) — excluye SYSTEM
        if priv > 50:
            findings.append(self.build("high",
                f"Asignacion masiva de privilegios: {priv} eventos (4672)",
                f"{priv} asignaciones de privilegios especiales en 24h (sin cuentas de sistema).",
                "Revisar Event ID 4672 para identificar cuentas no autorizadas.",
                ["T1134 - Access Token Manipulation", "T1078 - Valid Accounts"]))
        elif priv > 10:
            findings.append(self.build("medium",
                f"{priv} asignaciones de privilegios especiales en 24h (4672)",
                "Actividad de privilegios por encima de lo normal.",
                "Auditar Event ID 4672 en el Visor de eventos.",
                ["T1078 - Valid Accounts"]))

        # Logins fuera de horario
        if offhours > 10:
            findings.append(self.build("high",
                f"{offhours} inicios de sesion fuera de horario en 24h (4624)",
                "Logins detectados entre 23:00 y 07:00 horas.",
                "Revisar Event ID 4624 para identificar origen y cuenta.",
                ["T1078 - Valid Accounts"]))

        # Sesiones remotas (RDP/RemoteInteractive)
        if remote > 20:
            findings.append(self.build("medium",
                f"{remote} sesiones remotas interactivas en 24h (4624 tipo 10)",
                "Volumen elevado de conexiones RemoteInteractive (RDP).",
                "Verificar si todas las sesiones son legitimas.",
                ["T1021.001 - Remote Desktop Protocol"]))

        return findings

    # Auto-Login
    def analyze_autologin(self, results):
        findings = []
        al = results.get("autologin", {}) or {}
        if not al:
            return findings
        if str(al.get("AutoAdminLogon", "0")).strip() == "1":
            has_pw = bool((al.get("DefaultPassword") or "").strip())
            findings.append(self.build(
                "critical" if not has_pw else "high",
                "Auto-login habilitado en el sistema",
                f"AutoAdminLogon=1, usuario: {al.get('DefaultUserName','desconocido')}, "
                f"contrasena: {'almacenada en texto plano' if has_pw else 'no configurada'}.",
                "Deshabilitar AutoAdminLogon o proteger con BitLocker+PIN.",
                ["T1552.002 - Credentials in Registry"]))
        return findings

    # BitLocker
    def analyze_bitlocker(self, results):
        findings = []
        volumes = results.get("bitlocker", []) or []
        if not volumes:
            findings.append(self.build("review",
                "BitLocker: no se pudo leer el estado de cifrado",
                "No se pudo obtener informacion de BitLocker (permisos insuficientes o modulo no disponible).",
                "Verificar manualmente con: Get-BitLockerVolume en PowerShell como Admin.",
                ["T1025 - Data from Removable Media"]))
            return findings

        for vol in volumes:
            mount      = vol.get("mount", "?")
            status     = (vol.get("status")     or "").strip()
            vol_status = (vol.get("vol_status") or "").strip()
            pct        = int(vol.get("pct", 0) or 0)
            protectors = (vol.get("protectors") or "").strip()

            # El cifrado real se determina por VolumeStatus + porcentaje, no solo ProtectionStatus
            fully_enc    = vol_status == "FullyEncrypted" or pct >= 100
            fully_dec    = vol_status == "FullyDecrypted" or pct == 0
            prot_info    = f"Protectores: {protectors}." if protectors else ""

            if fully_enc:
                # Cifrado completo → seguro independientemente de ProtectionStatus
                continue

            if fully_dec:
                findings.append(self.build("high",
                    f"BitLocker desactivado en {mount}",
                    f"La unidad {mount} no tiene cifrado activo (VolumeStatus={vol_status}, {pct}%). {prot_info}",
                    f"Activar BitLocker: Enable-BitLocker -MountPoint '{mount}' "
                    "-EncryptionMethod XtsAes256 -TpmProtector",
                    ["T1025 - Data from Removable Media"]))
            elif 0 < pct < 100:
                findings.append(self.build("medium",
                    f"BitLocker en progreso en {mount}: {pct}% cifrado",
                    f"La unidad {mount} está cifrándose (VolumeStatus={vol_status}). {prot_info}",
                    "Esperar a que el cifrado complete o verificar que no esté pausado.",
                    ["T1025 - Data from Removable Media"]))
            else:
                findings.append(self.build("review",
                    f"BitLocker en {mount}: estado indeterminado",
                    f"VolumeStatus={vol_status}, ProtectionStatus={status}, {pct}% cifrado. {prot_info}",
                    "Verificar manualmente: Get-BitLockerVolume como Admin.",
                    ["T1025 - Data from Removable Media"]))

        return findings

    # Correlación y alertas comportamentales
    def detect_behavioral_alerts(self, results):
        alerts = []
        ev     = results.get("event_logs",      {}) or {}
        rdp    = results.get("rdp_config",      {}) or {}
        policy = results.get("password_policy", {}) or {}
        dv     = results.get("defender",        {}) or {}
        ps     = results.get("powershell_logs", {}) or {}
        al     = results.get("autologin",       {}) or {}
        bl     = results.get("bitlocker",       []) or []
        upd    = results.get("windows_update",  {}) or {}
        users  = results.get("users",           {}) or {}

        failed      = int(ev.get("failed_logins_1h",  0) or ev.get("failed_logins_24h", 0) or 0)
        created     = int(ev.get("users_created_24h", 0) or 0)
        lockout_thr = int(policy.get("lockout_threshold", 0) or 0)
        min_len     = int(policy.get("min_length", 8) or 8)
        admins      = users.get("admins", []) or []
        no_pw       = len(users.get("users_without_password", []) or [])
        pending     = int(upd.get("pending_count", 0) or 0)
        _log_enabled  = ev.get("security_log_enabled")
        _log_err      = bool(ev.get("security_log_read_error", True))
        _svc_running  = ev.get("eventlog_svc_running", True)
        log_ok        = (_log_enabled is True) or (_log_err and _svc_running is not False)
        ps_enabled    = bool(ps.get("Enabled", True))
        ps_read_err   = bool(ps.get("ReadError", False))
        auto_on     = str(al.get("AutoAdminLogon", "0")).strip() == "1"
        bl_off      = any((v.get("status") or "").strip() in ("0", "Off", "ProtectionOff") for v in bl)
        svc_on      = bool(dv.get("service_enabled", True))
        rt_on       = bool(dv.get("realtime_enabled", True))
        rdp_on      = bool(rdp.get("RDPEnabled", False))
        nla_off     = not bool(rdp.get("NLARequired", True))
        ntlm_lvl    = int(rdp.get("NTLMLevel", 3) or 3)
        wdigest     = bool(rdp.get("WDigest", False))

        if failed > 50 and lockout_thr == 0:
            alerts.append(self.build("critical",
                f"[CORRELACION] Fuerza bruta sin bloqueo de cuenta ({failed} fallos/h)",
                "Fallos masivos de autenticacion sin ningun mecanismo de defensa activo.",
                "Implementar lockout threshold inmediatamente.",
                ["T1110 - Brute Force"]))

        if not log_ok and not ps_enabled and not ps_read_err:
            alerts.append(self.build("critical",
                "[CORRELACION] Auditoria ciega: Security Log + PowerShell Log deshabilitados",
                "Sin logs de seguridad ni PowerShell, cualquier ataque queda sin evidencia forense.",
                "Habilitar Security Log (auditpol) y Script Block Logging via GPO.",
                ["T1562.002 - Disable Windows Event Logging", "T1059.001 - PowerShell"]))

        if (min_len < 8 or lockout_thr == 0) and no_pw > 0:
            alerts.append(self.build("critical",
                f"[CORRELACION] Politica debil + {no_pw} usuario(s) sin contraseña",
                f"Longitud minima: {min_len}, lockout: {lockout_thr}. Acceso sin credenciales posible.",
                "Reforzar politica de contraseñas y asignar contraseñas a todos los usuarios.",
                ["T1110 - Brute Force", "T1078 - Valid Accounts"]))

        if wdigest and rdp_on:
            alerts.append(self.build("critical",
                "[CORRELACION] WDigest activo + RDP expuesto — volcado remoto de credenciales",
                "Credenciales en texto plano en LSASS accesibles via sesion RDP.",
                "Deshabilitar WDigest (UseLogonCredential=0) y habilitar NLA en RDP.",
                ["T1003.001 - LSASS Memory", "T1021.001 - Remote Desktop Protocol"]))

        if auto_on and bl_off:
            alerts.append(self.build("critical",
                "[CORRELACION] Auto-login habilitado + disco sin cifrar",
                "Acceso fisico permite login automatico y lectura directa de datos del disco.",
                "Deshabilitar auto-login y activar BitLocker.",
                ["T1552.002 - Credentials in Registry", "T1025 - Data from Removable Media"]))

        if (not svc_on or not rt_on) and pending > 10:
            alerts.append(self.build("critical",
                f"[CORRELACION] Defender desactivado + {pending} actualizaciones pendientes",
                "Sistema sin antimalware y con vulnerabilidades conocidas sin parchear.",
                "Activar Defender y aplicar parches de seguridad inmediatamente.",
                ["T1562.001 - Disable or Modify Tools", "T1190 - Exploit Public-Facing Application"]))

        if rdp_on and nla_off and ntlm_lvl < 3:
            alerts.append(self.build("critical",
                f"[CORRELACION] RDP sin NLA + NTLM nivel {ntlm_lvl} — captura de hashes posible",
                "Atacante puede conectar sin NLA y capturar/degradar hashes NTLM.",
                "Habilitar NLA y configurar LmCompatibilityLevel=5.",
                ["T1021.001 - Remote Desktop Protocol", "T1550.002 - Pass the Hash"]))

        if created > 0 and len(admins) > 3:
            alerts.append(self.build("critical",
                f"[CORRELACION] Cuenta nueva + {len(admins)} administradores activos",
                f"{created} cuenta(s) creada(s) con grupo Admins sobredimensionado.",
                "Auditar cuentas de administrador y validar la nueva cuenta.",
                ["T1136.001 - Create Account", "T1078.003 - Local Accounts"]))

        return alerts

    # RDP / NTLM
    def analyze_rdp(self, results):
        findings = []
        rdp = results.get("rdp_config", {}) or {}
        if not rdp:
            return findings

        rdp_enabled  = bool(rdp.get("RDPEnabled", False))
        nla          = bool(rdp.get("NLARequired", True))
        ntlm_level   = int(rdp.get("NTLMLevel", 3) or 3)
        wdigest      = bool(rdp.get("WDigest", False))
        cred_guard   = bool(rdp.get("CredentialGuard", False))

        if rdp_enabled and not nla:
            findings.append(self.build(
                "high",
                "RDP habilitado sin autenticacion a nivel de red (NLA)",
                "UserAuthenticationRequired=0. Sin NLA el servidor RDP es vulnerable a exploits pre-autenticacion.",
                "Habilitar NLA en Propiedades del sistema > Conexiones remotas.",
                ["T1021.001 - Remote Desktop Protocol"],
            ))

        if ntlm_level < 3:
            sev = "critical" if ntlm_level <= 1 else "high"
            findings.append(self.build(
                sev,
                f"Nivel de autenticacion NTLM inseguro (LmCompatibilityLevel={ntlm_level})",
                f"Nivel {ntlm_level} permite LM/NTLMv1, vulnerable a ataques pass-the-hash y captura de hashes.",
                "Configurar LmCompatibilityLevel=5 en gpedit.msc > Opciones de seguridad.",
                ["T1550.002 - Pass the Hash", "T1557 - Adversary-in-the-Middle"],
            ))

        if wdigest:
            findings.append(self.build(
                "critical",
                "WDigest habilitado: credenciales almacenadas en texto plano en memoria",
                "UseLogonCredential=1. Mimikatz puede volcar contrasenas directamente desde LSASS.",
                "Deshabilitar: HKLM\\...\\WDigest -> UseLogonCredential = 0",
                ["T1003.001 - LSASS Memory"],
            ))

        if not cred_guard:
            findings.append(self.build(
                "medium",
                "Credential Guard no habilitado",
                "Sin Credential Guard, los hashes NTLM/Kerberos son vulnerables a volcado de credenciales.",
                "Habilitar Credential Guard en gpedit.msc (requiere TPM 2.0 + Secure Boot).",
                ["T1003 - OS Credential Dumping"],
            ))

        return findings

    # Suspicious Processes
    def analyze_suspicious_processes(self, results):
        findings = []
        procs = results.get("suspicious_processes", []) or []
        if not procs:
            return findings

        for proc in procs:
            path  = (proc.get("path") or "").lower()
            name  = proc.get("name", "Unknown")
            pid   = proc.get("pid", "?")

            if "\\appdata\\local\\temp\\" in path:
                sev, label = "high", "AppData\\Local\\Temp"
            elif "\\appdata\\roaming\\" in path:
                sev, label = "high", "AppData\\Roaming"
            elif "\\downloads\\" in path:
                sev, label = "medium", "Downloads"
            elif "\\desktop\\" in path:
                sev, label = "medium", "Desktop"
            else:
                sev, label = "medium", "ruta sospechosa"

            findings.append(self.build(
                sev,
                f"Proceso ejecutandose desde {label}: {name}",
                f"PID {pid} - {proc.get('path', '')}",
                "Verificar el origen y legitimidad del ejecutable.",
                ["T1059 - Command and Scripting Interpreter", "T1204 - User Execution"],
            ))

        return findings

    # PowerShell Logs
    def analyze_powershell_logs(self, results):
        findings = []
        ps = results.get("powershell_logs", {}) or {}
        if not ps:
            return findings

        if not ps.get("Enabled", True):
            if ps.get("ReadError", False):
                findings.append(self.build("review",
                    "PowerShell Script Block Logging: sin acceso al log",
                    "No se pudo leer Microsoft-Windows-PowerShell/Operational (permisos o log no configurado).",
                    "Ejecutar como Admin y habilitar Script Block Logging via GPO si no esta activo.",
                    ["T1059.001 - PowerShell"]))
            else:
                findings.append(self.build("medium",
                    "PowerShell Script Block Logging deshabilitado",
                    "No se pudieron leer logs de Microsoft-Windows-PowerShell/Operational.",
                    "Habilitar Script Block Logging via GPO: Administrative Templates > Windows PowerShell.",
                    ["T1059.001 - PowerShell"]))
            return findings

        count   = int(ps.get("Count", 0) or 0)
        samples = ps.get("Samples", []) or []

        if count > 0:
            sev     = "critical" if count > 20 else "high"
            preview = " | ".join(
                (s.get("Snippet") or "")[:120] for s in samples[:3] if s.get("Snippet")
            )
            findings.append(self.build(sev,
                f"Comandos PowerShell sospechosos detectados: {count} evento(s) (ID 4104)",
                f"Patrones: IEX, DownloadString, Base64, WebClient, etc. Muestra: {preview}",
                "Revisar Event ID 4104 en Microsoft-Windows-PowerShell/Operational e investigar el origen.",
                ["T1059.001 - PowerShell",
                 "T1027 - Obfuscated Files or Information",
                 "T1105 - Ingress Tool Transfer"]))

        return findings

    # Windows Defender
    def analyze_defender(self, results):
        findings = []
        dv = results.get("defender", {}) or {}
        if not dv:
            return findings

        svc_on  = bool(dv.get("service_enabled",  False))
        rt_on   = bool(dv.get("realtime_enabled",  False))
        sig_age = int(dv.get("signature_age_days", 0) or 0)
        susp    = dv.get("suspicious_exclusion_paths", []) or []
        all_p   = dv.get("exclusion_paths",        []) or []
        all_pr  = dv.get("exclusion_processes",    []) or []

        if not svc_on:
            findings.append(self.build("critical",
                "Windows Defender completamente deshabilitado",
                "AMServiceEnabled=False. Sin proteccion antimalware activa.",
                "Habilitar Defender o instalar un AV alternativo.",
                ["T1562.001 - Disable or Modify Tools"]))
            return findings

        if not rt_on:
            findings.append(self.build("critical",
                "Proteccion en tiempo real de Defender deshabilitada",
                "RealTimeProtectionEnabled=False. No se detectan amenazas en tiempo real.",
                "Habilitar proteccion en tiempo real en Seguridad de Windows.",
                ["T1562.001 - Disable or Modify Tools"]))

        if sig_age > 30:
            findings.append(self.build("high",
                f"Firmas de Defender muy desactualizadas ({sig_age} dias)",
                f"Definiciones de malware con {sig_age} dias de antiguedad.",
                "Ejecutar: Update-MpSignature o actualizar via Windows Update.",
                ["T1562.001 - Disable or Modify Tools"]))
        elif sig_age > 7:
            findings.append(self.build("medium",
                f"Firmas de Defender desactualizadas ({sig_age} dias)",
                f"Definiciones con {sig_age} dias sin actualizar.",
                "Actualizar las definiciones de Defender.",
                ["T1562.001 - Disable or Modify Tools"]))

        if susp:
            findings.append(self.build("high",
                f"Exclusiones sospechosas en Defender: {len(susp)} ruta(s)",
                f"Rutas de riesgo excluidas del escaneo: {', '.join(susp[:5])}",
                "Eliminar exclusiones innecesarias de Defender.",
                ["T1562.001 - Disable or Modify Tools", "T1036 - Masquerading"]))
        elif all_p or all_pr:
            findings.append(self.build("medium",
                f"Defender tiene {len(all_p)} ruta(s) y {len(all_pr)} proceso(s) excluidos",
                "Exclusiones activas que pueden ocultar amenazas.",
                "Auditar las exclusiones en Get-MpPreference.",
                ["T1562.001 - Disable or Modify Tools"]))

        return findings

    def analyze(self, results):
        import math
        findings = []
        findings += self.analyze_ports(results)
        findings += self.analyze_firewall(results)
        findings += self.analyze_users(results)
        findings += self.analyze_password_policy(results)
        findings += self.analyze_smb(results)
        findings += self.analyze_processes(results)
        findings += self.analyze_signatures(results)
        findings += self.analyze_updates(results)
        findings += self.analyze_persistence(results)
        findings += self.analyze_services(results)
        findings += self.analyze_uac(results)
        findings += self.analyze_event_logs(results)
        findings += self.analyze_rdp(results)
        findings += self.analyze_suspicious_processes(results)
        findings += self.analyze_autologin(results)
        findings += self.analyze_bitlocker(results)
        findings += self.analyze_powershell_logs(results)
        findings += self.analyze_defender(results)
        findings += self.detect_behavioral_alerts(results)

        # Sort: critical first
        _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "review": 4, "info": 5}
        findings.sort(key=lambda f: _order.get(f.get("severity", "info"), 5))

        # Dynamic scoring — logarithmic, based on real impact weight
        _w = {"critical": 20, "high": 10, "medium": 3, "low": 1, "review": 0}
        raw = sum(_w.get(f.get("severity", "info"), 0) for f in findings)
        score = min(100, int(100 * (1 - math.exp(-raw / 60)))) if raw > 0 else 0

        return findings, score