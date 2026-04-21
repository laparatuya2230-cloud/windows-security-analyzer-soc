import re

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
        return {
            "severity": severity.lower(),
            "title": title,
            "details": details,
            "recommendation": recommendation,
            "mitre": mitre or [],
        }

    def _extract_port_from_netstat_line(self, line):
        # Example: TCP 0.0.0.0:445 0.0.0.0:0 LISTENING 4
        match = re.search(r":(\d+)\s+\S+\s+LISTENING\b", line, re.IGNORECASE)
        return match.group(1) if match else None

    # Ports
    def analyze_ports(self, results):
        findings = []
        firewall = results.get("firewall", {})
        if isinstance(firewall, dict):
            blocked_ports = firewall.get("blocked_ports", set()) or set()
        else:
            blocked_ports = firewall or set()

        ports = results.get("network", {}).get("listening_ports", []) or []

        high_risk_ports = {
            "21": "FTP",
            "23": "Telnet",
            "445": "SMB",
            "3389": "RDP",
            "139": "NetBIOS",
            "135": "RPC",
            "5900": "VNC",
        }
        safe_system_ports = {"135"}
        seen_ports = set()

        for line in ports:
            if "LISTENING" not in line.upper():
                continue

            port = self._extract_port_from_netstat_line(line)
            if not port or port not in high_risk_ports or port in seen_ports:
                continue
            seen_ports.add(port)

            name = high_risk_ports[port]
            mitre = MITRE_MAP.get(name, ["T1046 - Network Service Discovery"])
            exposed_to_all = (
                f"0.0.0.0:{port}" in line
                or f"[::]:{port}" in line
                or f"*:{port}" in line
            )
            is_protected = port in blocked_ports or "Any" in blocked_ports

            if name in ("FTP", "Telnet"):
                findings.append(
                    self.build(
                        "critical",
                        f"Protocolo inseguro activo: {name} (puerto {port})",
                        line,
                        f"Deshabilitar {name} y usar alternativas seguras como SSH/SFTP.",
                        ["T1021 - Remote Services"],
                    )
                )
                continue

            if port in safe_system_ports:
                findings.append(
                    self.build(
                        "medium",
                        f"Puerto del sistema expuesto: {name} ({port})",
                        line,
                        "Restringir acceso remoto solo a redes y hosts autorizados.",
                        mitre,
                    )
                )
                continue

            if name == "SMB" and exposed_to_all and not is_protected:
                severity = "critical"
            elif name == "RDP" and exposed_to_all and not is_protected:
                severity = "high"
            elif exposed_to_all and not is_protected:
                severity = "high"
            else:
                severity = "medium"

            findings.append(
                self.build(
                    severity,
                    f"Puerto sensible en escucha: {name} ({port})",
                    line,
                    "Confirmar necesidad del servicio y limitar la exposicion.",
                    mitre,
                )
            )

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

        min_length = int(policy.get("min_length", 0) or 0)
        max_age = int(policy.get("max_age", 0) or 0)
        lockout_threshold = int(policy.get("lockout_threshold", 0) or 0)
        history = int(policy.get("history", 0) or 0)

        if min_length < 8:
            findings.append(
                self.build(
                    "high",
                    f"Politica de contrasena debil: longitud minima {min_length}",
                    f"Se detecto una longitud minima de {min_length}.",
                    "Configurar longitud minima de 8 a 12 caracteres.",
                    ["T1110 - Brute Force"],
                )
            )

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
                    "Sesiones nulas SMB no restringidas",
                    "RestrictNullSessAccess = False",
                    "Restringir sesiones nulas SMB.",
                    ["T1135 - Network Share Discovery"],
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
                "UAC completamente deshabilitado (EnableLUA=0)",
                "El Control de Cuentas de Usuario esta desactivado. Cualquier proceso puede "
                "obtener privilegios de administrador sin ningun aviso.",
                "Habilitar UAC: HKLM\\...\\Policies\\System -> EnableLUA = 1",
                ["T1548.002 - Bypass User Account Control"],
            ))
            return findings  # sin UAC el resto no aplica

        if consent_admin == 0:
            findings.append(self.build(
                "high",
                "UAC: elevacion silenciosa sin solicitud de credenciales (Admin)",
                "ConsentPromptBehaviorAdmin=0. Los administradores obtienen privilegios "
                "elevados sin ningun prompt, facilitando escalada de privilegios.",
                "Configurar ConsentPromptBehaviorAdmin a 1 (pedir credenciales) o 2 (pedir consentimiento).",
                ["T1548.002 - Bypass User Account Control"],
            ))
        elif consent_admin in (2, 4, 5):
            findings.append(self.build(
                "medium",
                "UAC: solo solicita confirmacion, no credenciales (Admin)",
                f"ConsentPromptBehaviorAdmin={consent_admin}. El administrador solo hace "
                "clic en 'Si' sin introducir contrasena, lo que reduce la proteccion.",
                "Configurar ConsentPromptBehaviorAdmin=1 para exigir credenciales completas.",
                ["T1548.002 - Bypass User Account Control"],
            ))
        # consent_admin in (1, 3) → pide credenciales → configuracion segura, no se reporta

        if consent_user == 0:
            findings.append(self.build(
                "high",
                "UAC: usuarios estandar elevan sin solicitud (ConsentPromptBehaviorUser=0)",
                "Los usuarios no-administradores pueden elevar privilegios sin credenciales.",
                "Configurar ConsentPromptBehaviorUser=3 (solicitar credenciales de administrador).",
                ["T1548.002 - Bypass User Account Control"],
            ))

        if secure_desktop == 0:
            findings.append(self.build(
                "medium",
                "UAC: escritorio seguro deshabilitado (PromptOnSecureDesktop=0)",
                "El prompt de UAC no usa escritorio seguro, vulnerable a ataques de UI spoofing.",
                "Habilitar PromptOnSecureDesktop=1 para mostrar el dialogo UAC en escritorio aislado.",
                ["T1548.002 - Bypass User Account Control"],
            ))

        return findings

    # Event Logs
    def analyze_event_logs(self, results):
        findings = []
        ev = results.get("event_logs", {}) or {}
        if not ev:
            return findings

        failed   = int(ev.get("failed_logins_24h", 0) or 0)
        lockouts = int(ev.get("lockouts_24h", 0) or 0)
        log_ok   = bool(ev.get("security_log_enabled", True))
        log_mb   = int(ev.get("security_log_max_mb", 0) or 0)

        if not log_ok:
            findings.append(self.build(
                "critical",
                "Registro de seguridad de Windows deshabilitado",
                "El Security Event Log no esta activo — no hay auditoria de eventos.",
                "Habilitar el registro via gpedit.msc o: auditpol /set /category:* /success:enable /failure:enable",
                ["T1562.002 - Disable Windows Event Logging"],
            ))
        elif log_mb < 20:
            findings.append(self.build(
                "medium",
                f"Registro de seguridad con tamanio minimo ({log_mb} MB)",
                "Un log pequeno se sobreescribe rapido, perdiendo evidencia de incidentes.",
                "Aumentar el tamanio maximo del Security Log a 128 MB o mas.",
                ["T1562.002 - Disable Windows Event Logging"],
            ))

        if failed > 100:
            findings.append(self.build(
                "critical",
                f"Posible ataque de fuerza bruta: {failed} fallos de login en 24h (ID 4625)",
                f"Se detectaron {failed} intentos fallidos de autenticacion en las ultimas 24 horas.",
                "Revisar origenes, aplicar bloqueo de cuenta y alertas de seguridad.",
                ["T1110.001 - Password Guessing", "T1110 - Brute Force"],
            ))
        elif failed > 20:
            findings.append(self.build(
                "high",
                f"{failed} intentos de inicio de sesion fallidos en 24h (ID 4625)",
                f"Se detectaron {failed} fallos de autenticacion en las ultimas 24 horas.",
                "Investigar origenes e implementar politica de bloqueo de cuenta.",
                ["T1110 - Brute Force"],
            ))

        if lockouts > 5:
            findings.append(self.build(
                "high",
                f"{lockouts} bloqueos de cuenta detectados en 24h (ID 4740)",
                "Multiples bloqueos de cuenta, posible ataque de fuerza bruta en curso.",
                "Revisar el origen de los bloqueos con el Event ID 4740 en el Visor de eventos.",
                ["T1110 - Brute Force"],
            ))

        return findings

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

    def analyze(self, results):
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

        weights = {
            "critical": 30,
            "high": 20,
            "medium": 10,
            "low": 4,
            "review": 2,
            "info": 1,
        }
        max_per_finding = 30
        raw_score = sum(weights.get(f.get("severity", "info"), 1) for f in findings)
        score = 0 if not findings else min(int((raw_score / (len(findings) * max_per_finding)) * 100), 100)

        return findings, score