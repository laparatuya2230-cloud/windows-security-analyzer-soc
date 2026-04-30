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

    def build(self, severity, title, details, recommendation, mitre=None,
              explanation="", impact=""):
        norm  = re.sub(r'\b\d+\b', '#', title.lower().strip())
        fid   = hashlib.md5(f"{severity.lower()}:{norm}".encode()).hexdigest()[:12]
        return {
            "id":             fid,
            "severity":       severity.lower(),
            "title":          title,
            "details":        details,
            "recommendation": recommendation,
            "mitre":          mitre or [],
            "explanation":    explanation,
            "impact":         impact,
        }

    def _extract_port_from_netstat_line(self, line):
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

            if name in ("FTP", "Telnet"):
                findings.append(self.build(
                    "critical",
                    f"Protocolo inseguro activo: {name} (puerto {port})",
                    f"Puerto {port} en escucha. {line.strip()}",
                    f"Deshabilitar {name} y usar alternativas seguras (SSH/SFTP).",
                    ["T1021 - Remote Services"],
                    explanation=(
                        f"{name} transmite todos los datos, incluidas las credenciales de autenticacion, "
                        "completamente en texto plano sin ningun cifrado. Son protocolos de los anos 70 "
                        "disenados antes de que existiera el concepto moderno de seguridad de red."
                    ),
                    impact=(
                        "Un atacante en la misma red puede capturar usuarios y contrasenas en segundos "
                        "con herramientas como Wireshark. Las credenciales robadas suelen reutilizarse "
                        "para acceder a otros sistemas (credential stuffing)."
                    ),
                ))
                continue

            fw_allows    = port in allowed_ports
            fw_protected = firewall_on and not fw_allows

            if fw_protected:
                findings.append(self.build(
                    "low",
                    f"Puerto {name} ({port}) activo pero bloqueado por firewall",
                    f"El servicio {name} esta en escucha localmente pero el firewall no tiene regla "
                    f"ALLOW inbound para el puerto {port}.",
                    f"Verificar que el servicio {name} sea necesario. Si no, deshabilitarlo.",
                    mitre,
                    explanation=(
                        f"El puerto {port} ({name}) tiene un servicio activo pero el Firewall de Windows "
                        "bloquea las conexiones entrantes externas. El riesgo es bajo mientras el firewall permanezca activo."
                    ),
                    impact=(
                        "Riesgo minimo en el estado actual. Si el firewall se deshabilita o modifica, "
                        "el puerto quedara expuesto inmediatamente. Mantener el servicio activo sin "
                        "necesidad real amplia la superficie de ataque potencial."
                    ),
                ))
            elif exposed_to_all and not firewall_on:
                sev = "critical" if name == "SMB" else "high"
                findings.append(self.build(
                    sev,
                    f"Puerto {name} ({port}) expuesto a red sin proteccion de firewall",
                    f"El servicio {name} acepta conexiones desde cualquier direccion y el firewall "
                    f"no esta activo. Riesgo de acceso remoto no autorizado.",
                    f"Activar el firewall de Windows y restringir el puerto {port} a hosts autorizados.",
                    mitre,
                    explanation=(
                        f"El puerto {port} ({name}) esta completamente expuesto a la red sin ninguna "
                        "barrera de proteccion. Cualquier IP puede intentar conectarse directamente al servicio."
                    ),
                    impact=(
                        f"Punto de entrada directo para atacantes remotos. {name} expuesto sin firewall "
                        "es un objetivo prioritario de escaneos automatizados. Puede permitir acceso no "
                        "autorizado, ejecucion remota de codigo o movimiento lateral."
                    ),
                ))
            else:
                sev = "high" if name in ("SMB", "RDP") else "medium"
                findings.append(self.build(
                    sev,
                    f"Puerto {name} ({port}) expuesto con regla ALLOW en firewall",
                    f"El puerto {port} ({name}) tiene una regla de entrada explicita que permite "
                    f"conexiones entrantes.",
                    f"Restringir la regla de firewall del puerto {port} a IPs o subredes autorizadas.",
                    mitre,
                    explanation=(
                        f"El servicio {name} en el puerto {port} esta activo y el firewall tiene una "
                        "regla ALLOW que permite conexiones entrantes. Si la regla es demasiado permisiva, "
                        "cualquier IP puede intentar conectarse."
                    ),
                    impact=(
                        "Superficie de ataque ampliada. Los servicios SMB y RDP expuestos publicamente "
                        "son objetivos frecuentes de escaneos automaticos, ataques de fuerza bruta "
                        "y explotacion de vulnerabilidades conocidas."
                    ),
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
            findings.append(self.build(
                "critical",
                "Firewall desactivado en todos los perfiles",
                f"Perfiles: {', '.join(disabled_profiles)}",
                "Activar firewall en Domain, Private y Public.",
                ["T1562.004 - Disable or Modify System Firewall"],
                explanation=(
                    "El Firewall de Windows es la primera barrera de defensa contra conexiones de red "
                    "no autorizadas. Cuando esta desactivado en todos los perfiles (Domain, Private, Public), "
                    "todos los puertos en escucha son accesibles desde la red sin ningun filtro."
                ),
                impact=(
                    "Cualquier servicio activo (SMB 445, RDP 3389, RPC 135...) se convierte en un punto "
                    "de entrada directo. Los escaneos de red automatizados encontraran y atacaran estos "
                    "servicios en minutos desde cualquier red."
                ),
            ))
        elif disabled_profiles:
            findings.append(self.build(
                "medium",
                "Firewall desactivado parcialmente",
                f"Perfiles sin proteccion: {', '.join(disabled_profiles)}",
                "Revisar configuracion y habilitar los perfiles faltantes.",
                ["T1562.004 - Disable or Modify System Firewall"],
                explanation=(
                    "Algunos perfiles del firewall estan activos pero otros no. En Windows, los perfiles "
                    "(Domain, Private, Public) se aplican segun el tipo de red conectada y pueden cambiar automaticamente."
                ),
                impact=(
                    "Si el equipo se conecta a una red donde el perfil desactivado se activa (comun en "
                    "laptops que cambian de red), quedara completamente expuesto. Riesgo especialmente "
                    "alto en entornos con movilidad."
                ),
            ))
        return findings

    # Users
    def analyze_users(self, results):
        findings = []
        users_data = results.get("users", {}) or {}
        users = users_data.get("users_full", []) or []
        admins = {u.lower() for u in (users_data.get("admins", []) or [])}

        system_builtin = {"defaultaccount", "wdagutilityaccount"}

        for user in users:
            name = user.get("name", "").strip()
            if not name:
                continue

            name_l = name.lower()
            enabled = bool(user.get("enabled", True))
            password_required = bool(user.get("password_required", True))

            if name_l in ("guest", "invitado") and enabled:
                findings.append(self.build(
                    "high",
                    f"Cuenta invitado habilitada: {name}",
                    "La cuenta Invitado esta activa.",
                    "Deshabilitar la cuenta Invitado si no es estrictamente necesaria.",
                    ["T1078 - Valid Accounts"],
                    explanation=(
                        "La cuenta Invitado es una cuenta integrada de Windows disenada para acceso temporal "
                        "sin contrasena. Windows la deshabilita por defecto precisamente por el riesgo que "
                        "representa. Permite acceso al sistema sin ninguna credencial."
                    ),
                    impact=(
                        "Acceso anonimo al sistema sin necesidad de conocer ninguna contrasena. Un atacante "
                        "puede explorar recursos compartidos de red, ejecutar programas locales o usarla "
                        "como punto de pivote para escalar privilegios."
                    ),
                ))

            if not password_required and name_l not in system_builtin:
                severity = "high" if name_l in admins else "medium"
                findings.append(self.build(
                    severity,
                    f"Usuario sin contrasena requerida: {name}",
                    f"El usuario '{name}' tiene PasswordRequired=False "
                    f"({'activo' if enabled else 'deshabilitado'}).",
                    f'Ejecutar: net user "{name}" /passwordreq:yes',
                    ["T1078 - Valid Accounts"],
                    explanation=(
                        f"La cuenta '{name}' esta configurada para no requerir contrasena. Esto significa "
                        "que cualquier persona puede iniciar sesion con solo escribir el nombre de usuario, "
                        "sin ninguna autenticacion adicional."
                    ),
                    impact=(
                        "Acceso inmediato al sistema sin ninguna barrera de autenticacion. "
                        + ("Para una cuenta administrativa, esto equivale a control total del sistema "
                           "disponible sin ninguna proteccion." if name_l in admins else
                           "Permite acceso no autorizado a datos y recursos del usuario.")
                    ),
                ))

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
            findings.append(self.build(
                "medium",
                f"Contrasenas sin rotacion adecuada ({max_age} dias)",
                f"max_age = {max_age}",
                "Configurar expiracion entre 60 y 90 dias.",
                ["T1078 - Valid Accounts"],
                explanation=(
                    "La politica de expiracion de contrasenas obliga a los usuarios a cambiar sus credenciales "
                    "periodicamente. Sin esta politica, una contrasena comprometida puede ser valida "
                    "indefinidamente sin que nadie lo detecte."
                ),
                impact=(
                    "Las credenciales robadas en ataques de phishing, data breaches o fuerza bruta "
                    "permanecen validas sin limite de tiempo, dando acceso persistente a atacantes "
                    "sin ninguna caducidad natural."
                ),
            ))

        if lockout_threshold == 0:
            findings.append(self.build(
                "high",
                "Sin bloqueo de cuenta por intentos fallidos",
                "lockout_threshold = 0",
                "Establecer bloqueo tras 5-10 intentos fallidos.",
                ["T1110.001 - Password Guessing"],
                explanation=(
                    "El bloqueo de cuenta es el mecanismo que bloquea temporalmente una cuenta despues "
                    "de un numero configurable de intentos de autenticacion fallidos. Sin este mecanismo, "
                    "los atacantes pueden probar contrasenas ilimitadamente."
                ),
                impact=(
                    "Los ataques de fuerza bruta y password guessing pueden ejecutarse sin ningun limite. "
                    "Herramientas modernas prueban millones de combinaciones, comprometiendo contrasenas "
                    "debiles en minutos y contrasenas de longitud media en horas."
                ),
            ))

        if history < 5:
            findings.append(self.build(
                "low",
                f"Historial de contrasenas bajo ({history})",
                f"history = {history}",
                "Configurar historial minimo de 10 contrasenas.",
                ["T1078 - Valid Accounts"],
                explanation=(
                    "El historial de contrasenas previene que los usuarios reutilicen las mismas credenciales "
                    "recientes. Sin un historial adecuado, un usuario puede alternar ciclicamente entre "
                    "las mismas contrasenas."
                ),
                impact=(
                    "Reduce la efectividad de la politica de rotacion. Los usuarios pueden mantener "
                    "indefinidamente contrasenas que podrian estar comprometidas simplemente rotandolas "
                    "ciclicamente entre pocas opciones."
                ),
            ))

        return findings

    # SMB Shares
    def analyze_smb(self, results):
        findings = []
        smb = results.get("smb_shares", {}) or {}
        if not smb:
            return findings

        if smb.get("smb1_enabled"):
            findings.append(self.build(
                "critical",
                "SMBv1 habilitado",
                "EnableSMB1Protocol = True",
                "Deshabilitar SMBv1 inmediatamente.",
                ["T1210 - Exploitation of Remote Services", "T1021.002 - SMB"],
                explanation=(
                    "SMBv1 es la version original del protocolo para compartir archivos en red de Microsoft, "
                    "lanzada en 1983. Contiene multiples vulnerabilidades criticas, siendo la mas famosa "
                    "EternalBlue (MS17-010), la base tecnica del ransomware WannaCry y NotPetya."
                ),
                impact=(
                    "Explotable con herramientas publicas para ejecucion remota de codigo sin autenticacion. "
                    "Fue el vector de los ataques de ransomware mas devastadores de la historia (WannaCry 2017: "
                    "200.000+ sistemas afectados). Solo tenerlo habilitado es suficiente para ser atacado."
                ),
            ))

        if not smb.get("null_session_restricted", True):
            findings.append(self.build(
                "high",
                "SMB: sesiones nulas sin restriccion (RestrictNullSessAccess = 0)",
                "Cualquier usuario anonimo puede conectarse a recursos compartidos IPC$ sin "
                "credenciales, permitiendo enumeracion de usuarios, grupos y politicas del dominio.",
                "Establecer RestrictNullSessAccess = 1: "
                "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
                "-Name RestrictNullSessAccess -Value 1. "
                "Si SMB no es necesario en red, bloquearlo en el firewall (puerto 445).",
                ["T1135 - Network Share Discovery", "T1087 - Account Discovery"],
                explanation=(
                    "Las sesiones nulas permiten conectarse al recurso compartido IPC$ (canal de comunicacion "
                    "entre procesos de Windows) sin ningun usuario ni contrasena. Era una caracteristica de "
                    "redes Windows antiguas (NT 4.0) usada para administracion remota que ya no es necesaria."
                ),
                impact=(
                    "Un atacante anonimo puede enumerar usuarios del sistema, grupos, recursos compartidos, "
                    "politicas de contrasenas y otra informacion sensible sin ninguna credencial, usando "
                    "herramientas como enum4linux. Es el primer paso tipico del reconocimiento en redes Windows."
                ),
            ))

        default_admin_shares = {"ADMIN$", "IPC$", "C$", "D$"}
        custom_shares = [
            s.get("name", "")
            for s in (smb.get("shares", []) or [])
            if s.get("name", "").upper() not in default_admin_shares
        ]
        if custom_shares:
            findings.append(self.build(
                "medium",
                "Recursos compartidos adicionales detectados",
                f"Shares detectados: {', '.join(sorted(set(custom_shares)))}",
                "Validar permisos y necesidad de cada recurso compartido.",
                ["T1135 - Network Share Discovery"],
                explanation=(
                    "Se detectaron recursos compartidos de red (SMB) adicionales a los predeterminados del "
                    "sistema. Estos exponen directorios del sistema de archivos a traves de la red y "
                    "requieren permisos correctamente configurados para ser seguros."
                ),
                impact=(
                    "Acceso no autorizado a datos si los permisos no estan correctamente configurados. "
                    "Los recursos compartidos mal protegidos son uno de los vectores mas comunes de "
                    "robo de datos internos y movimiento lateral en redes corporativas."
                ),
            ))

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
                findings.append(self.build(
                    "high",
                    f"Proceso ejecutandose desde ruta sospechosa: {proc.get('name', 'Unknown')}",
                    f"PID {proc.get('pid', '?')} - {proc.get('path', '')}",
                    "Investigar el proceso y su origen.",
                    ["T1059 - Command and Scripting Interpreter"],
                    explanation=(
                        "Los procesos legitimos se ejecutan desde rutas estandar del sistema (System32, "
                        "Program Files). Un proceso ejecutandose desde Temp, Public o Downloads es inusual "
                        "y caracteristico de malware que se extrae y ejecuta desde rutas de escritura libre."
                    ),
                    impact=(
                        "Alta probabilidad de actividad maliciosa. Las rutas Temp y Public son accesibles "
                        "para cualquier usuario sin privilegios, ideales para malware. Puede ser un "
                        "downloader, RAT, ransomware o backdoor en ejecucion activa."
                    ),
                ))

        system_lolbin_paths = ("\\system32\\", "\\syswow64\\", "\\systemapps\\")

        grouped_lolbins = {}
        for lolbin in procs.get("lolbins", []) or []:
            name = (lolbin.get("name") or "").lower()
            mitre_tag = LOLBINS.get(name, "T1218 - System Binary Proxy Execution")
            path = (lolbin.get("path") or "").lower()

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
            findings.append(self.build(
                "high" if entry["suspicious"] else "review",
                f"LOLBin activo: {entry['name']} ({entry['count']} proceso(s))",
                f"Ruta: {entry['path']}",
                "Verificar si su ejecucion corresponde al comportamiento esperado.",
                [entry["mitre"]],
                explanation=(
                    "Los LOLBins (Living Off the Land Binaries) son ejecutables legitimos de Windows "
                    f"(firmados por Microsoft) como {entry['name']} que los atacantes reutilizan para "
                    "realizar acciones maliciosas. Su firma valida les permite evadir la deteccion de antivirus."
                ),
                impact=(
                    "Ejecucion de codigo malicioso que los antivirus no detectan por estar firmado por "
                    "Microsoft. Permite descargar payloads, ejecutar scripts, escalar privilegios y "
                    "moverse lateralmente sin generar alertas en herramientas de seguridad tradicionales."
                    if entry["suspicious"] else
                    "Requiere verificacion manual. Si el proceso esta siendo abusado, puede indicar un "
                    "atacante usando tecnicas living-off-the-land para evadir deteccion."
                ),
            ))

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
                findings.append(self.build(
                    severity,
                    f"Ejecutable con firma invalida: {item.get('name', 'Unknown')} ({status})",
                    item.get("path", ""),
                    "Validar integridad y origen del binario.",
                    ["T1036 - Masquerading", "T1574 - Hijack Execution Flow"],
                    explanation=(
                        "La firma digital garantiza que un ejecutable fue creado por el firmante declarado "
                        "y no ha sido modificado desde entonces. Un ejecutable sin firma en una ruta no "
                        "estandar es inusual. "
                        + ("Un HashMismatch indica que el archivo fue modificado DESPUES de firmarse, "
                           "senal directa de tampering." if status == "HashMismatch" else
                           "Los ejecutables sin firma en rutas no estandar son caracteristicos de malware.")
                    ),
                    impact=(
                        "Puede indicar malware disfrazado de software legitimo o un binario del sistema "
                        "reemplazado por una version maliciosa. "
                        + ("HashMismatch es especialmente grave: confirma modificacion post-firma, "
                           "lo que apunta a comprension activa del sistema." if status == "HashMismatch" else
                           "Requiere investigacion del origen y proposito del ejecutable.")
                    ),
                ))

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
            findings.append(self.build(
                "critical",
                f"Sistema desactualizado: {count} actualizaciones pendientes",
                f"Ultima actualizacion: {last}",
                "Aplicar actualizaciones de seguridad inmediatamente.",
                ["T1190 - Exploit Public-Facing Application"],
                explanation=(
                    "Las actualizaciones de Windows incluyen parches para vulnerabilidades de seguridad "
                    "conocidas publicamente (CVEs). Con mas de 20 pendientes, el sistema tiene un gran "
                    "volumen de vulnerabilidades documentadas sin corregir."
                ),
                impact=(
                    "Los atacantes escanean activamente sistemas sin parchear. Los exploits para CVEs "
                    "conocidos estan disponibles publicamente. Un sistema muy desactualizado puede "
                    "comprometerse con herramientas automatizadas en minutos."
                ),
            ))
        elif count > 5:
            findings.append(self.build(
                "high",
                f"{count} actualizaciones pendientes de Windows",
                f"Ultima actualizacion: {last}",
                "Aplicar actualizaciones pendientes.",
                ["T1190 - Exploit Public-Facing Application"],
                explanation=(
                    "Existen actualizaciones de seguridad pendientes que corrigen vulnerabilidades conocidas. "
                    "Microsoft publica parches mensualmente (Patch Tuesday) y en emergencias para "
                    "vulnerabilidades criticas."
                ),
                impact=(
                    "Cada actualizacion pendiente es una vulnerabilidad conocida sin corregir. "
                    "Los atacantes priorizan sistemas desactualizados como objetivos facilmente explotables "
                    "usando exploits publicos."
                ),
            ))
        elif count > 0:
            findings.append(self.build(
                "medium",
                f"{count} actualizaciones menores pendientes",
                f"Ultima actualizacion: {last}",
                "Completar ciclo de actualizacion.",
                explanation=(
                    "Hay algunas actualizaciones pendientes. Pueden incluir correcciones de seguridad "
                    "menores, mejoras de estabilidad o actualizaciones funcionales."
                ),
                impact=(
                    "Riesgo bajo pero acumulativo. Mantener el sistema actualizado reduce progresivamente "
                    "la superficie de ataque y previene la explotacion de vulnerabilidades recientes."
                ),
            ))
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
                findings.append(self.build(
                    "critical",
                    "Persistencia sospechosa en registro (Run key)",
                    line,
                    "Eliminar o deshabilitar la entrada sospechosa.",
                    ["T1547.001 - Registry Run Keys"],
                    explanation=(
                        "Las claves Run y RunOnce del registro de Windows permiten que programas se ejecuten "
                        "automaticamente al iniciar sesion. Son uno de los mecanismos de persistencia mas "
                        "simples y frecuentemente usados por malware para sobrevivir a reinicios."
                    ),
                    impact=(
                        "El malware con persistencia via Run keys se reactiva automaticamente en cada "
                        "reinicio del sistema. Una entrada sospechosa puede ser un backdoor, keylogger, "
                        "bot o cualquier tipo de malware persistente que reinstala sus componentes."
                    ),
                ))

        for line in results.get("startup", []) or []:
            low = line.lower()
            if any(w in low for w in whitelist):
                continue
            if ".ps1" in low or any(p in low for p in suspicious_paths):
                findings.append(self.build(
                    "high",
                    "Persistencia sospechosa en carpeta Startup",
                    line,
                    "Investigar y remover el artefacto si no es legitimo.",
                    ["T1547.001 - Boot or Logon Autostart"],
                    explanation=(
                        "La carpeta Startup de Windows contiene accesos directos y programas que se ejecutan "
                        "automaticamente al iniciar sesion de usuario. Es un mecanismo clasico de persistencia "
                        "de malware, especialmente para scripts .ps1 y .vbs."
                    ),
                    impact=(
                        "El malware persiste y se ejecuta automaticamente en cada login. Los scripts "
                        "PowerShell (.ps1) en Startup son especialmente sospechosos al combinar "
                        "persistencia con las capacidades de scripting de PowerShell."
                    ),
                ))
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
                    findings.append(self.build(
                        "medium",
                        f"Ruta de servicio sin comillas: {name}",
                        raw_path,
                        "Encerrar la ruta del ejecutable entre comillas.",
                        ["T1574.009 - Path Interception by Unquoted Path"],
                        explanation=(
                            "Cuando la ruta de un ejecutable de servicio contiene espacios y no esta entre "
                            "comillas, Windows puede intentar ejecutar rutas alternativas. Por ejemplo, "
                            "'C:\\Program Files\\Mi App\\servicio.exe' podria ejecutar 'C:\\Program.exe'."
                        ),
                        impact=(
                            "Un atacante con permisos de escritura en la ruta alternativa puede colocar "
                            "un ejecutable malicioso que sera ejecutado como servicio del sistema con "
                            "privilegios elevados. Es una tecnica clasica de escalada de privilegios local."
                        ),
                    ))

            if any(p in exe_low for p in suspicious_paths):
                findings.append(self.build(
                    "high",
                    f"Servicio desde ruta sospechosa: {name}",
                    raw_path,
                    "Validar legitimidad y origen del servicio.",
                    ["T1543 - Create or Modify System Process"],
                    explanation=(
                        "Los servicios de Windows normalmente residen en System32, Program Files o "
                        "ProgramData\\Microsoft. Un servicio ejecutandose desde AppData, Temp o Public "
                        "es extremadamente inusual y requiere investigacion inmediata."
                    ),
                    impact=(
                        "Muy probable indicador de malware persistente. Los servicios se ejecutan con "
                        "privilegios elevados y antes del login del usuario, haciendolos ideales para "
                        "backdoors y RATs que necesitan persistencia con privilegios."
                    ),
                ))

        return findings

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
                explanation=(
                    "UAC (Control de Cuentas de Usuario) es el sistema de Windows que separa los "
                    "privilegios de usuario estandar de los administrativos. Con EnableLUA=0, todos "
                    "los procesos se ejecutan directamente con el token de administrador completo, "
                    "sin ninguna separacion de privilegios."
                ),
                impact=(
                    "Cualquier proceso, incluido malware, que se ejecute obtiene automaticamente "
                    "privilegios de administrador y SYSTEM sin necesitar confirmacion. No existe "
                    "ninguna barrera entre el codigo del usuario y el control total del sistema operativo."
                ),
            ))
            return findings

        if consent_admin == 0:
            findings.append(self.build(
                "high",
                "UAC: elevacion automatica sin confirmacion para administradores (ConsentPromptBehaviorAdmin=0)",
                "Los procesos ejecutados por cuentas administrativas obtienen tokens elevados de forma "
                "silenciosa. Un malware con contexto de administrador escala a SYSTEM sin friction.",
                "Establecer ConsentPromptBehaviorAdmin=1 (solicitar credenciales en escritorio seguro) "
                "o al menos =2 (solicitar consentimiento). Valor 0 solo es aceptable en entornos kiosko.",
                ["T1548.002 - Bypass User Account Control"],
                explanation=(
                    "Con ConsentPromptBehaviorAdmin=0, cualquier proceso ejecutado con contexto de "
                    "administrador obtiene un token elevado completamente de forma silenciosa, sin "
                    "ningun prompt de confirmacion visible para el usuario."
                ),
                impact=(
                    "Un malware que consiga ejecutarse con contexto de administrador (por ejemplo, "
                    "mediante phishing o explotacion) escala inmediatamente a SYSTEM sin ninguna "
                    "friccion ni alerta visible para el usuario."
                ),
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
                explanation=(
                    "El nivel de UAC solicita confirmacion al usuario (clic en 'Si') pero no requiere "
                    "introducir credenciales. Este nivel no verifica que quien aprueba sea realmente "
                    "un administrador autorizado, solo que alguien hizo clic en 'Si'."
                ),
                impact=(
                    "Vulnerable a ataques de clickjacking y prompt fatigue. Un malware puede mostrar "
                    "ventanas falsas superpuestas al prompt UAC o simplemente abusar de la tendencia "
                    "del usuario a hacer clic en 'Si' sin leer."
                ),
            ))

        if consent_user == 0:
            findings.append(self.build(
                "high",
                "UAC: usuarios estandar pueden elevar privilegios sin credenciales (ConsentPromptBehaviorUser=0)",
                "ConsentPromptBehaviorUser=0: las cuentas sin privilegios administrativos obtienen "
                "elevacion sin presentar credenciales de administrador, anulando el modelo de minimo privilegio.",
                "Establecer ConsentPromptBehaviorUser=3 para requerir credenciales de administrador "
                "en cada solicitud de elevacion desde cuentas estandar.",
                ["T1548.002 - Bypass User Account Control"],
                explanation=(
                    "Con ConsentPromptBehaviorUser=0, cualquier usuario estandar del sistema puede "
                    "obtener elevacion de privilegios sin proporcionar credenciales de administrador, "
                    "violando completamente el principio de minimo privilegio."
                ),
                impact=(
                    "Cualquier usuario del sistema puede obtener acceso administrativo sin conocer "
                    "ninguna contrasena. Anula completamente el modelo de separacion de privilegios "
                    "de Windows."
                ),
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
                explanation=(
                    "El escritorio seguro (Secure Desktop) aísla el prompt UAC en un proceso separado "
                    "que otros procesos no pueden manipular ni superponer. Sin el, el dialogo UAC "
                    "aparece en el escritorio normal donde cualquier proceso puede interactuar con el."
                ),
                impact=(
                    "Vulnerable a ataques de UI spoofing donde un proceso malicioso puede superponer "
                    "ventanas falsas sobre el prompt UAC, engananado al usuario para que apruebe "
                    "elevaciones no deseadas sin saberlo."
                ),
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
        log_enabled  = ev.get("security_log_enabled")
        read_error   = bool(ev.get("security_log_read_error", True))
        log_mb       = int(ev.get("security_log_max_mb",   0) or 0)
        svc_running  = ev.get("eventlog_svc_running", True)
        auditpol_ok      = ev.get("auditpol_ok", True)
        auditpol_unknown = ev.get("auditpol_unknown", False)

        _expl_logs = (
            "Los registros de eventos de Windows (Event Logs) son el unico mecanismo nativo de "
            "auditoria. Registran autenticaciones, cambios de configuracion, errores y eventos "
            "criticos de seguridad como logins fallidos, creacion de cuentas y uso de privilegios."
        )
        _impact_logs = (
            "Sin logs de seguridad, cualquier ataque, intrusion, escalada de privilegios o cambio "
            "de configuracion ocurre completamente sin dejar rastro. Imposibilidad total de "
            "investigacion forense post-incidente o deteccion de ataques activos."
        )

        if svc_running is False:
            findings.append(self.build("critical",
                "Servicio Windows Event Log detenido",
                "El servicio EventLog no esta en ejecucion — ningun evento del sistema se registra.",
                "Iniciar el servicio: Start-Service EventLog y configurar inicio automatico.",
                ["T1562.002 - Disable Windows Event Logging"],
                explanation=_expl_logs,
                impact=_impact_logs,
            ))
        elif log_enabled is False and not read_error:
            findings.append(self.build("critical",
                "Registro de seguridad de Windows deshabilitado",
                "El canal Security Event Log esta desactivado — sin auditoria de eventos de autenticacion.",
                "auditpol /set /category:* /success:enable /failure:enable",
                ["T1562.002 - Disable Windows Event Logging"],
                explanation=_expl_logs,
                impact=_impact_logs,
            ))
        elif auditpol_unknown:
            findings.append(self.build("review",
                "Auditoria (auditpol): no se pudo verificar el estado",
                "No se pudo leer la configuracion de auditpol para Logon/Logoff/Special Logon.",
                "Verificar manualmente: auditpol /get /category:* como Administrador.",
                ["T1562.002 - Disable Windows Event Logging"],
                explanation=(
                    "Auditpol controla que categorias de eventos de seguridad se registran. "
                    "No se pudo verificar si la auditoria de Logon/Logoff esta activa, posiblemente "
                    "por restricciones de permisos al leer la configuracion."
                ),
                impact=(
                    "Sin confirmacion del estado de auditoria, no se puede garantizar que los eventos "
                    "de autenticacion se registren. Requiere verificacion manual."
                ),
            ))
        elif not auditpol_ok:
            findings.append(self.build("high",
                "Auditoria de eventos de seguridad deshabilitada (auditpol)",
                "Las subcategorias Logon, Logoff y Special Logon no registran eventos de autenticacion.",
                "Ejecutar: auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
                ["T1562.002 - Disable Windows Event Logging"],
                explanation=(
                    "Auditpol controla que categorias de eventos de seguridad se registran en el "
                    "Security Event Log. Con Logon/Logoff deshabilitado, los intentos de autenticacion "
                    "(tanto exitosos como fallidos) no generan ningun evento."
                ),
                impact=(
                    "Los ataques de fuerza bruta, accesos no autorizados y movimientos laterales "
                    "son completamente invisibles. Sin estos eventos, es imposible detectar un "
                    "ataque de autenticacion activo o investigarlo post-incidente."
                ),
            ))
        elif read_error:
            findings.append(self.build("review",
                "Registro de seguridad: no se pudo verificar el estado",
                "No se pudo leer la configuracion del Security Event Log (posible falta de permisos).",
                "Verificar con: Get-WinEvent -ListLog Security y auditpol /get /category:* como Admin.",
                ["T1562.002 - Disable Windows Event Logging"],
                explanation=(
                    "No se pudo acceder al Security Event Log para verificar su estado. Esto puede "
                    "deberse a permisos insuficientes o a que el log no esta configurado correctamente."
                ),
                impact=(
                    "Sin acceso de verificacion, no se puede confirmar si la auditoria de seguridad "
                    "esta activa. Se recomienda verificacion manual con permisos de administrador."
                ),
            ))
        elif log_mb > 0 and log_mb < 20:
            findings.append(self.build("medium",
                f"Registro de seguridad muy pequeno ({log_mb} MB)",
                "El tamano maximo del log es insuficiente y se sobreescribe rapidamente, perdiendo evidencia forense.",
                "Aumentar el tamano del Security Log a 128 MB o mas en el Visor de Eventos.",
                ["T1562.002 - Disable Windows Event Logging"],
                explanation=(
                    "El tamano maximo del Security Event Log determina cuanta historia de eventos puede "
                    "mantenerse antes de sobreescribirse. Un log de menos de 20 MB se llena rapidamente, "
                    "especialmente bajo ataques que generan muchos eventos."
                ),
                impact=(
                    "La evidencia forense se pierde en horas. En un ataque de fuerza bruta activo, "
                    "el log puede sobreescribirse en minutos, borrando toda evidencia del ataque "
                    "y dificultando la investigacion post-incidente."
                ),
            ))

        if failed_1h > 20:
            findings.append(self.build("critical",
                f"Ataque de fuerza bruta activo: {failed_1h} fallos en la ultima hora (4625)",
                f"{failed_1h} intentos fallidos de autenticacion en 60 minutos.",
                "Bloquear IP origen, aplicar lockout policy inmediatamente.",
                ["T1110.001 - Password Guessing", "T1110 - Brute Force"],
                explanation=(
                    f"Se detectaron {failed_1h} intentos de autenticacion fallidos en la ultima hora, "
                    "indicando un ataque de fuerza bruta activo en tiempo real. Este volumen supera "
                    "ampliamente el comportamiento de usuarios legitimos."
                ),
                impact=(
                    "Si el ataque tiene exito, el atacante obtiene acceso completo a la cuenta comprometida. "
                    "Sin politica de lockout, el ataque puede continuar indefinidamente hasta encontrar "
                    "la contrasena correcta."
                ),
            ))
        elif failed_24h > 100:
            findings.append(self.build("critical",
                f"Posible fuerza bruta: {failed_24h} fallos en 24h (4625)",
                f"{failed_24h} intentos fallidos acumulados.",
                "Revisar origenes e implementar lockout threshold.",
                ["T1110 - Brute Force"],
                explanation=(
                    f"Se detectaron {failed_24h} intentos de autenticacion fallidos en 24 horas. "
                    "Este volumen elevado puede indicar un ataque de fuerza bruta distribuido, "
                    "un botnet o multiples fuentes de ataque coordinadas."
                ),
                impact=(
                    "Posible compromiso de cuentas si alguno de los intentos tuvo exito. "
                    "Los intentos fallidos tambien permiten enumerar usuarios validos del sistema "
                    "a partir de las respuestas del servidor."
                ),
            ))
        elif failed_24h > 20:
            findings.append(self.build("high",
                f"{failed_24h} intentos fallidos de login en 24h (4625)",
                "Actividad de autenticacion elevada.",
                "Investigar origenes.",
                ["T1110 - Brute Force"],
                explanation=(
                    f"Se registraron {failed_24h} intentos de autenticacion fallidos en 24 horas, "
                    "por encima del nivel normal. Puede indicar ataques de fuerza bruta, "
                    "credenciales mal configuradas en sistemas automatizados o actividad sospechosa."
                ),
                impact=(
                    "Indica actividad de autenticacion anormal. Si los intentos son dirigidos "
                    "y una cuenta no tiene lockout, puede comprometerse con suficientes intentos."
                ),
            ))

        if len(targets) > 5 and failed_24h > 10:
            preview = ", ".join(targets[:8]) + ("..." if len(targets) > 8 else "")
            findings.append(self.build("high",
                f"Posible password spray: {len(targets)} cuentas distintas atacadas (4625)",
                f"Cuentas objetivo detectadas: {preview}",
                "Revisar IP origen comun; considerar bloqueo a nivel de red.",
                ["T1110.003 - Password Spraying"],
                explanation=(
                    "Un ataque de password spray consiste en probar pocas contrasenas muy comunes "
                    "contra muchas cuentas diferentes, evitando triggear el lockout de una cuenta "
                    f"especifica. Se detectaron {len(targets)} cuentas distintas siendo atacadas."
                ),
                impact=(
                    "Efectivo para comprometer cuentas con contrasenas debiles o predecibles. "
                    "Al distribuirse entre muchas cuentas, evita el bloqueo automatico y puede "
                    "pasar desapercibido en sistemas sin deteccion de anomalias."
                ),
            ))

        if lockouts > 5:
            findings.append(self.build("high",
                f"{lockouts} bloqueos de cuenta en 24h (4740)",
                "Multiples cuentas bloqueadas, posible ataque activo.",
                "Revisar origen con Event ID 4740.",
                ["T1110 - Brute Force"],
                explanation=(
                    f"Se detectaron {lockouts} bloqueos de cuenta en 24 horas. Los bloqueos "
                    "ocurren cuando una cuenta alcanza el umbral de intentos fallidos configurado, "
                    "lo que indica ataques de autenticacion activos."
                ),
                impact=(
                    "Indica ataque activo en progreso. Los bloqueos de cuenta tambien afectan "
                    "la disponibilidad del servicio para usuarios legitimos (DoS sobre cuentas)."
                ),
            ))

        if created > 0:
            findings.append(self.build("critical",
                f"Cuenta de usuario creada en las ultimas 24h (4720) x{created}",
                f"{created} cuenta(s) nueva(s) detectada(s).",
                "Verificar si la creacion fue autorizada.",
                ["T1136.001 - Create Account: Local Account"],
                explanation=(
                    f"Se detecto la creacion de {created} cuenta(s) de usuario en las ultimas 24 horas. "
                    "La creacion de cuentas inesperadas es una tecnica clasica de post-explotacion "
                    "para mantener acceso persistente al sistema."
                ),
                impact=(
                    "Una cuenta nueva no autorizada puede ser un backdoor creado por un atacante "
                    "que ya tiene acceso al sistema. Permite mantener acceso incluso si se "
                    "cambian las contrasenas de las cuentas existentes."
                ),
            ))

        if priv > 50:
            findings.append(self.build("high",
                f"Asignacion masiva de privilegios: {priv} eventos (4672)",
                f"{priv} asignaciones de privilegios especiales en 24h (sin cuentas de sistema).",
                "Revisar Event ID 4672 para identificar cuentas no autorizadas.",
                ["T1134 - Access Token Manipulation", "T1078 - Valid Accounts"],
                explanation=(
                    f"Se detectaron {priv} asignaciones de privilegios especiales (Event ID 4672) "
                    "en 24 horas, excluyendo cuentas del sistema. Este evento se genera cuando "
                    "una cuenta inicia sesion con privilegios administrativos especiales."
                ),
                impact=(
                    "Un volumen elevado puede indicar uso abusivo de cuentas privilegiadas, "
                    "movimiento lateral con cuentas de administrador o manipulacion de tokens "
                    "de acceso por parte de un atacante."
                ),
            ))
        elif priv > 10:
            findings.append(self.build("medium",
                f"{priv} asignaciones de privilegios especiales en 24h (4672)",
                "Actividad de privilegios por encima de lo normal.",
                "Auditar Event ID 4672 en el Visor de eventos.",
                ["T1078 - Valid Accounts"],
                explanation=(
                    f"Se registraron {priv} eventos de asignacion de privilegios especiales, "
                    "por encima del nivel base normal. Puede ser actividad administrativa "
                    "legitima o uso inusual de cuentas privilegiadas."
                ),
                impact=(
                    "Requiere revision para confirmar que toda la actividad de privilegios "
                    "corresponde a administradores autorizados realizando tareas legitimas."
                ),
            ))

        if offhours > 10:
            findings.append(self.build("high",
                f"{offhours} inicios de sesion fuera de horario en 24h (4624)",
                "Logins detectados entre 23:00 y 07:00 horas.",
                "Revisar Event ID 4624 para identificar origen y cuenta.",
                ["T1078 - Valid Accounts"],
                explanation=(
                    f"Se detectaron {offhours} inicios de sesion entre las 23:00 y 07:00 horas. "
                    "Los accesos fuera del horario laboral habitual son indicadores de "
                    "actividad sospechosa o compromiso de cuentas."
                ),
                impact=(
                    "Los accesos nocturnos no autorizados permiten a los atacantes operar con "
                    "menor visibilidad y supervision. Pueden indicar exfiltracion de datos, "
                    "instalacion de herramientas o reconocimiento del entorno."
                ),
            ))

        if remote > 20:
            findings.append(self.build("medium",
                f"{remote} sesiones remotas interactivas en 24h (4624 tipo 10)",
                "Volumen elevado de conexiones RemoteInteractive (RDP).",
                "Verificar si todas las sesiones son legitimas.",
                ["T1021.001 - Remote Desktop Protocol"],
                explanation=(
                    f"Se registraron {remote} sesiones RDP (RemoteInteractive, tipo 10) en 24 horas. "
                    "Un volumen elevado de conexiones remotas puede indicar uso intensivo de "
                    "administracion remota o actividad sospechosa no autorizada."
                ),
                impact=(
                    "Requiere verificacion de que todas las sesiones RDP corresponden a "
                    "usuarios y sistemas autorizados. Conexiones no autorizadas pueden "
                    "indicar un atacante controlando el sistema remotamente."
                ),
            ))

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
                ["T1552.002 - Credentials in Registry"],
                explanation=(
                    "El auto-login almacena el nombre de usuario y contrasena en el registro de "
                    "Windows (HKLM\\...\\Winlogon) en texto plano. Windows inicia sesion "
                    "automaticamente al arrancar sin solicitar ninguna credencial al usuario."
                ),
                impact=(
                    "Acceso fisico al equipo equivale a acceso completo al sistema operativo. "
                    + ("La contrasena puede extraerse del registro con herramientas simples. "
                       "Si el disco no esta cifrado con BitLocker, basta arrancar desde USB." if has_pw else
                       "Sin contrasena configurada, cualquiera puede acceder simplemente encendiendo el equipo.")
                ),
            ))
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
                ["T1025 - Data from Removable Media"],
                explanation=(
                    "BitLocker Drive Encryption protege los datos del disco cifrando todo su contenido. "
                    "No se pudo verificar el estado de cifrado, posiblemente por falta de permisos "
                    "o porque BitLocker no esta disponible en esta edicion de Windows."
                ),
                impact=(
                    "Sin confirmacion del estado de cifrado, no se puede garantizar la proteccion "
                    "de datos en caso de acceso fisico al dispositivo o robo del equipo."
                ),
            ))
            return findings

        for vol in volumes:
            mount      = vol.get("mount", "?")
            status     = (vol.get("status")     or "").strip()
            vol_status = (vol.get("vol_status") or "").strip()
            pct        = int(vol.get("pct", 0) or 0)
            protectors = (vol.get("protectors") or "").strip()

            fully_enc    = vol_status == "FullyEncrypted" or pct >= 100
            fully_dec    = vol_status == "FullyDecrypted" or pct == 0
            prot_info    = f"Protectores: {protectors}." if protectors else ""

            if fully_enc:
                continue

            if fully_dec:
                findings.append(self.build("high",
                    f"BitLocker desactivado en {mount}",
                    f"La unidad {mount} no tiene cifrado activo (VolumeStatus={vol_status}, {pct}%). {prot_info}",
                    f"Activar BitLocker: Enable-BitLocker -MountPoint '{mount}' "
                    "-EncryptionMethod XtsAes256 -TpmProtector",
                    ["T1025 - Data from Removable Media"],
                    explanation=(
                        f"La unidad {mount} no esta cifrada. BitLocker Drive Encryption protege los datos "
                        "del disco cifrando todo su contenido con AES-XTS-256. Sin cifrado, los datos "
                        "son accesibles directamente si alguien obtiene acceso fisico al dispositivo."
                    ),
                    impact=(
                        "Acceso completo a todos los datos (documentos, bases de datos, contrasenas "
                        "guardadas, historial de navegacion) simplemente conectando el disco a otro equipo "
                        "o arrancando desde un Live USB. No se necesita conocer la contrasena de Windows."
                    ),
                ))
            elif 0 < pct < 100:
                findings.append(self.build("medium",
                    f"BitLocker en progreso en {mount}: {pct}% cifrado",
                    f"La unidad {mount} esta cifrándose (VolumeStatus={vol_status}). {prot_info}",
                    "Esperar a que el cifrado complete o verificar que no este pausado.",
                    ["T1025 - Data from Removable Media"],
                    explanation=(
                        f"BitLocker esta cifrando la unidad {mount} ({pct}% completado). "
                        "Durante este proceso, los sectores ya cifrados estan protegidos pero "
                        "los pendientes aun son accesibles sin cifrado."
                    ),
                    impact=(
                        "Proteccion parcial hasta que el proceso complete. Si el cifrado se "
                        "pausa o interrumpe, pueden quedar sectores sin cifrar permanentemente. "
                        "Verificar que el proceso avance correctamente."
                    ),
                ))
            else:
                findings.append(self.build("review",
                    f"BitLocker en {mount}: estado indeterminado",
                    f"VolumeStatus={vol_status}, ProtectionStatus={status}, {pct}% cifrado. {prot_info}",
                    "Verificar manualmente: Get-BitLockerVolume como Admin.",
                    ["T1025 - Data from Removable Media"],
                    explanation=(
                        f"El estado de cifrado de la unidad {mount} no pudo determinarse con certeza. "
                        "Los valores obtenidos son inconsistentes o indeterminados."
                    ),
                    impact=(
                        "Sin estado claro de cifrado, no se puede evaluar el nivel de proteccion "
                        "de datos en este volumen. Requiere verificacion manual."
                    ),
                ))

        return findings

    # Correlacion y alertas comportamentales
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
                ["T1110 - Brute Force"],
                explanation=(
                    "Se combina un ataque de fuerza bruta activo con ausencia total de politica "
                    "de bloqueo de cuenta. Este es el escenario optimo para un atacante: puede "
                    "intentar contrasenas indefinidamente sin ninguna consecuencia."
                ),
                impact=(
                    "Alta probabilidad de compromiso de cuenta inminente. El ataque continuara "
                    "hasta encontrar la contrasena correcta. Solo la fortaleza de la contrasena "
                    "esta entre el atacante y el acceso completo al sistema."
                ),
            ))

        if not log_ok and not ps_enabled and not ps_read_err:
            alerts.append(self.build("critical",
                "[CORRELACION] Auditoria ciega: Security Log + PowerShell Log deshabilitados",
                "Sin logs de seguridad ni PowerShell, cualquier ataque queda sin evidencia forense.",
                "Habilitar Security Log (auditpol) y Script Block Logging via GPO.",
                ["T1562.002 - Disable Windows Event Logging", "T1059.001 - PowerShell"],
                explanation=(
                    "Tanto el Security Event Log como el PowerShell Script Block Logging estan "
                    "deshabilitados simultaneamente. Estos son los dos principales canales de "
                    "auditoria para detectar ataques en sistemas Windows."
                ),
                impact=(
                    "Ceguera forense total. Un atacante puede ejecutar ataques de autenticacion, "
                    "scripts maliciosos, descargar herramientas y moverse lateralmente sin dejar "
                    "absolutamente ninguna evidencia en los logs del sistema."
                ),
            ))

        if (min_len < 8 or lockout_thr == 0) and no_pw > 0:
            alerts.append(self.build("critical",
                f"[CORRELACION] Politica debil + {no_pw} usuario(s) sin contrasena",
                f"Longitud minima: {min_len}, lockout: {lockout_thr}. Acceso sin credenciales posible.",
                "Reforzar politica de contrasenas y asignar contrasenas a todos los usuarios.",
                ["T1110 - Brute Force", "T1078 - Valid Accounts"],
                explanation=(
                    "Se combinan una politica de contrasenas debil con cuentas sin contrasena "
                    "requerida. Esto crea multiples vectores de acceso sin autenticacion real "
                    "o con autenticacion facilmente superable."
                ),
                impact=(
                    "Acceso directo al sistema sin ninguna credencial para las cuentas sin "
                    "contrasena. Para el resto, la politica debil hace los ataques de fuerza "
                    "bruta triviales con herramientas automatizadas."
                ),
            ))

        if wdigest and rdp_on:
            alerts.append(self.build("critical",
                "[CORRELACION] WDigest activo + RDP expuesto — volcado remoto de credenciales",
                "Credenciales en texto plano en LSASS accesibles via sesion RDP.",
                "Deshabilitar WDigest (UseLogonCredential=0) y habilitar NLA en RDP.",
                ["T1003.001 - LSASS Memory", "T1021.001 - Remote Desktop Protocol"],
                explanation=(
                    "WDigest almacena contrasenas en texto plano en la memoria LSASS y RDP esta "
                    "activo. Un atacante puede conectarse via RDP y ejecutar Mimikatz para extraer "
                    "las contrasenas en texto plano de todos los usuarios con sesion activa."
                ),
                impact=(
                    "Volcado remoto de credenciales en texto plano sin necesidad de acceso fisico. "
                    "Un atacante con acceso RDP inicial puede escalar y obtener todas las contrasenas "
                    "activas del sistema, comprometiendo potencialmente el dominio completo."
                ),
            ))

        if auto_on and bl_off:
            alerts.append(self.build("critical",
                "[CORRELACION] Auto-login habilitado + disco sin cifrar",
                "Acceso fisico permite login automatico y lectura directa de datos del disco.",
                "Deshabilitar auto-login y activar BitLocker.",
                ["T1552.002 - Credentials in Registry", "T1025 - Data from Removable Media"],
                explanation=(
                    "Las credenciales de auto-login estan almacenadas en el registro Y el disco "
                    "no esta cifrado. Esta combinacion hace que el acceso fisico al dispositivo "
                    "sea suficiente para obtener acceso completo al sistema y sus datos."
                ),
                impact=(
                    "Arrancar desde USB es suficiente para: leer las credenciales del registro, "
                    "acceder a todos los datos del disco, y potencialmente comprometer "
                    "otros sistemas usando las credenciales obtenidas."
                ),
            ))

        if (not svc_on or not rt_on) and pending > 10:
            alerts.append(self.build("critical",
                f"[CORRELACION] Defender desactivado + {pending} actualizaciones pendientes",
                "Sistema sin antimalware y con vulnerabilidades conocidas sin parchear.",
                "Activar Defender y aplicar parches de seguridad inmediatamente.",
                ["T1562.001 - Disable or Modify Tools", "T1190 - Exploit Public-Facing Application"],
                explanation=(
                    "El antivirus esta desactivado y hay vulnerabilidades conocidas sin parchear. "
                    "Esta combinacion elimina dos capas fundamentales de proteccion: la deteccion "
                    "de malware y la correccion de vulnerabilidades explotables."
                ),
                impact=(
                    "El sistema es vulnerable a exploits de vulnerabilidades conocidas que "
                    "el antivirus no puede detectar ni bloquear. Escenario ideal para ataques "
                    "de ransomware automatizados y explotacion de CVEs publicos."
                ),
            ))

        if rdp_on and nla_off and ntlm_lvl < 3:
            alerts.append(self.build("critical",
                f"[CORRELACION] RDP sin NLA + NTLM nivel {ntlm_lvl} — captura de hashes posible",
                "Atacante puede conectar sin NLA y capturar/degradar hashes NTLM.",
                "Habilitar NLA y configurar LmCompatibilityLevel=5.",
                ["T1021.001 - Remote Desktop Protocol", "T1550.002 - Pass the Hash"],
                explanation=(
                    "RDP esta activo sin NLA y el nivel NTLM es insuficiente. Sin NLA, cualquier "
                    "IP puede alcanzar la fase de autenticacion. Con NTLM debil, los hashes "
                    "capturados durante ese proceso pueden crackearse facilmente."
                ),
                impact=(
                    "Captura de hashes NTLM posible incluso sin autenticarse correctamente. "
                    "Los hashes LM/NTLMv1 se crackean offline con Hashcat en minutos, "
                    "obteniendo contrasenas en texto plano."
                ),
            ))

        if created > 0 and len(admins) > 3:
            alerts.append(self.build("critical",
                f"[CORRELACION] Cuenta nueva + {len(admins)} administradores activos",
                f"{created} cuenta(s) creada(s) con grupo Admins sobredimensionado.",
                "Auditar cuentas de administrador y validar la nueva cuenta.",
                ["T1136.001 - Create Account", "T1078.003 - Local Accounts"],
                explanation=(
                    "Se creo una nueva cuenta y el sistema tiene un numero elevado de cuentas "
                    "administrativas. La proliferacion de admins y la creacion inesperada de cuentas "
                    "son senales tipicas de post-explotacion."
                ),
                impact=(
                    "La nueva cuenta podria ser un backdoor creado por un atacante con acceso previo. "
                    "El exceso de cuentas admin amplifica el riesgo y dificulta el control de "
                    "acceso privilegiado."
                ),
            ))

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
                explanation=(
                    "NLA (Network Level Authentication) requiere que el usuario se autentique ANTES "
                    "de establecer la sesion RDP completa. Sin NLA, el servidor acepta conexiones y "
                    "muestra la pantalla de login a cualquier IP, exponiendo el servicio completo."
                ),
                impact=(
                    "Vulnerable a exploits pre-autenticacion como BlueKeep (CVE-2019-0708) que "
                    "permiten ejecucion remota de codigo sin credenciales. Facilita ataques de "
                    "fuerza bruta directa contra el servicio desde cualquier IP."
                ),
            ))

        if ntlm_level < 3:
            sev = "critical" if ntlm_level <= 1 else "high"
            findings.append(self.build(
                sev,
                f"Nivel de autenticacion NTLM inseguro (LmCompatibilityLevel={ntlm_level})",
                f"Nivel {ntlm_level} permite LM/NTLMv1, vulnerable a ataques pass-the-hash y captura de hashes.",
                "Configurar LmCompatibilityLevel=5 en gpedit.msc > Opciones de seguridad.",
                ["T1550.002 - Pass the Hash", "T1557 - Adversary-in-the-Middle"],
                explanation=(
                    "LmCompatibilityLevel determina que protocolos de autenticacion NTLM acepta Windows. "
                    f"El nivel {ntlm_level} permite protocolos obsoletos (LM/NTLMv1) con cifrado "
                    "debil que pueden ser crackeados en segundos con hardware moderno."
                ),
                impact=(
                    "Los hashes LM/NTLMv1 capturados en la red se crackean offline con Hashcat "
                    "en minutos. Tambien vulnerables a ataques Pass-the-Hash donde el hash "
                    "capturado se usa directamente sin necesidad de crackear la contrasena."
                ),
            ))

        if wdigest:
            findings.append(self.build(
                "critical",
                "WDigest habilitado: credenciales almacenadas en texto plano en memoria",
                "UseLogonCredential=1. Mimikatz puede volcar contrasenas directamente desde LSASS.",
                "Deshabilitar: HKLM\\...\\WDigest -> UseLogonCredential = 0",
                ["T1003.001 - LSASS Memory"],
                explanation=(
                    "WDigest es un protocolo de autenticacion heredado que, cuando esta habilitado, "
                    "hace que Windows almacene una copia de las contrasenas de los usuarios en texto "
                    "plano en la memoria del proceso LSASS del sistema."
                ),
                impact=(
                    "Con herramientas como Mimikatz, cualquier proceso con privilegios de "
                    "administrador puede extraer las contrasenas en texto plano de la RAM en "
                    "segundos. Es una de las tecnicas de post-explotacion mas utilizadas."
                ),
            ))

        if not cred_guard:
            findings.append(self.build(
                "medium",
                "Credential Guard no habilitado",
                "Sin Credential Guard, los hashes NTLM/Kerberos son vulnerables a volcado de credenciales.",
                "Habilitar Credential Guard en gpedit.msc (requiere TPM 2.0 + Secure Boot).",
                ["T1003 - OS Credential Dumping"],
                explanation=(
                    "Credential Guard usa virtualizacion hardware (VBS) para aislar los hashes de "
                    "credenciales (NTLM, Kerberos) en un entorno protegido separado del sistema "
                    "operativo, inaccesible para procesos con privilegios de administrador."
                ),
                impact=(
                    "Sin Credential Guard, los hashes NTLM y tickets Kerberos almacenados en "
                    "memoria son accesibles y vulnerables a herramientas de credential dumping "
                    "como Mimikatz, permitiendo lateral movement y escalada de privilegios."
                ),
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
                explanation=(
                    "Los ejecutables legitimos firmados digitalmente se ejecutan desde rutas estandar "
                    f"del sistema. Un proceso sin firma valida en {label} es inusual: "
                    + ("Temp y Roaming son rutas escribibles sin admin, tipicas para malware que "
                       "no puede instalarse en System32." if "appdata" in path else
                       "Downloads y Desktop son rutas de usuario donde frecuentemente se ejecutan "
                       "archivos de origen desconocido.")
                ),
                impact=(
                    "Puede indicar malware activo en ejecucion. "
                    + ("Alta probabilidad de payload malicioso: downloader, RAT, ransomware o "
                       "backdoor ejecutandose desde una ruta de escritura libre." if "appdata" in path else
                       "Riesgo moderado: requiere verificacion del origen. Puede ser un instalador "
                       "legitimo o un ejecutable descargado de fuente no confiable.")
                ),
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
                    ["T1059.001 - PowerShell"],
                    explanation=(
                        "Script Block Logging registra todos los bloques de codigo PowerShell ejecutados. "
                        "No se pudo acceder al log para verificar su estado, posiblemente por "
                        "restricciones de permisos."
                    ),
                    impact=(
                        "Sin acceso de verificacion, no se puede confirmar si los scripts PowerShell "
                        "se estan registrando. Los ataques basados en PowerShell podrian estar "
                        "ocurriendo sin dejar evidencia."
                    ),
                ))
            else:
                findings.append(self.build("medium",
                    "PowerShell Script Block Logging deshabilitado",
                    "No se pudieron leer logs de Microsoft-Windows-PowerShell/Operational.",
                    "Habilitar Script Block Logging via GPO: Administrative Templates > Windows PowerShell.",
                    ["T1059.001 - PowerShell"],
                    explanation=(
                        "Script Block Logging deberia estar habilitado como medida de auditoria basica. "
                        "Sin el, todos los scripts PowerShell que se ejecuten lo hacen sin dejar "
                        "ningun rastro en los logs del sistema."
                    ),
                    impact=(
                        "Los ataques basados en PowerShell (uno de los vectores mas usados) pasan "
                        "completamente desapercibidos. No hay evidencia de que scripts se ejecutaron, "
                        "con que parametros, que descargaron o que comandos ejecutaron."
                    ),
                ))
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
                 "T1105 - Ingress Tool Transfer"],
                explanation=(
                    "Script Block Logging detecto patrones asociados con tecnicas de ataque en PowerShell: "
                    "IEX/Invoke-Expression (ejecucion dinamica de codigo), DownloadString/WebClient "
                    "(descarga desde Internet), Base64 (ofuscacion para evadir deteccion)."
                ),
                impact=(
                    "Indica ejecucion de codigo potencialmente malicioso. "
                    + ("Con mas de 20 eventos, es muy probable actividad maliciosa activa: " if count > 20 else "")
                    + "puede ser parte de un ataque en progreso (descarga de payloads, "
                    "instalacion de backdoors, inicio de ransomware o exfiltracion de datos)."
                ),
            ))

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
                ["T1562.001 - Disable or Modify Tools"],
                explanation=(
                    "Windows Defender es el antivirus integrado de Windows, activo por defecto. "
                    "Cuando el servicio AMService esta detenido, no hay ningun analisis de "
                    "malware en el sistema, ni en tiempo real ni programado."
                ),
                impact=(
                    "Ejecucion sin obstaculos de cualquier malware conocido: ransomware, trojans, "
                    "backdoors, spyware. El sistema es incapaz de detectar, bloquear o eliminar "
                    "amenazas conocidas automaticamente."
                ),
            ))
            return findings

        if not rt_on:
            findings.append(self.build("critical",
                "Proteccion en tiempo real de Defender deshabilitada",
                "RealTimeProtectionEnabled=False. No se detectan amenazas en tiempo real.",
                "Habilitar proteccion en tiempo real en Seguridad de Windows.",
                ["T1562.001 - Disable or Modify Tools"],
                explanation=(
                    "La proteccion en tiempo real escanea los archivos en el momento en que se "
                    "accede a ellos, se descargan o ejecutan. Sin ella, el malware puede "
                    "copiarse y ejecutarse antes de ser analizado por Defender."
                ),
                impact=(
                    "Malware puede instalarse y ejecutarse sin ser bloqueado. El analisis "
                    "periodico (si esta configurado) solo detecta malware ya instalado, "
                    "no previene la infeccion inicial."
                ),
            ))

        if sig_age > 30:
            findings.append(self.build("high",
                f"Firmas de Defender muy desactualizadas ({sig_age} dias)",
                f"Definiciones de malware con {sig_age} dias de antiguedad.",
                "Ejecutar: Update-MpSignature o actualizar via Windows Update.",
                ["T1562.001 - Disable or Modify Tools"],
                explanation=(
                    "Las firmas de Defender son la base de datos de malware conocido que usa para "
                    "detectar amenazas. Se actualizan varias veces al dia. Con mas de 30 dias "
                    "sin actualizar, el catalogo de amenazas conocidas esta severamente desactualizado."
                ),
                impact=(
                    "Todas las variantes de malware, ransomware y trojans publicados en el "
                    "ultimo mes no son detectados. Los grupos de ransomware rotan sus muestras "
                    "precisamente para evadir firmas antiguas."
                ),
            ))
        elif sig_age > 7:
            findings.append(self.build("medium",
                f"Firmas de Defender desactualizadas ({sig_age} dias)",
                f"Definiciones con {sig_age} dias sin actualizar.",
                "Actualizar las definiciones de Defender.",
                ["T1562.001 - Disable or Modify Tools"],
                explanation=(
                    "Las firmas de Defender llevan mas de una semana sin actualizar. Microsoft "
                    "publica actualizaciones de firmas varias veces al dia para cubrir nuevas "
                    "amenazas y variantes de malware existente."
                ),
                impact=(
                    "Las variantes recientes de malware publicadas en los ultimos dias pueden "
                    "no ser detectadas. Mantener las firmas al dia es una de las medidas de "
                    "seguridad mas basicas y efectivas."
                ),
            ))

        if susp:
            findings.append(self.build("high",
                f"Exclusiones sospechosas en Defender: {len(susp)} ruta(s)",
                f"Rutas de riesgo excluidas del escaneo: {', '.join(susp[:5])}",
                "Eliminar exclusiones innecesarias de Defender.",
                ["T1562.001 - Disable or Modify Tools", "T1036 - Masquerading"],
                explanation=(
                    "Las exclusiones de Defender son rutas o procesos que el antivirus ignora "
                    "completamente. Son a veces necesarias para software legitimo, pero los "
                    "atacantes las abusan para dejar sus herramientas maliciosas fuera del "
                    "alcance del antivirus."
                ),
                impact=(
                    "El malware instalado en una ruta excluida es completamente invisible para "
                    "Defender. Tecnica comun de persistencia: instalar el payload en Temp o "
                    "AppData y anadir la ruta a las exclusiones para garantizar supervivencia."
                ),
            ))
        elif all_p or all_pr:
            findings.append(self.build("medium",
                f"Defender tiene {len(all_p)} ruta(s) y {len(all_pr)} proceso(s) excluidos",
                "Exclusiones activas que pueden ocultar amenazas.",
                "Auditar las exclusiones en Get-MpPreference.",
                ["T1562.001 - Disable or Modify Tools"],
                explanation=(
                    "Defender tiene exclusiones configuradas para rutas o procesos. Aunque pueden "
                    "ser necesarias para software legitimo, cada exclusion es una zona ciega "
                    "para el antivirus que un atacante podria explotar."
                ),
                impact=(
                    "Las exclusiones mal configuradas o innecesarias crean zonas donde el malware "
                    "puede operar sin deteccion. Requiere auditoria para verificar que todas "
                    "las exclusiones son legitimas y necesarias."
                ),
            ))

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

        _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "review": 4, "info": 5}
        findings.sort(key=lambda f: _order.get(f.get("severity", "info"), 5))

        _w = {"critical": 20, "high": 10, "medium": 3, "low": 1, "review": 0}
        raw = sum(_w.get(f.get("severity", "info"), 0) for f in findings)
        score = min(100, int(100 * (1 - math.exp(-raw / 60)))) if raw > 0 else 0

        return findings, score
