"""
services.py — Identificación de servicios: mapa puerto→servicio, grupos de puertos
comunes y "banner grabbing" ligero para refinar la detección.
"""

import socket

# Puertos comunes -> servicio por defecto
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5601: "kibana", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}

# Servicios de texto plano / riesgosos si quedan expuestos
RISKY_SERVICES = {
    "telnet": "Protocolo en texto plano (credenciales expuestas).",
    "ftp": "FTP suele ir en texto plano; preferir SFTP/FTPS.",
    "rdp": "Escritorio remoto expuesto: superficie común de fuerza bruta.",
    "smb": "SMB expuesto a Internet es un riesgo alto (ransomware/lateralización).",
    "vnc": "VNC expuesto: acceso remoto, a menudo mal autenticado.",
    "redis": "Redis sin auth por defecto: exposición crítica.",
    "mongodb": "MongoDB sin auth por defecto: exposición de datos.",
    "elasticsearch": "Elasticsearch expuesto: posible fuga de datos.",
    "docker": "API de Docker expuesta: equivale a acceso root remoto.",
}

# Grupos de puertos seleccionables
TOP_20 = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
          993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
TOP_50 = sorted(COMMON_PORTS.keys())


def ports_for(group: str) -> list[int]:
    group = (group or "top20").lower()
    if group == "top20":
        return TOP_20
    if group in ("top50", "common"):
        return TOP_50
    if group == "web":
        return [80, 443, 8000, 8080, 8443, 5601, 9200]
    # rango "1-1024" o lista "22,80,443"
    if "-" in group:
        a, b = group.split("-", 1)
        return list(range(int(a), int(b) + 1))
    return [int(p) for p in group.split(",") if p.strip()]


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """Intenta leer un banner. Para puertos web envía una petición HTTP mínima."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8000, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: scan\r\n\r\n")
            try:
                data = s.recv(256)
            except socket.timeout:
                return ""
            return data.decode("latin-1", "ignore").strip().splitlines()[0] if data else ""
    except Exception:
        return ""


def identify(port: int, banner: str) -> str:
    """Determina el servicio combinando el puerto y el banner."""
    svc = COMMON_PORTS.get(port, "desconocido")
    b = banner.lower()
    if b.startswith("ssh-"):
        return "ssh"
    if "http/" in b or b.startswith("server:"):
        return "https" if port in (443, 8443) else "http"
    if b.startswith("220") and "ftp" in b:
        return "ftp"
    if b.startswith("220") and ("smtp" in b or "esmtp" in b):
        return "smtp"
    return svc
