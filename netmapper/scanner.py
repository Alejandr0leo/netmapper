"""
scanner.py — Descubrimiento de hosts y escaneo de puertos por TCP connect, usando
solo la librería estándar (sockets) con concurrencia vía hilos.

Nota: TCP connect scan no requiere privilegios de root. Para cada puerto:
  - conexión exitosa  -> 'open'
  - conexión rechazada -> 'closed' (host vivo)
  - timeout            -> 'filtered'
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .services import grab_banner, identify

DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 8080]


@dataclass
class PortInfo:
    port: int
    service: str
    banner: str = ""


@dataclass
class HostInfo:
    ip: str
    up: bool = False
    open_ports: list[PortInfo] = field(default_factory=list)


def expand_targets(spec: str) -> list[str]:
    """Convierte un objetivo (IP, CIDR o hostname) en una lista de IPs."""
    spec = spec.strip()
    try:
        net = ipaddress.ip_network(spec, strict=False)
        if net.num_addresses > 1:
            return [str(h) for h in net.hosts()]
        return [str(net.network_address)]
    except ValueError:
        pass
    # hostname -> resolver
    try:
        return [socket.gethostbyname(spec)]
    except socket.gaierror:
        return [spec]  # se dejará y fallará en el escaneo si no resuelve


def _probe(ip: str, port: int, timeout: float) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        rc = sock.connect_ex((ip, port))
        if rc == 0:
            return "open"
        # ECONNREFUSED => host vivo, puerto cerrado
        return "closed" if rc in (111, 61, 10061) else "filtered"
    except (socket.timeout, OSError):
        return "filtered"
    finally:
        sock.close()


def discover_hosts(ips: list[str], timeout: float = 0.6, workers: int = 100) -> list[str]:
    """Determina qué hosts están vivos probando algunos puertos comunes."""
    def alive(ip: str) -> str | None:
        for port in DISCOVERY_PORTS:
            if _probe(ip, port, timeout) in ("open", "closed"):
                return ip
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        return [ip for ip in ex.map(alive, ips) if ip]


def scan_host(ip: str, ports: list[int], timeout: float = 0.8,
              workers: int = 200, banners: bool = True) -> HostInfo:
    """Escanea los puertos de un host y devuelve los abiertos con su servicio."""
    host = HostInfo(ip=ip)

    def check(port: int) -> PortInfo | None:
        if _probe(ip, port, timeout) == "open":
            banner = grab_banner(ip, port) if banners else ""
            return PortInfo(port=port, service=identify(port, banner), banner=banner)
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for pi in ex.map(check, ports):
            if pi:
                host.open_ports.append(pi)
    host.open_ports.sort(key=lambda p: p.port)
    host.up = bool(host.open_ports)
    return host


def scan(targets: list[str], ports: list[int], discover: bool = True,
         timeout: float = 0.8, banners: bool = True) -> list[HostInfo]:
    """Flujo completo: (descubrir hosts) -> escanear puertos de cada host vivo."""
    live = discover_hosts(targets, timeout=min(timeout, 0.6)) if discover else targets
    results = []
    for ip in live:
        host = scan_host(ip, ports, timeout=timeout, banners=banners)
        if host.open_ports or not discover:
            host.up = True
            results.append(host)
    return results
