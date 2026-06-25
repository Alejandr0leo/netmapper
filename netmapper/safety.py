"""
safety.py — Guardrail de alcance. NetMapper está pensado para auditar SOLO redes
propias o con autorización explícita. Por defecto únicamente permite objetivos
privados/de laboratorio (RFC1918, loopback, link-local). Cualquier objetivo público
exige confirmación explícita de autorización.
"""

import ipaddress


class AuthorizationError(Exception):
    """Se intentó escanear un objetivo público sin declarar autorización."""


def is_lab_target(ip: str) -> bool:
    """True si la IP pertenece a un rango privado/loopback/link-local (lab)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def guard_targets(ips: list[str], authorized: bool) -> None:
    """Lanza AuthorizationError si hay objetivos públicos y no se declaró autorización."""
    public = [ip for ip in ips if not is_lab_target(ip)]
    if public and not authorized:
        muestra = ", ".join(public[:5]) + ("..." if len(public) > 5 else "")
        raise AuthorizationError(
            "Objetivos públicos detectados (" + muestra + ").\n"
            "NetMapper solo debe usarse en redes propias o con autorización explícita.\n"
            "Si tienes permiso por escrito, vuelve a ejecutar con --authorized."
        )
