"""
report.py — Genera el inventario de activos, el resumen de superficie de ataque
y los reportes en Markdown / JSON.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .scanner import HostInfo
from .services import RISKY_SERVICES


def attack_surface(hosts: list[HostInfo]) -> dict:
    """Resume la superficie de ataque: totales y exposiciones notables."""
    total_ports = sum(len(h.open_ports) for h in hosts)
    risky = []
    for h in hosts:
        for p in h.open_ports:
            if p.service in RISKY_SERVICES:
                risky.append({"ip": h.ip, "port": p.port, "service": p.service,
                              "motivo": RISKY_SERVICES[p.service]})
    return {
        "hosts_vivos": len(hosts),
        "puertos_abiertos": total_ports,
        "exposiciones_notables": risky,
    }


def to_json(hosts: list[HostInfo]) -> str:
    payload = {
        "resumen": attack_surface(hosts),
        "hosts": [asdict(h) for h in hosts],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def to_markdown(hosts: list[HostInfo]) -> str:
    surf = attack_surface(hosts)
    lines = [
        "# Inventario de activos — NetMapper", "",
        f"- Hosts vivos: **{surf['hosts_vivos']}**",
        f"- Puertos abiertos: **{surf['puertos_abiertos']}**",
        f"- Exposiciones notables: **{len(surf['exposiciones_notables'])}**",
        "",
    ]
    if surf["exposiciones_notables"]:
        lines += ["## ⚠️ Exposiciones notables", "",
                  "| Host | Puerto | Servicio | Motivo |", "|---|---|---|---|"]
        for e in surf["exposiciones_notables"]:
            lines.append(f"| {e['ip']} | {e['port']} | {e['service']} | {e['motivo']} |")
        lines.append("")

    lines += ["## Hosts y servicios", ""]
    for h in hosts:
        lines.append(f"### {h.ip}  ({len(h.open_ports)} puerto(s) abierto(s))")
        if not h.open_ports:
            lines.append("- Sin puertos abiertos detectados.")
        for p in h.open_ports:
            extra = f" — `{p.banner}`" if p.banner else ""
            lines.append(f"- **{p.port}/tcp** · {p.service}{extra}")
        lines.append("")
    return "\n".join(lines)
