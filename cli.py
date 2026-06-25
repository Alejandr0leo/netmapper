"""
cli.py — Escáner de red por terminal.

Uso:
    python cli.py 192.168.1.0/24
    python cli.py 127.0.0.1 --ports top50 --markdown reporte.md
    python cli.py scanme.example.com --ports 22,80,443 --authorized

Por seguridad, los objetivos públicos requieren --authorized (ver netmapper/safety.py).
"""

import argparse
import os
import sys

from netmapper import scan, expand_targets, guard_targets, AuthorizationError
from netmapper.services import ports_for
from netmapper.report import to_markdown, to_json, attack_surface

GREEN, RED, YEL, DIM, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[90m", "\033[0m"


def main():
    ap = argparse.ArgumentParser(description="NetMapper — escáner de red y mapa de activos")
    ap.add_argument("target", help="IP, CIDR (192.168.1.0/24) o hostname")
    ap.add_argument("--ports", default="top20", help="top20 | top50 | web | 1-1024 | 22,80,443")
    ap.add_argument("--timeout", type=float, default=0.8)
    ap.add_argument("--no-discovery", action="store_true", help="escanear sin descubrir hosts primero")
    ap.add_argument("--no-banners", action="store_true")
    ap.add_argument("--authorized", action="store_true", help="declaro autorización para objetivos públicos")
    ap.add_argument("--json", help="guardar reporte JSON")
    ap.add_argument("--markdown", help="guardar reporte Markdown")
    args = ap.parse_args()

    ips = expand_targets(args.target)
    try:
        guard_targets(ips, args.authorized)
    except AuthorizationError as e:
        print(f"{RED}[BLOQUEADO]{RESET} {e}", file=sys.stderr)
        sys.exit(2)

    ports = ports_for(args.ports)
    print(f"Objetivo: {args.target}  ·  {len(ips)} IP(s)  ·  {len(ports)} puerto(s) por host\n")

    hosts = scan(ips, ports, discover=not args.no_discovery,
                 timeout=args.timeout, banners=not args.no_banners)

    if not hosts:
        print("No se detectaron hosts vivos / puertos abiertos.")
        return

    for h in hosts:
        print(f"{GREEN}●{RESET} {h.ip}  ({len(h.open_ports)} abierto/s)")
        for p in h.open_ports:
            extra = f"  {DIM}{p.banner}{RESET}" if p.banner else ""
            print(f"    {p.port:>5}/tcp  {p.service}{extra}")
        print()

    surf = attack_surface(hosts)
    print(f"Resumen: {surf['hosts_vivos']} host(s), {surf['puertos_abiertos']} puerto(s) abierto(s).")
    if surf["exposiciones_notables"]:
        print(f"{YEL}⚠ {len(surf['exposiciones_notables'])} exposición(es) notable(s):{RESET}")
        for e in surf["exposiciones_notables"]:
            print(f"    {e['ip']}:{e['port']} ({e['service']}) — {e['motivo']}")

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        open(args.json, "w").write(to_json(hosts))
        print(f"\nReporte JSON: {args.json}")
    if args.markdown:
        os.makedirs(os.path.dirname(args.markdown) or ".", exist_ok=True)
        open(args.markdown, "w").write(to_markdown(hosts))
        print(f"Reporte Markdown: {args.markdown}")


if __name__ == "__main__":
    main()
