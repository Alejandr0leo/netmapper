"""NetMapper — escáner de red y mapa de activos (TCP connect, solo stdlib)."""
from .scanner import scan, scan_host, discover_hosts, expand_targets, HostInfo, PortInfo
from .safety import guard_targets, is_lab_target, AuthorizationError

__all__ = ["scan", "scan_host", "discover_hosts", "expand_targets",
           "HostInfo", "PortInfo", "guard_targets", "is_lab_target", "AuthorizationError"]
__version__ = "0.1.0"
