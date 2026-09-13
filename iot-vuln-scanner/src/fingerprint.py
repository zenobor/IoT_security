"""
fingerprint.py
Identifica vendor, servizi e versioni per ogni dispositivo trovato.
"""

import os
import socket


def _create_scanner(nmap):
    search_paths = [
        path
        for path in (
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
        )
        if os.path.exists(path)
    ]
    return nmap.PortScanner(nmap_search_path=tuple(search_paths))


def get_vendor(mac_address: str) -> str:
    """Ritorna il nome del produttore a partire dal MAC address (lookup OUI)."""
    try:
        from mac_vendor_lookup import MacLookup

        return MacLookup().lookup(mac_address)
    except Exception:
        return "Unknown"


def get_hostname(ip: str) -> str:
    """Try to resolve a friendly hostname without failing the scan."""
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(1)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return "Unknown hostname"
    finally:
        socket.setdefaulttimeout(previous_timeout)


def identify_device(vendor: str, ports: list[dict]) -> dict[str, str]:
    """Build a readable device identity from vendor and detected services."""
    services = {
        str(port.get("service", "")).lower()
        for port in ports
        if port.get("state") == "open"
    }
    products = [
        str(port.get("product", "")).strip()
        for port in ports
        if port.get("product")
    ]
    versions = [
        str(port.get("version", "")).strip()
        for port in ports
        if port.get("version")
    ]
    vendor_name = vendor if vendor and vendor != "Unknown" else "Unknown vendor"
    model = products[0] if products else "Unknown model"

    if "rtsp" in services or 554 in {port.get("port") for port in ports}:
        device_type = "IP camera"
    elif "ssh" in services and ("http" in services or "https" in services):
        device_type = "Network device or IoT gateway"
    elif "http" in services or "https" in services:
        device_type = "Web-enabled IoT device"
    elif "ipp" in services or 9100 in {port.get("port") for port in ports}:
        device_type = "Network printer"
    elif "smb" in services or 445 in {port.get("port") for port in ports}:
        device_type = "Network storage or computer"
    else:
        device_type = "Unknown network device"

    return {
        "type": device_type,
        "vendor": vendor_name,
        "model": model,
        "version": versions[0] if versions else "Unknown version",
        "confidence": "service-based estimate" if not products else "Nmap service match",
    }


def scan_ports(
    ip: str,
    port_spec: str | None = None,
    mode: str = "quick",
) -> list[dict]:
    """Ritorna porte aperte e servizi/versioni rilevati su un IP."""
    try:
        import nmap
    except ImportError as exc:
        raise RuntimeError(
            "python-nmap non e installato. Esegui: pip install -r requirements.txt"
        ) from exc

    try:
        scanner = _create_scanner(nmap)
    except nmap.nmap.PortScannerError as exc:
        raise RuntimeError(
            "Nmap program was not found. Install Nmap and reopen PowerShell."
        ) from exc
    if port_spec:
        arguments = f"-T4 -p {port_spec} --version-light --host-timeout 15s"
    elif mode == "full":
        arguments = "-T4 --top-ports 1000 --version-light --host-timeout 30s"
    else:
        arguments = "-T4 --top-ports 100 --version-light --host-timeout 15s"
    try:
        scanner.scan(hosts=ip, arguments=arguments)
    except nmap.nmap.PortScannerError as exc:
        raise RuntimeError(f"Nmap port scan failed for {ip}: {exc}") from exc

    if ip not in scanner.all_hosts():
        return []

    ports = []
    for protocol in scanner[ip].all_protocols():
        for port in sorted(scanner[ip][protocol]):
            service = scanner[ip][protocol][port]
            ports.append(
                {
                    "port": port,
                    "protocol": protocol,
                    "state": service.get("state", "unknown"),
                    "service": service.get("name", "unknown"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                }
            )

    return ports
