"""
fingerprint.py
Identifica vendor, servizi e versioni per ogni dispositivo trovato.
"""


def get_vendor(mac_address: str) -> str:
    """Ritorna il nome del produttore a partire dal MAC address (lookup OUI)."""
    try:
        from mac_vendor_lookup import MacLookup

        return MacLookup().lookup(mac_address)
    except Exception:
        return "Unknown"


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


def scan_ports(ip: str, arguments: str = "-sV") -> list[dict]:
    """Ritorna porte aperte e servizi/versioni rilevati su un IP."""
    try:
        import nmap
    except ImportError as exc:
        raise RuntimeError(
            "python-nmap non e installato. Esegui: pip install -r requirements.txt"
        ) from exc

    try:
        scanner = nmap.PortScanner()
    except nmap.nmap.PortScannerError as exc:
        raise RuntimeError(
            "Nmap program was not found. Install Nmap and reopen PowerShell."
        ) from exc
    scanner.scan(hosts=ip, arguments=arguments)

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
