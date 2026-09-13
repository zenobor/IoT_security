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


def scan_ports(ip: str, arguments: str = "-sV") -> list[dict]:
    """Ritorna porte aperte e servizi/versioni rilevati su un IP."""
    try:
        import nmap
    except ImportError as exc:
        raise RuntimeError(
            "python-nmap non e installato. Esegui: pip install -r requirements.txt"
        ) from exc

    scanner = nmap.PortScanner()
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
