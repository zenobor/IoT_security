"""
fingerprint.py
Identifica vendor, servizi e versioni per ogni dispositivo trovato.
"""


def get_vendor(mac_address: str) -> str:
    """Ritorna il nome del produttore a partire dal MAC address (lookup OUI)."""
    # TODO: usare mac-vendor-lookup
    raise NotImplementedError


def scan_ports(ip: str) -> list[dict]:
    """Ritorna porte aperte e servizi/versioni rilevati su un IP."""
    # TODO: usare python-nmap con -sV
    raise NotImplementedError
