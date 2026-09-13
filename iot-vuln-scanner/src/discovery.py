"""
discovery.py
Trova i dispositivi attivi sulla rete locale (scansione ARP).
"""


def scan_network(ip_range: str) -> list[dict]:
    """
    Scansiona la rete e ritorna una lista di dispositivi trovati.

    Args:
        ip_range: es. "192.168.1.0/24"

    Returns:
        Lista di dict, es: [{"ip": "192.168.1.5", "mac": "AA:BB:CC:..."}]
    """
    # TODO: implementare con Scapy (ARP request/response)
    raise NotImplementedError
