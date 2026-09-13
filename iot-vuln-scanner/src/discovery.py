"""
discovery.py
Trova i dispositivi attivi sulla rete locale (scansione ARP).
"""

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def scan_network(ip_range: str, timeout: int = 2) -> list[dict[str, str]]:
    """
    Scansiona la rete e ritorna una lista di dispositivi trovati.

    Args:
        ip_range: es. "192.168.1.0/24"
        timeout: secondi di attesa per le risposte ARP

    Returns:
        Lista di dict, es: [{"ip": "192.168.1.5", "mac": "AA:BB:CC:..."}]
    """
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(request, timeout=timeout, verbose=False)

    return [
        {"ip": received.psrc, "mac": received.hwsrc}
        for _, received in answered
    ]
