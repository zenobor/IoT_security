"""
rules.py
Controlli specifici per pattern di insicurezza comuni nei dispositivi IoT.
"""


def check_telnet_open(open_ports: list[int]) -> bool:
    """Ritorna True se la porta Telnet (23) è aperta."""
    return 23 in open_ports


def check_default_credentials(vendor: str, ip: str) -> bool:
    """Prova credenziali di default note per il vendor (da data/default_creds.json)."""
    # TODO: caricare data/default_creds.json e testare login
    raise NotImplementedError


def check_upnp_exposed(open_ports: list[int]) -> bool:
    """Ritorna True se UPnP (porta 1900/5000) risulta esposto."""
    return any(p in open_ports for p in (1900, 5000))
