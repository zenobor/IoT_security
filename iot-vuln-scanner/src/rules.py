"""
rules.py
Controlli specifici per pattern di insicurezza comuni nei dispositivi IoT.
"""

import json
from pathlib import Path


DEFAULT_CREDS_PATH = Path(__file__).parents[1] / "data" / "default_creds.json"

def check_telnet_open(open_ports: list[int]) -> bool:
    """Ritorna True se la porta Telnet (23) è aperta."""
    return 23 in open_ports


def check_default_credentials(vendor: str, ip: str) -> bool:
    """Segnala se esistono credenziali di default note per il vendor.

    This check does not attempt a login. It only flags a device for review.
    """
    del ip
    try:
        with DEFAULT_CREDS_PATH.open(encoding="utf-8") as file:
            credentials = json.load(file)
    except (OSError, json.JSONDecodeError):
        return False

    normalized_vendor = vendor.strip().lower()
    has_vendor_credentials = any(
        name in normalized_vendor or normalized_vendor in name
        for name in credentials
        if name != "generic"
    )
    return has_vendor_credentials or normalized_vendor in {"unknown", "generic"}


def check_upnp_exposed(open_ports: list[int]) -> bool:
    """Ritorna True se UPnP (porta 1900/5000) risulta esposto."""
    return any(p in open_ports for p in (1900, 5000))
