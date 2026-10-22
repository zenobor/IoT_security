"""
rules.py
Simple checks for insecure patterns that are common on IoT devices.
"""

import json
import re
from pathlib import Path


DEFAULT_CREDS_PATH = Path(__file__).parents[1] / "data" / "default_creds.json"


def check_telnet_open(open_ports: list[int]) -> bool:
    """Returns True if Telnet is open (23, or 2323 which a lot of cheap IoT devices use)."""
    return 23 in open_ports or 2323 in open_ports


def check_ftp_open(open_ports: list[int]) -> bool:
    """Returns True when the unencrypted FTP port is open."""
    return 21 in open_ports


def check_ssh_open(open_ports: list[int]) -> bool:
    """Returns True when SSH is exposed to the scanned network."""
    return 22 in open_ports


def check_insecure_http(open_ports: list[int]) -> bool:
    """Returns True when HTTP is open without HTTPS being detected."""
    return 80 in open_ports and 443 not in open_ports


def check_upnp_exposed(open_ports: list[int], answered_ssdp: bool = False) -> bool:
    """Returns True if the device answered our SSDP discovery or has port 1900 open."""
    # UPnP discovery is UDP, but Nmap only scans TCP here, so the SSDP answer
    # is the real test. Port 5000 was removed: Synology and AirPlay use it too.
    return answered_ssdp or 1900 in open_ports


def check_adb_open(open_ports: list[int]) -> bool:
    """Returns True if Android Debug Bridge (5555) is open. Anyone on the LAN could control the device."""
    return 5555 in open_ports


def check_tr069_open(open_ports: list[int]) -> bool:
    """Returns True if the TR-069 remote management port (7547) is open (usually ISP routers)."""
    return 7547 in open_ports


def check_rtsp_open(open_ports: list[int]) -> bool:
    """Returns True if an RTSP video stream port is open (cameras, baby monitors, NVRs)."""
    return 554 in open_ports or 8554 in open_ports


def check_mqtt_open(open_ports: list[int]) -> bool:
    """Returns True if an MQTT broker listens on the unencrypted port 1883."""
    return 1883 in open_ports


def _load_default_creds() -> dict:
    try:
        with DEFAULT_CREDS_PATH.open(encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}


def check_default_credentials(vendor: str, ip: str | None = None) -> bool:
    """Flags the device if its vendor is known for shipping default passwords.

    This check never tries to log in. It only tells the user to double check the password.
    """
    del ip
    normalized_vendor = vendor.strip().lower()
    # Before this check every "Unknown" device was flagged, which made almost
    # every phone look risky. No vendor = we can't say anything.
    if not normalized_vendor or normalized_vendor.startswith(("unknown", "private")):
        return False

    # \b = whole word, otherwise "axis" would also match "Maxis"
    return any(
        re.search(rf"\b{re.escape(name)}\b", normalized_vendor)
        for name in _load_default_creds()
        if name != "generic" and not name.startswith("_")
    )


def evaluate_rules(open_ports: list[int], vendor: str, answered_ssdp: bool = False) -> dict[str, bool]:
    """Runs every rule and returns the flags used by scoring and reports."""
    return {
        "telnet_open": check_telnet_open(open_ports),
        "ftp_open": check_ftp_open(open_ports),
        "ssh_open": check_ssh_open(open_ports),
        "insecure_http": check_insecure_http(open_ports),
        "upnp_exposed": check_upnp_exposed(open_ports, answered_ssdp),
        "adb_open": check_adb_open(open_ports),
        "tr069_open": check_tr069_open(open_ports),
        "rtsp_open": check_rtsp_open(open_ports),
        "mqtt_open": check_mqtt_open(open_ports),
        "default_credentials": check_default_credentials(vendor),
    }
