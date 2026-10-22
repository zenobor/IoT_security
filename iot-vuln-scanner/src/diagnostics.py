"""
diagnostics.py
Checks that the computer is ready to scan (used by "python main.py doctor"),
plus the network-wide checks that are shown once per scan.
"""

import ctypes
import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def find_nmap() -> str | None:
    """Returns the path of nmap, also looking in the default Windows install folders."""
    nmap_path = shutil.which("nmap")
    if nmap_path:
        return nmap_path
    for candidate in (
        Path(r"C:\Program Files\Nmap\nmap.exe"),
        Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
    ):
        if candidate.exists():
            return str(candidate)
    return None


def is_admin() -> bool:
    """True when running as Administrator (Windows) or root (Linux/macOS)."""
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def _run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
    return result.stdout or ""


def _check_nmap() -> dict[str, str]:
    nmap_path = find_nmap()
    if not nmap_path:
        return {"name": "Nmap", "status": "MISSING", "details": "Install Nmap from nmap.org and reopen the terminal."}
    try:
        first_line = _run([nmap_path, "--version"]).strip().splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError):
        first_line = ""
    details = f"{first_line} ({nmap_path})" if first_line.lower().startswith("nmap") else nmap_path
    return {"name": "Nmap", "status": "OK", "details": details}


def _check_npcap() -> dict[str, str]:
    if sys.platform != "win32":
        return {"name": "Npcap", "status": "OK", "details": "Not needed on this OS (libpcap is used)."}
    try:
        service_text = _run(["sc.exe", "query", "npcap"]).upper()
    except (OSError, subprocess.SubprocessError) as exc:
        return {"name": "Npcap", "status": "UNKNOWN", "details": str(exc)}
    if "RUNNING" in service_text:
        return {"name": "Npcap", "status": "OK", "details": "Npcap service is running."}
    if "STOPPED" in service_text:
        return {"name": "Npcap", "status": "WARNING", "details": "Npcap is installed but stopped."}
    return {"name": "Npcap", "status": "MISSING", "details": "Install Npcap (it comes with the Nmap installer)."}


def _check_admin() -> dict[str, str]:
    if is_admin():
        return {"name": "Admin rights", "status": "OK", "details": "Running with administrator/root rights."}
    hint = "Open the terminal with 'Run as administrator'." if sys.platform == "win32" else "Run with sudo."
    return {
        "name": "Admin rights",
        "status": "WARNING",
        "details": f"ARP discovery and Nmap work best with admin rights. {hint}",
    }


def _check_packages() -> dict[str, str]:
    modules = {"scapy": "scapy", "nmap": "python-nmap", "mac_vendor_lookup": "mac-vendor-lookup", "requests": "requests", "rich": "rich"}
    missing = [package for module, package in modules.items() if importlib.util.find_spec(module) is None]
    if missing:
        return {
            "name": "Python packages",
            "status": "MISSING",
            "details": f"Missing: {', '.join(missing)}. Run: pip install -r requirements.txt",
        }
    return {"name": "Python packages", "status": "OK", "details": "All required packages are installed."}


def check_system() -> list[dict[str, str]]:
    """Returns readable diagnostics without changing anything on the system."""
    return [
        _check_nmap(),
        _check_npcap(),
        _check_admin(),
        _check_packages(),
        check_wifi_security(),
    ]


def check_wifi_security() -> dict[str, str]:
    """Inspects the current Windows Wi-Fi connection (not the whole access point policy)."""
    if sys.platform != "win32":
        return {"name": "Wi-Fi security", "status": "MANUAL", "details": "Check the router for WPA2/WPA3."}
    try:
        text = _run(["netsh", "wlan", "show", "interfaces"])
    except (OSError, subprocess.SubprocessError) as exc:
        return {"name": "Wi-Fi security", "status": "MANUAL", "details": f"Could not inspect the Wi-Fi connection: {exc}"}

    # netsh is translated on non-English Windows, so we also accept the Italian names.
    keys = {"authentication": "authentication", "autenticazione": "authentication", "cipher": "cipher", "crittografia": "cipher"}
    settings = {}
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        key = keys.get(name.strip().lower())
        if separator and key:
            # The translated netsh output sometimes glues the next field name to the value.
            value = re.split(r"cipher|crittografia", value, flags=re.IGNORECASE)[0]
            settings[key] = " ".join(value.split())
    authentication = settings.get("authentication", "")
    cipher = settings.get("cipher", "")
    auth_lower, cipher_lower = authentication.lower(), cipher.lower()

    if not authentication:
        return {"name": "Wi-Fi security", "status": "MANUAL", "details": "No active Wi-Fi connection found (cable?)."}
    if auth_lower in ("open", "aperta") or "wep" in auth_lower or "wep" in cipher_lower or "tkip" in cipher_lower:
        return {
            "name": "Wi-Fi security",
            "status": "WARNING",
            "details": f"The current Wi-Fi uses weak or no encryption ({authentication} / {cipher or '?'}).",
        }
    if "wpa3" in auth_lower or "wpa2" in auth_lower:
        return {"name": "Wi-Fi security", "status": "OK", "details": f"The current connection uses {authentication}."}
    return {"name": "Wi-Fi security", "status": "MANUAL", "details": "Wi-Fi authentication could not be classified automatically."}


def network_checks() -> list[dict[str, str]]:
    """Checks about the whole network that are shown once in the report (not per device)."""
    return [
        check_wifi_security(),
        {
            "name": "IoT / guest isolation",
            "status": "MANUAL",
            "details": "Put IoT devices on a guest or separate network (VLAN) so they can't reach your PC.",
        },
        {
            "name": "Passwords",
            "status": "MANUAL",
            "details": "No passwords were tested. Make sure every device and the router use a unique password.",
        },
        {
            "name": "Firmware updates",
            "status": "MANUAL",
            "details": "Turn on automatic updates in the router and in the apps of your smart devices.",
        },
    ]
