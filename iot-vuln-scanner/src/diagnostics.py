"""Checks for local tools required by the scanner."""

import shutil
import subprocess
from pathlib import Path


def check_system() -> list[dict[str, str]]:
    """Return readable Nmap and Npcap diagnostics without changing the system."""
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        for candidate in (
            Path(r"C:\Program Files\Nmap\nmap.exe"),
            Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
        ):
            if candidate.exists():
                nmap_path = str(candidate)
                break

    checks = [
        {
            "name": "Nmap",
            "status": "OK" if nmap_path else "MISSING",
            "details": nmap_path or "Install Nmap and add it to PATH.",
        }
    ]
    try:
        result = subprocess.run(
            ["sc.exe", "query", "npcap"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        service_text = result.stdout.upper()
        if "RUNNING" in service_text:
            status, details = "OK", "Npcap service is running."
        elif "STOPPED" in service_text:
            status, details = "WARNING", "Npcap is installed but stopped."
        else:
            status, details = "MISSING", "Npcap service was not found."
    except (OSError, subprocess.SubprocessError) as exc:
        status, details = "UNKNOWN", str(exc)
    checks.append({"name": "Npcap", "status": status, "details": details})
    checks.append(_check_wifi_security())
    checks.append(
        {
            "name": "VLAN / guest isolation",
            "status": "MANUAL",
            "details": "Check guest and IoT isolation in the router or managed switch.",
        }
    )
    return checks


def _check_wifi_security() -> dict[str, str]:
    """Inspect the current Windows Wi-Fi connection, not the whole AP policy."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "name": "Wi-Fi security",
            "status": "MANUAL",
            "details": f"Could not inspect the Wi-Fi connection: {exc}",
        }

    text = result.stdout.lower()
    if not text.strip():
        return {
            "name": "Wi-Fi security",
            "status": "MANUAL",
            "details": "No active Windows Wi-Fi interface was found.",
        }
    if any(value in text for value in ("wep", "open system", "tkip")):
        return {
            "name": "Wi-Fi security",
            "status": "WARNING",
            "details": "The current Wi-Fi connection may use weak or open security.",
        }
    if "wpa3" in text or "wpa2" in text:
        return {
            "name": "Wi-Fi security",
            "status": "OK",
            "details": "The current connection reports WPA2/WPA3.",
        }
    return {
        "name": "Wi-Fi security",
        "status": "MANUAL",
        "details": "Wi-Fi authentication could not be classified automatically.",
    }