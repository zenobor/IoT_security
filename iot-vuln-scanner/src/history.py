"""Save scan history and compare the current network with the last scan."""

import json
from datetime import datetime, timezone
from pathlib import Path


def _device_snapshot(device: dict) -> dict:
    identity = device.get("identity", {})
    return {
        "ip": device.get("ip", ""),
        "mac": device.get("mac", ""),
        "vendor": identity.get("vendor", device.get("vendor", "Unknown")),
        "type": identity.get("type", "Unknown device"),
        "model": identity.get("model", "Unknown model"),
        "risk": device.get("risk", "low"),
        "open_ports": sorted(
            port.get("port")
            for port in device.get("ports", [])
            if port.get("state") == "open"
        ),
    }


def compare_with_history(devices: list[dict], history_path: str) -> dict:
    """Return new, removed and changed devices compared with the last scan."""
    path = Path(history_path)
    current = [_device_snapshot(device) for device in devices]
    previous_data = {}
    if path.exists():
        try:
            previous_data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            previous_data = {}

    previous = {
        device.get("ip"): device
        for device in previous_data.get("devices", [])
        if device.get("ip")
    }
    current_by_ip = {device["ip"]: device for device in current if device.get("ip")}

    return {
        "new_devices": [ip for ip in current_by_ip if ip not in previous],
        "removed_devices": [ip for ip in previous if ip not in current_by_ip],
        "changed_devices": [
            ip
            for ip in current_by_ip
            if ip in previous and current_by_ip[ip] != previous[ip]
        ],
    }


def save_history(devices: list[dict], history_path: str) -> None:
    """Save a small JSON snapshot for comparison with the next scan."""
    path = Path(history_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "devices": [_device_snapshot(device) for device in devices],
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")