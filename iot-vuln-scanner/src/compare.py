"""
compare.py
Compares two saved scans (JSON) to see what changed on the network.
"""


def _device_key(device: dict) -> str:
    # The MAC is more stable than the IP (DHCP can give a device a new IP).
    mac = str(device.get("mac", "unknown")).lower()
    return mac if mac != "unknown" else device.get("ip", "")


def _open_ports(device: dict) -> set[int]:
    return {port.get("port") for port in device.get("ports", []) if port.get("state") == "open"}


def compare_scans(old_scan: dict, new_scan: dict) -> dict:
    """Returns new/missing devices, ports that opened/closed and risk changes."""
    old_devices = {_device_key(device): device for device in old_scan.get("devices", [])}
    new_devices = {_device_key(device): device for device in new_scan.get("devices", [])}

    changes = []
    # devices that are in both scans: check if something is different
    for key in sorted(old_devices.keys() & new_devices.keys()):
        old, new = old_devices[key], new_devices[key]
        opened = sorted(_open_ports(new) - _open_ports(old))
        closed = sorted(_open_ports(old) - _open_ports(new))
        old_risk, new_risk = old.get("risk", "low"), new.get("risk", "low")
        if opened or closed or old_risk != new_risk or old.get("ip") != new.get("ip"):
            changes.append(
                {
                    "ip": new.get("ip"),
                    "old_ip": old.get("ip"),
                    "type": new.get("identity", {}).get("type", "Unknown device"),
                    "opened_ports": opened,
                    "closed_ports": closed,
                    "old_risk": old_risk,
                    "new_risk": new_risk,
                }
            )

    return {
        "old_date": old_scan.get("scan", {}).get("started_at", "unknown"),
        "new_date": new_scan.get("scan", {}).get("started_at", "unknown"),
        "old_score": old_scan.get("scan", {}).get("network_score"),
        "new_score": new_scan.get("scan", {}).get("network_score"),
        "new_devices": [new_devices[key] for key in sorted(new_devices.keys() - old_devices.keys())],
        "missing_devices": [old_devices[key] for key in sorted(old_devices.keys() - new_devices.keys())],
        "changed_devices": changes,
    }


def has_changes(diff: dict) -> bool:
    return bool(diff["new_devices"] or diff["missing_devices"] or diff["changed_devices"])
