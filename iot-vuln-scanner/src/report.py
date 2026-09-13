"""
report.py
Genera il report finale (Markdown) con i risultati della scansione.
"""

from pathlib import Path


def _clean(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _test_summary(device: dict) -> list[str]:
    flags = device.get("iot_flags", {})
    checks = [
        "ARP: found",
        "Telnet: open" if flags.get("telnet_open") else "Telnet: closed",
        "UPnP: open" if flags.get("upnp_exposed") else "UPnP: not found",
        "Default credentials: review needed" if flags.get("default_credentials") else "Default credentials: no vendor match",
    ]
    if device.get("scan_errors"):
        checks.append("Nmap: unavailable")
    else:
        checks.append("Nmap: completed")
    return checks


def generate_report(devices: list[dict], output_path: str) -> None:
    """Scrive un report Markdown riassuntivo dei dispositivi e delle vulnerabilità trovate."""
    lines = [
        "# IoT Scan Report",
        "",
        f"Found **{len(devices)}** devices on the network.",
        "",
        "The scan finds devices with ARP, checks their network services with Nmap, "
        "and looks for common IoT security problems.",
        "",
    ]

    for device in devices:
        identity = device.get("identity", {})
        open_ports = [
            f"{port.get('port')} ({port.get('service', 'unknown')})"
            for port in device.get("ports", [])
            if port.get("state") == "open"
        ]
        lines.extend(
            [
                f"## {_clean(device.get('ip', 'unknown'))} - {_clean(identity.get('type', 'Unknown device'))}",
                f"**Vendor:** {_clean(identity.get('vendor', 'Unknown vendor'))}  ",
                f"**Model:** {_clean(identity.get('model', 'Unknown model'))}  ",
                f"**Risk:** {_clean(device.get('risk', 'low').upper())}  ",
                f"**Open ports:** {_clean(', '.join(open_ports) or 'none detected')}",
                "",
                f"**Checks:** {_clean('; '.join(_test_summary(device)))}",
            ]
        )
        vulnerabilities = device.get("vulnerabilities", [])
        if vulnerabilities:
            lines.extend(["", "**Possible vulnerabilities:**"])
            for vulnerability in vulnerabilities:
                lines.append(
                    f"- {vulnerability.get('id', 'CVE-unknown')}: "
                    f"{_clean(vulnerability.get('description', ''))}"
                )
        lines.append("")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
