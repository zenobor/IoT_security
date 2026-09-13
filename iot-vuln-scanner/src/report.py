"""
report.py
Genera il report finale (Markdown) con i risultati della scansione.
"""

from pathlib import Path
import json


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


def _recommendations(device: dict) -> list[str]:
    flags = device.get("iot_flags", {})
    recommendations = []
    if flags.get("telnet_open"):
        recommendations.append("Disable Telnet and use SSH instead.")
    if flags.get("upnp_exposed"):
        recommendations.append("Disable UPnP if it is not needed.")
    if flags.get("default_credentials"):
        recommendations.append("Change the default password on this device.")
    if device.get("vulnerabilities"):
        recommendations.append("Check the firmware and update affected services.")
    if not recommendations:
        recommendations.append("No immediate issue was found by these checks.")
    return recommendations


def _risk_summary(devices: list[dict]) -> str:
    counts = {risk: 0 for risk in ("high", "medium", "low")}
    for device in devices:
        risk = device.get("risk", "low")
        counts[risk] = counts.get(risk, 0) + 1
    return (
        f"High risk: **{counts['high']}** | "
        f"Medium risk: **{counts['medium']}** | "
        f"Low risk: **{counts['low']}**"
    )


def generate_json_report(devices: list[dict], output_path: str, history: dict | None = None) -> None:
    """Write the scan results as JSON for scripts and future comparisons."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"devices": devices}
    if history is not None:
        data["history"] = history
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def generate_report(devices: list[dict], output_path: str) -> None:
    """Write a short, structured Markdown report."""
    lines = [
        "# IoT Scan Report",
        "",
        "## Scan summary",
        "",
        f"- Devices found: **{len(devices)}**",
        _risk_summary(devices),
        "",
        "The scan uses ARP to find devices, Nmap to inspect services, and simple checks "
        "for common IoT security problems.",
        "",
    ]

    for number, device in enumerate(devices, start=1):
        identity = device.get("identity", {})
        vendor = identity.get("vendor") or device.get("vendor", "Unknown vendor")
        model = identity.get("model") or device.get("model", "Unknown model")
        device_type = identity.get("type") or device.get("type", "Unknown device")
        risk = device.get("risk", "low").upper()
        open_ports = [
            f"{port.get('port')} ({port.get('service', 'unknown')})"
            for port in device.get("ports", [])
            if port.get("state") == "open"
        ]
        lines.extend(
            [
                f"---\n\n## Device {number}: {_clean(device.get('ip', 'unknown'))}",
                "",
                "### Identity",
                "",
                "| Field | Result |",
                "| --- | --- |",
                f"| Type | {_clean(device_type)} |",
                f"| Vendor | {_clean(vendor)} |",
                f"| Model | {_clean(model)} |",
                f"| MAC address | {_clean(device.get('mac', 'unknown'))} |",
                "",
                "### Risk",
                "",
                f"**{_clean(risk)}**",
                "",
                "### Open ports",
                "",
                _clean(", ".join(open_ports) or "None detected"),
                "",
                "### Security checks",
                "",
                *[f"- {check}" for check in _test_summary(device)],
                "",
                "### What to do",
                "",
                *[f"- {_clean(recommendation)}" for recommendation in _recommendations(device)],
            ]
        )
        vulnerabilities = device.get("vulnerabilities", [])
        if vulnerabilities:
            lines.extend(["", "### Possible vulnerabilities", ""])
            for vulnerability in vulnerabilities:
                lines.append(
                    f"- {vulnerability.get('id', 'CVE-unknown')}: "
                    f"{_clean(vulnerability.get('description', ''))}"
                )
        lines.append("")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
