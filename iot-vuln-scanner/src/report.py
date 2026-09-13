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
    """Write a compact Markdown report with details only for devices needing attention."""
    lines = [
        "# IoT Scan Report",
        "",
        "## Scan summary",
        "",
        f"- Devices found: **{len(devices)}**",
        _risk_summary(devices),
        "",
        "### Checks performed",
        "- ARP: finds active devices and their MAC addresses.",
        "- Nmap: checks open ports and service versions.",
        "- IoT rules: checks Telnet, UPnP and known default credentials.",
        "- NVD/Nmap scripts: looks for possible known vulnerabilities.",
        "",
        "## Devices",
        "",
        "| IP | What it is | Vendor / model | Ports | Risk |",
        "| --- | --- | --- | --- | --- |",
    ]

    attention_devices = []
    for device in devices:
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
        lines.append(
            "| "
            + " | ".join(
                _clean(value)
                for value in (
                    device.get("ip", "unknown"),
                    device_type,
                    f"{vendor} / {model}",
                    ", ".join(open_ports) or "none",
                    risk,
                )
            )
            + " |"
        )
        vulnerabilities = device.get("vulnerabilities", [])
        if risk in {"HIGH", "MEDIUM"} or vulnerabilities or device.get("scan_errors"):
            attention_devices.append((device, vulnerabilities))

    if attention_devices:
        lines.extend(["", "## Attention needed", ""])
        for device, vulnerabilities in attention_devices:
            lines.append(f"### {_clean(device.get('ip', 'unknown'))}")
            lines.append(
                "- " + _clean(" ".join(_recommendations(device)))
            )
            if device.get("scan_errors"):
                lines.append("- Nmap was not available, so port checks may be incomplete.")
            for vulnerability in vulnerabilities:
                lines.append(
                    f"- {_clean(vulnerability.get('id', 'CVE-unknown'))}: "
                    f"{_clean(vulnerability.get('description', ''))}"
                )
            lines.append("")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
