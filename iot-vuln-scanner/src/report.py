"""
report.py
Genera il report finale (Markdown) con i risultati della scansione.
"""

from pathlib import Path
import json
import csv
import html


def _clean(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _test_summary(device: dict) -> list[str]:
    flags = device.get("iot_flags", {})
    checks = [
        "ARP: found",
        "Telnet: open" if flags.get("telnet_open") else "Telnet: closed",
        "FTP: open" if flags.get("ftp_open") else "FTP: closed",
        "SSH: open" if flags.get("ssh_open") else "SSH: not found",
        "HTTP: insecure" if flags.get("insecure_http") else "HTTP: not flagged",
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
    if flags.get("ftp_open"):
        recommendations.append("Disable FTP or use encrypted SFTP.")
    if flags.get("insecure_http"):
        recommendations.append("Use HTTPS for the device web panel.")
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


def generate_json_report(devices: list[dict], output_path: str) -> None:
    """Write the current scan results as JSON for scripts."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"devices": devices}, indent=2), encoding="utf-8")


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
        "- Full mode: checks web panels, TLS and security headers without logging in.",
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
                    f"{device.get('ip', 'unknown')} ({device.get('hostname', 'Unknown hostname')})",
                    device_type,
                    f"{vendor} / {model}",
                    ", ".join(open_ports) or "none",
                    risk,
                )
            )
            + " |"
        )
        vulnerabilities = device.get("vulnerabilities", [])
        deep_findings = device.get("deep_checks", [])
        has_deep_warning = any(
            check.get("status") == "warning" for check in deep_findings
        )
        if risk in {"HIGH", "MEDIUM"} or vulnerabilities or has_deep_warning or device.get("scan_errors"):
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
            for check in deep_findings:
                lines.append(
                    f"- {_clean(check.get('name', 'Deep check'))}: "
                    f"{_clean(check.get('status', 'info'))}; "
                    f"{_clean(check.get('evidence', ''))}"
                )
            lines.append("")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def generate_html_report(devices: list[dict], output_path: str) -> None:
    """Write a small standalone HTML report."""
    rows = []
    for device in devices:
        identity = device.get("identity", {})
        ports = ", ".join(
            f"{port.get('port')} ({port.get('service', 'unknown')})"
            for port in device.get("ports", [])
            if port.get("state") == "open"
        ) or "none"
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(value))}</td>"
                for value in (
                    device.get("ip", "unknown"),
                    device.get("hostname", "Unknown hostname"),
                    identity.get("type", "Unknown device"),
                    identity.get("vendor", device.get("vendor", "Unknown vendor")),
                    identity.get("model", "Unknown model"),
                    ports,
                    device.get("risk", "low").upper(),
                )
            )
            + "</tr>"
        )
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>IoT Scan Report</title>
<style>body{font-family:Arial,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#222}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.55rem;text-align:left}th{background:#f0f0f0}.high{color:#a00}.medium{color:#a60}.low{color:#176b2c}</style>
</head><body><h1>IoT Scan Report</h1>
<p>Devices found: """ + str(len(devices)) + """</p><table><thead><tr><th>IP</th><th>Hostname</th><th>Type</th><th>Vendor</th><th>Model</th><th>Ports</th><th>Risk</th></tr></thead><tbody>""" + "".join(rows) + """</tbody></table>
</body></html>"""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")


def generate_csv_report(devices: list[dict], output_path: str) -> None:
    """Write one simple CSV row per device."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["ip", "hostname", "type", "vendor", "model", "open_ports", "risk"])
        for device in devices:
            identity = device.get("identity", {})
            ports = ",".join(
                str(port.get("port"))
                for port in device.get("ports", [])
                if port.get("state") == "open"
            )
            writer.writerow(
                [
                    device.get("ip", ""),
                    device.get("hostname", "Unknown hostname"),
                    identity.get("type", "Unknown device"),
                    identity.get("vendor", device.get("vendor", "Unknown vendor")),
                    identity.get("model", "Unknown model"),
                    ports,
                    device.get("risk", "low"),
                ]
            )
