"""
report.py
Writes the scan results to Markdown, HTML, CSV and JSON files.
All the functions take the "scan" dict built by scanner.build_scan().
"""

import csv
import html
import json
from pathlib import Path

from src.findings import device_issues, open_ports_text


CHECKS_PERFORMED = [
    "ARP + SSDP: find the active devices, their MAC vendor and UPnP info.",
    "Nmap: open ports and service versions (IoT ports included: MQTT, RTSP, ADB, TR-069...).",
    "IoT rules: Telnet, FTP, plain HTTP, UPnP, MQTT, ADB, TR-069 and vendors with default passwords.",
    "Full mode: web panel login and headers, TLS version, anonymous MQTT, RTSP without password, safe Nmap vuln scripts.",
    "NVD (optional): known CVEs for the detected versions, marked if they are in the CISA KEV list.",
    "No password is ever guessed and nothing is changed on the devices.",
]


def _write(output_path: str, text: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _clean(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _identity(device: dict) -> tuple[str, str, str]:
    identity = device.get("identity", {})
    return (
        identity.get("type", "Unknown device"),
        identity.get("vendor", device.get("vendor", "Unknown vendor")),
        identity.get("model", "Unknown model"),
    )


def _needs_attention(device: dict) -> bool:
    return device.get("risk") in ("high", "medium") or bool(device.get("scan_errors"))


def generate_json_report(scan: dict, output_path: str) -> None:
    """Saves the full results (used by "show", "compare" and the desktop app)."""
    _write(output_path, json.dumps(scan, indent=2, default=str))


def generate_report(scan: dict, output_path: str) -> None:
    """Writes the Markdown report: summary, device table, then details only for risky devices."""
    info = scan.get("scan", {})
    devices = scan.get("devices", [])
    counts = info.get("risk_counts", {})
    lines = [
        "# IoT Scan Report",
        "",
        "| | |",
        "| --- | --- |",
        f"| Date | {_clean(info.get('started_at', 'unknown')).replace('T', ' ')} |",
        f"| Network | {_clean(info.get('network', 'unknown'))} |",
        f"| Mode | {_clean(info.get('mode', 'quick'))}{' + NVD' if info.get('nvd') else ''} |",
        f"| Devices found | {len(devices)} |",
        f"| Network score | **{info.get('network_score', '-')}/100** |",
        f"| Risk | High: **{counts.get('high', 0)}** · Medium: **{counts.get('medium', 0)}** · Low: **{counts.get('low', 0)}** |",
        "",
        "## Devices",
        "",
        "| IP | Hostname | What it is | Vendor / model | Open ports | Risk |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for device in devices:
        device_type, vendor, model = _identity(device)
        lines.append(
            "| "
            + " | ".join(
                _clean(value)
                for value in (
                    device.get("ip", "unknown"),
                    device.get("hostname", "Unknown hostname"),
                    device_type,
                    f"{vendor} / {model}",
                    open_ports_text(device),
                    device.get("risk", "low").upper(),
                )
            )
            + " |"
        )

    attention = [device for device in devices if _needs_attention(device)]
    if attention:
        lines.extend(["", "## Devices that need attention", ""])
    for device in attention:
        device_type, vendor, _ = _identity(device)
        lines.append(f"### {_clean(device.get('ip'))} - {_clean(device_type)} ({device.get('risk', 'low').upper()})")
        lines.append("")
        lines.append(f"Vendor: {_clean(vendor)} · MAC: {_clean(device.get('mac', 'unknown'))}")
        lines.append("")
        for issue in device_issues(device):
            lines.append(f"- **[{issue['severity'].upper()}] {_clean(issue['title'])}** - {_clean(issue['detail'])}")
            lines.append(f"  - Fix: {_clean(issue['fix'])}")
        for error in device.get("scan_errors", []):
            lines.append(f"- *Scan problem:* {_clean(error)}")
        lines.append("")

    lines.extend(["", "## Network checks", ""])
    for check in scan.get("network_checks", []):
        lines.append(f"- **{_clean(check['name'])}** ({check['status']}): {_clean(check['details'])}")

    lines.extend(["", "## What was checked", ""])
    lines.extend(f"- {item}" for item in CHECKS_PERFORMED)
    lines.append("")
    _write(output_path, "\n".join(lines))


def generate_html_report(scan: dict, output_path: str) -> None:
    """Writes a small standalone HTML report (opens in any browser)."""
    info = scan.get("scan", {})
    devices = scan.get("devices", [])
    escape = html.escape

    rows = []
    for device in devices:
        device_type, vendor, model = _identity(device)
        risk = device.get("risk", "low")
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{escape(str(value))}</td>"
                for value in (
                    device.get("ip", "unknown"),
                    device.get("hostname", "Unknown hostname"),
                    device_type,
                    f"{vendor} / {model}",
                    open_ports_text(device),
                )
            )
            + f'<td class="{escape(risk)}">{escape(risk.upper())}</td></tr>'
        )

    details = []
    for device in devices:
        if not _needs_attention(device):
            continue
        items = "".join(
            f'<li><span class="{issue["severity"]}">[{issue["severity"].upper()}]</span> '
            f"<b>{escape(issue['title'])}</b> - {escape(issue['detail'])}<br><i>Fix:</i> {escape(issue['fix'])}</li>"
            for issue in device_issues(device)
        )
        items += "".join(f"<li><i>Scan problem:</i> {escape(error)}</li>" for error in device.get("scan_errors", []))
        details.append(f"<h3>{escape(device.get('ip', ''))} - {escape(_identity(device)[0])}</h3><ul>{items}</ul>")

    network_checks = "".join(
        f"<li><b>{escape(check['name'])}</b> ({escape(check['status'])}): {escape(check['details'])}</li>"
        for check in scan.get("network_checks", [])
    )
    counts = info.get("risk_counts", {})
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>IoT Scan Report</title>
<style>
body{{font-family:Arial,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#222}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:.5rem;text-align:left}}
th{{background:#f0f0f0}}.high{{color:#b42318;font-weight:bold}}.medium{{color:#b54708;font-weight:bold}}.low{{color:#176b4d}}
li{{margin-bottom:.5rem}}
</style></head><body>
<h1>IoT Scan Report</h1>
<p>{escape(str(info.get('started_at', '')).replace('T', ' '))} &middot; network {escape(str(info.get('network', '')))}
&middot; mode {escape(str(info.get('mode', '')))}</p>
<p><b>Network score: {info.get('network_score', '-')}/100</b> &middot; High: {counts.get('high', 0)}
&middot; Medium: {counts.get('medium', 0)} &middot; Low: {counts.get('low', 0)}</p>
<h2>Devices ({len(devices)})</h2>
<table><thead><tr><th>IP</th><th>Hostname</th><th>Type</th><th>Vendor / model</th><th>Open ports</th><th>Risk</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
{'<h2>Devices that need attention</h2>' + ''.join(details) if details else ''}
<h2>Network checks</h2><ul>{network_checks}</ul>
</body></html>
"""
    _write(output_path, document)


def generate_csv_report(scan: dict, output_path: str) -> None:
    """Writes one CSV row per device (easy to open in Excel)."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["ip", "mac", "hostname", "type", "vendor", "model", "open_ports", "risk", "issues"])
        for device in scan.get("devices", []):
            device_type, vendor, model = _identity(device)
            writer.writerow(
                [
                    device.get("ip", ""),
                    device.get("mac", ""),
                    device.get("hostname", "Unknown hostname"),
                    device_type,
                    vendor,
                    model,
                    open_ports_text(device, with_service=False),
                    device.get("risk", "low"),
                    "; ".join(issue["title"] for issue in device_issues(device)),
                ]
            )
