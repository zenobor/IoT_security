"""
report.py
Genera il report finale (Markdown) con i risultati della scansione.
"""

from pathlib import Path


def _clean(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def generate_report(devices: list[dict], output_path: str) -> None:
    """Scrive un report Markdown riassuntivo dei dispositivi e delle vulnerabilità trovate."""
    lines = [
        "# IoT Vulnerability Scan",
        "",
        f"Devices found: {len(devices)}",
        "",
        "| IP | MAC | Vendor | Open ports | Risk |",
        "| --- | --- | --- | --- | --- |",
    ]

    for device in devices:
        ports = device.get("ports", [])
        open_ports = ", ".join(str(port.get("port")) for port in ports)
        lines.append(
            "| "
            + " | ".join(
                _clean(
                    value
                )
                for value in (
                    device.get("ip", ""),
                    device.get("mac", ""),
                    device.get("vendor", "Unknown"),
                    open_ports or "none",
                    device.get("risk", "low"),
                )
            )
            + " |"
        )

    lines.extend(["", "## Details", ""])
    for device in devices:
        lines.extend(
            [
                f"### {_clean(device.get('ip', 'unknown'))}",
                f"- IoT flags: {_clean(device.get('iot_flags', {}))}",
                f"- Nmap findings: {_clean(device.get('nmap_findings', []))}",
            ]
        )
        for vulnerability in device.get("vulnerabilities", []):
            lines.append(
                f"- {vulnerability.get('id', 'CVE-unknown')}: "
                f"{_clean(vulnerability.get('description', ''))}"
            )
        lines.append("")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
