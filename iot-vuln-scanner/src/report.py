"""
report.py
Genera il report finale (Markdown) con i risultati della scansione.
"""

from pathlib import Path


def _clean(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _test_summary(device: dict) -> list[str]:
    flags = device.get("iot_flags", {})
    return [
        "ARP discovery: device answered an ARP request",
        "Nmap service scan: checked open ports and tried to read service/product versions",
        "Telnet check: port 23 is " + ("open" if flags.get("telnet_open") else "not open"),
        "UPnP check: port 1900 or 5000 is " + ("open" if flags.get("upnp_exposed") else "not open"),
        "Default credential check: "
        + ("vendor has known credentials to review" if flags.get("default_credentials") else "no matching vendor entry"),
        "NVD lookup: "
        + (f"{len(device.get('vulnerabilities', []))} possible CVE result(s)" if device.get("vulnerabilities") else "no CVE results"),
        "Nmap vulnerability scripts: "
        + (f"{len(device.get('nmap_findings', []))} finding(s)" if device.get("nmap_findings") else "no findings"),
    ]


def generate_report(devices: list[dict], output_path: str) -> None:
    """Scrive un report Markdown riassuntivo dei dispositivi e delle vulnerabilità trovate."""
    lines = [
        "# IoT Vulnerability Scan",
        "",
        f"Devices found: {len(devices)}",
        "",
        "| IP | Type | Vendor | Model | Open ports | Risk |",
        "| --- | --- | --- | --- | --- | --- |",
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
                    device.get("identity", {}).get("type", "Unknown device"),
                    device.get("identity", {}).get("vendor", device.get("vendor", "Unknown")),
                    device.get("identity", {}).get("model", "Unknown model"),
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
                f"- MAC address: {_clean(device.get('mac', 'unknown'))}",
                f"- What this device is: {_clean(device.get('identity', {}).get('type', 'Unknown device'))}",
                f"- Vendor: {_clean(device.get('identity', {}).get('vendor', 'Unknown vendor'))}",
                f"- Model: {_clean(device.get('identity', {}).get('model', 'Unknown model'))}",
                f"- Version: {_clean(device.get('identity', {}).get('version', 'Unknown version'))}",
                f"- Identification confidence: {_clean(device.get('identity', {}).get('confidence', 'unknown'))}",
                f"- IoT flags: {_clean(device.get('iot_flags', {}))}",
                f"- Nmap findings: {_clean(device.get('nmap_findings', []))}",
                "",
                "#### Tests performed",
                *[f"- {test}" for test in _test_summary(device)],
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
