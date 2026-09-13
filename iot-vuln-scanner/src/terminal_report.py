"""Compact ASCII output for terminal users."""

from src.scoring import calculate_network_score


def _device_line(device: dict) -> str:
    identity = device.get("identity", {})
    device_type = identity.get("type", "Unknown device")
    hostname = device.get("hostname", "Unknown hostname")
    ports = [
        str(port.get("port"))
        for port in device.get("ports", [])
        if port.get("state") == "open"
    ]
    port_text = ",".join(ports) if ports else "none"
    checks = device.get("deep_checks", [])
    warnings = sum(check.get("status") == "warning" for check in checks)
    manual = sum(check.get("status") == "manual" for check in checks)
    return (
        f"| {device.get('ip', 'unknown'):<15} | "
        f"{hostname[:20]:<20} | {device_type[:22]:<22} | "
        f"{device.get('risk', 'low').upper():<6} | {port_text:<12} | "
        f"W:{warnings} M:{manual:<2} |"
    )


def print_summary(devices: list[dict], network: str, mode: str, output: str) -> None:
    """Print one clean final summary after the scan completes."""
    counts = {risk: 0 for risk in ("high", "medium", "low")}
    warning_count = 0
    manual_count = 0
    for device in devices:
        risk = device.get("risk", "low").lower()
        counts[risk] = counts.get(risk, 0) + 1
        checks = device.get("deep_checks", [])
        warning_count += sum(check.get("status") == "warning" for check in checks)
        manual_count += sum(check.get("status") == "manual" for check in checks)

    print()
    print("+" + "=" * 90 + "+")
    print("| IoT VULNERABILITY SCAN - FINAL SUMMARY".ljust(91) + "|")
    print("+" + "=" * 90 + "+")
    print(f"| Network: {network:<79}|")
    print(f"| Mode: {mode:<82}|")
    print(f"| Devices found: {len(devices):<73}|")
    print("+" + "-" * 90 + "+")
    print(
        f"| Network score: {calculate_network_score(devices)}/100"
        f"   HIGH: {counts['high']}   MEDIUM: {counts['medium']}   LOW: {counts['low']}".ljust(91)
        + "|"
    )
    print(f"| Checks: WARNINGS: {warning_count}   MANUAL: {manual_count}".ljust(91) + "|")
    print("+" + "-" * 90 + "+")
    print("| IP              | Hostname             | Device type            | Risk   | Ports        | Checks   |")
    print("+" + "-" * 90 + "+")
    for device in devices:
        print(_device_line(device))
    print("+" + "-" * 90 + "+")
    print(f"| Markdown report: {output:<72}|")
    print("+" + "=" * 90 + "+")