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
    return (
        f"| {device.get('ip', 'unknown'):<15} | "
        f"{hostname[:20]:<20} | {device_type[:22]:<22} | "
        f"{device.get('risk', 'low').upper():<6} | {port_text:<12} |"
    )


def print_summary(devices: list[dict], network: str, mode: str, output: str) -> None:
    """Print one clean final summary after the scan completes."""
    counts = {risk: 0 for risk in ("high", "medium", "low")}
    for device in devices:
        risk = device.get("risk", "low").lower()
        counts[risk] = counts.get(risk, 0) + 1

    print()
    print("+" + "=" * 78 + "+")
    print("| IoT VULNERABILITY SCAN - FINAL SUMMARY".ljust(79) + "|")
    print("+" + "=" * 78 + "+")
    print(f"| Network: {network:<67}|")
    print(f"| Mode: {mode:<70}|")
    print(f"| Devices found: {len(devices):<61}|")
    print("+" + "-" * 78 + "+")
    print(
        f"| Network score: {calculate_network_score(devices)}/100"
        f"   HIGH: {counts['high']}   MEDIUM: {counts['medium']}   LOW: {counts['low']}".ljust(79)
        + "|"
    )
    print("+" + "-" * 78 + "+")
    print("| IP              | Hostname             | Device type            | Risk   | Ports        |")
    print("+" + "-" * 78 + "+")
    for device in devices:
        print(_device_line(device))
    print("+" + "-" * 78 + "+")
    print(f"| Markdown report: {output:<60}|")
    print("+" + "=" * 78 + "+")