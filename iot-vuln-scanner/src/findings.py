"""
findings.py
Turns the raw results of one device into a short list of readable issues
(what is wrong + how to fix it). Used by both the terminal output and the reports.
"""

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

FLAG_ISSUES = {
    "telnet_open": (
        "high",
        "Telnet is open",
        "Passwords travel in clear text and Telnet is the #1 target of IoT botnets (e.g. Mirai).",
        "Disable Telnet in the device settings, or update the firmware.",
    ),
    "adb_open": (
        "high",
        "Android Debug Bridge (ADB) is open",
        "Anyone on the network can install apps or run commands on the device.",
        "Turn off USB / network debugging in the developer options.",
    ),
    "default_credentials": (
        "medium",
        "Vendor known for default passwords",
        "Devices from this vendor ship with a well-known factory password.",
        "Log in to the device and make sure the default password was changed.",
    ),
    "ftp_open": (
        "medium",
        "FTP is open",
        "Files and passwords are sent without encryption.",
        "Disable FTP or use SFTP instead.",
    ),
    "insecure_http": (
        "medium",
        "Web panel only on plain HTTP",
        "The login page has no HTTPS, so the password can be sniffed on the network.",
        "Enable HTTPS on the device, or only use the panel from a trusted network.",
    ),
    "upnp_exposed": (
        "medium",
        "UPnP is enabled",
        "UPnP lets devices open ports on the router by themselves.",
        "Disable UPnP on the device (and on the router) if you don't need it.",
    ),
    "tr069_open": (
        "medium",
        "TR-069 remote management is open",
        "This is the ISP remote management protocol and it has a history of serious bugs.",
        "Check with your ISP or turn off remote management if possible.",
    ),
    "mqtt_open": (
        "medium",
        "MQTT broker on unencrypted port 1883",
        "Smart home messages (and passwords) travel without encryption.",
        "Require a password on the broker and use TLS on port 8883 (a full scan tests anonymous access).",
    ),
    "ssh_open": (
        "low",
        "SSH is reachable",
        "SSH is encrypted, but weak or default passwords are still a risk.",
        "Use a strong password or keys, or turn SSH off if you don't use it.",
    ),
    "rtsp_open": (
        "low",
        "RTSP video stream port is open",
        "Cameras use RTSP for the live video.",
        "Make sure the stream needs a password.",
    ),
}


def _cve_severity(vulnerability: dict) -> str:
    if vulnerability.get("known_exploited"):
        return "high"
    severity = str(vulnerability.get("severity", "")).upper()
    if severity in ("CRITICAL", "HIGH"):
        return "high"
    if severity == "MEDIUM":
        return "medium"
    return "low"


def device_issues(device: dict) -> list[dict]:
    """Returns the issues of one device sorted from the most to the least serious."""
    issues = []
    flags = device.get("iot_flags", {})
    for flag, (severity, title, detail, fix) in FLAG_ISSUES.items():
        if flags.get(flag):
            issues.append({"severity": severity, "title": title, "detail": detail, "fix": fix})

    for check in device.get("deep_checks", []):
        if check.get("status") == "warning":
            points = check.get("points", 1)
            severity = "high" if points >= 3 else "medium" if points == 2 else "low"
            issues.append(
                {
                    "severity": severity,
                    "title": check.get("name", "Check"),
                    "detail": check.get("evidence", ""),
                    "fix": check.get("recommendation", ""),
                }
            )

    for finding in device.get("nmap_findings", []):
        issues.append(
            {
                "severity": "high",
                "title": "Nmap vulnerability script",
                "detail": finding,
                "fix": "Update the firmware of the device.",
            }
        )

    for vulnerability in device.get("vulnerabilities", []):
        score = vulnerability.get("score")
        score_text = f"CVSS {score}" if score is not None else "no CVSS score"
        exploited = ", actively exploited (CISA KEV)" if vulnerability.get("known_exploited") else ""
        issues.append(
            {
                "severity": _cve_severity(vulnerability),
                "title": f"{vulnerability.get('id', 'CVE-unknown')} ({score_text}{exploited})",
                "detail": vulnerability.get("description", "")[:200],
                "fix": f"Update {vulnerability.get('service', 'the affected service')} to the latest version.",
            }
        )

    issues.sort(key=lambda issue: SEVERITY_ORDER.get(issue["severity"], 3))
    return issues


def open_ports(device: dict) -> list[dict]:
    return [port for port in device.get("ports", []) if port.get("state") == "open"]


def open_ports_text(device: dict, with_service: bool = True) -> str:
    ports = open_ports(device)
    if not ports:
        return "none"
    if with_service:
        return ", ".join(f"{port.get('port')} ({port.get('service', 'unknown')})" for port in ports)
    return ", ".join(str(port.get("port")) for port in ports)
