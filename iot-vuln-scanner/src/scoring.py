"""
scoring.py
Calcola un livello di rischio (basso/medio/alto) per ogni dispositivo.
"""


def calculate_risk(vulnerabilities: list[dict], iot_flags: dict) -> str:
    """
    Combina CVE trovate e flag delle regole IoT-specifiche
    per assegnare un livello di rischio.

    Returns:
        "low", "medium" o "high"
    """
    points = 0
    severity_points = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for vulnerability in vulnerabilities:
        severity = str(vulnerability.get("severity", "")).upper()
        points += severity_points.get(severity, 0)
        score = vulnerability.get("score")
        if isinstance(score, (int, float)) and score >= 9:
            points += 1

    flag_points = {
        "telnet_open": 3,
        "ftp_open": 2,
        "ssh_open": 1,
        "insecure_http": 2,
        "default_credentials": 4,
        "upnp_exposed": 2,
    }
    points += sum(
        weight for flag, weight in flag_points.items() if iot_flags.get(flag, False)
    )
    points += min(len(iot_flags.get("nmap_findings", [])), 3)
    points += sum(
        1
        for check in iot_flags.get("deep_checks", [])
        if check.get("status") == "warning"
    )

    if points >= 7:
        return "high"
    if points >= 3:
        return "medium"
    return "low"


def calculate_network_score(devices: list[dict]) -> int:
    """Return a simple 0-100 score for the scanned network."""
    if not devices:
        return 100

    penalties = {"high": 35, "medium": 18, "low": 3}
    total_penalty = sum(penalties.get(device.get("risk", "low"), 3) for device in devices)
    return max(0, round(100 - (total_penalty / len(devices) * 2)))
