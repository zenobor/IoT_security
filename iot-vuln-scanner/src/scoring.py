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
        "default_credentials": 4,
        "upnp_exposed": 2,
    }
    points += sum(
        weight for flag, weight in flag_points.items() if iot_flags.get(flag, False)
    )
    points += min(len(iot_flags.get("nmap_findings", [])), 3)

    if points >= 7:
        return "high"
    if points >= 3:
        return "medium"
    return "low"
