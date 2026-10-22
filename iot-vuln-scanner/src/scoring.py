"""
scoring.py
Calculates a risk level (low / medium / high) for every device and a 0-100 network score.
"""

SEVERITY_POINTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# How bad each rule is. The idea: something that lets anyone take control of the
# device (ADB, Telnet, default password) weighs more than something that is only
# "not ideal" (SSH open, RTSP port open). The numbers were tuned by hand so that
# one serious problem alone gives MEDIUM, and two of them give HIGH.
FLAG_POINTS = {
    "telnet_open": 3,
    "adb_open": 4,
    "default_credentials": 3,
    "ftp_open": 2,
    "insecure_http": 2,
    "upnp_exposed": 2,
    "tr069_open": 2,
    "mqtt_open": 2,
    "ssh_open": 1,
    "rtsp_open": 1,
}

HIGH_RISK_POINTS = 7
MEDIUM_RISK_POINTS = 3


def calculate_points(vulnerabilities: list[dict], iot_flags: dict) -> int:
    """
    Combines the CVEs and the IoT rule flags into a number of risk points.

    Only the 3 worst CVEs count, otherwise one old service with 50 CVEs would
    hide everything else. CVEs in the CISA "actively exploited" list count extra.
    """
    cve_points = []
    for vulnerability in vulnerabilities:
        points = SEVERITY_POINTS.get(str(vulnerability.get("severity", "")).upper(), 0)
        score = vulnerability.get("score")
        if isinstance(score, (int, float)) and score >= 9:
            points += 1
        cve_points.append(points)
    points = sum(sorted(cve_points, reverse=True)[:3])
    points += 3 * min(sum(1 for vulnerability in vulnerabilities if vulnerability.get("known_exploited")), 2)

    points += sum(weight for flag, weight in FLAG_POINTS.items() if iot_flags.get(flag, False))
    # Nmap only says VULNERABLE when it actually confirmed the problem, so these count a lot
    points += 2 * min(len(iot_flags.get("nmap_findings", [])), 3)
    points += sum(
        check.get("points", 1)
        for check in iot_flags.get("deep_checks", [])
        if check.get("status") == "warning"
    )
    return points


def risk_level(points: int) -> str:
    if points >= HIGH_RISK_POINTS:
        return "high"
    if points >= MEDIUM_RISK_POINTS:
        return "medium"
    return "low"


def calculate_risk(vulnerabilities: list[dict], iot_flags: dict) -> str:
    """Returns "low", "medium" or "high"."""
    return risk_level(calculate_points(vulnerabilities, iot_flags))


def calculate_network_score(devices: list[dict]) -> int:
    """Returns a simple 0-100 score for the scanned network (100 = nothing found)."""
    if not devices:
        return 100

    # Average penalty per device, so a big network with one bad device
    # doesn't get the same score as a small network where everything is bad.
    penalties = {"high": 35, "medium": 18, "low": 3}
    total_penalty = sum(penalties.get(device.get("risk", "low"), 3) for device in devices)
    return max(0, round(100 - (total_penalty / len(devices) * 2)))


def count_risks(devices: list[dict]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for device in devices:
        risk = device.get("risk", "low").lower()
        counts[risk] = counts.get(risk, 0) + 1
    return counts
