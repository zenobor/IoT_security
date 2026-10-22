from src.findings import device_issues
from src.scoring import calculate_network_score, calculate_points, calculate_risk, count_risks


def test_calculate_risk_levels():
    assert calculate_risk([], {}) == "low"
    assert calculate_risk([], {"telnet_open": True}) == "medium"
    assert calculate_risk(
        [{"severity": "CRITICAL", "score": 9.8}],
        {"default_credentials": True},
    ) == "high"


def test_only_the_three_worst_cves_count():
    many_cves = [{"severity": "MEDIUM", "score": 5.0}] * 50
    assert calculate_points(many_cves, {}) == 6


def test_known_exploited_cves_add_points():
    normal = [{"severity": "HIGH", "score": 7.5}]
    exploited = [{"severity": "HIGH", "score": 7.5, "known_exploited": True}]
    assert calculate_points(exploited, {}) == calculate_points(normal, {}) + 3


def test_deep_check_warnings_use_their_points():
    flags = {"deep_checks": [{"status": "warning", "points": 3}, {"status": "pass"}]}
    assert calculate_points([], flags) == 3


def test_calculate_network_score():
    assert calculate_network_score([]) == 100
    assert calculate_network_score([{"risk": "low"}]) == 94
    assert calculate_network_score([{"risk": "high"}]) == 30


def test_count_risks():
    assert count_risks([{"risk": "high"}, {"risk": "low"}, {"risk": "low"}]) == {"high": 1, "medium": 0, "low": 2}


def test_device_issues_are_sorted_by_severity(device_factory):
    device = device_factory(
        iot_flags={"ssh_open": True, "telnet_open": True},
        vulnerabilities=[{"id": "CVE-2024-0001", "severity": "MEDIUM", "score": 5.0}],
    )

    issues = device_issues(device)

    assert [issue["severity"] for issue in issues] == ["high", "medium", "low"]
    assert issues[0]["title"] == "Telnet is open"
    assert all(issue["fix"] for issue in issues)
