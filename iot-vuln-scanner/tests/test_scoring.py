from src.report import generate_report
from src.scoring import calculate_risk


def test_calculate_risk_levels():
    assert calculate_risk([], {}) == "low"
    assert calculate_risk([], {"telnet_open": True}) == "medium"
    assert calculate_risk(
        [{"severity": "CRITICAL", "score": 9.8}],
        {"default_credentials": True},
    ) == "high"


def test_generate_report(tmp_path):
    output_path = tmp_path / "report.md"
    generate_report(
        [
            {
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "vendor": "Test vendor",
                "ports": [],
                "risk": "low",
                "iot_flags": {},
                "vulnerabilities": [],
                "nmap_findings": [],
            }
        ],
        str(output_path),
    )

    content = output_path.read_text(encoding="utf-8")
    assert "192.168.1.10" in content
    assert "Test vendor" in content