from src.fingerprint import identify_device
from src.report import generate_csv_report, generate_html_report, generate_report
from src.scoring import calculate_risk


def test_calculate_risk_levels():
    assert calculate_risk([], {}) == "low"
    assert calculate_risk([], {"telnet_open": True}) == "medium"
    assert calculate_risk(
        [{"severity": "CRITICAL", "score": 9.8}],
        {"default_credentials": True},
    ) == "high"


def test_identify_camera_from_services():
    identity = identify_device(
        "Hikvision",
        [
            {
                "port": 554,
                "state": "open",
                "service": "rtsp",
                "product": "Hikvision camera",
                "version": "5.0",
            }
        ],
    )

    assert identity["type"] == "IP camera"
    assert identity["vendor"] == "Hikvision"
    assert identity["model"] == "Hikvision camera"


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


def test_generate_html_and_csv_reports(tmp_path):
    device = {
        "ip": "192.168.1.10",
        "hostname": "camera.local",
        "identity": {"type": "IP camera", "vendor": "Test", "model": "Cam"},
        "ports": [{"port": 554, "service": "rtsp", "state": "open"}],
        "risk": "medium",
    }
    html_path = tmp_path / "report.html"
    csv_path = tmp_path / "report.csv"

    generate_html_report([device], str(html_path))
    generate_csv_report([device], str(csv_path))

    assert "camera.local" in html_path.read_text(encoding="utf-8")
    assert "192.168.1.10" in csv_path.read_text(encoding="utf-8")

