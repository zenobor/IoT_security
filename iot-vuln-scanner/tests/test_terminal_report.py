from src.terminal_report import print_summary


def test_print_summary_contains_score_and_device(capsys):
    print_summary(
        [
            {
                "ip": "192.168.1.10",
                "hostname": "camera",
                "identity": {"type": "IP camera"},
                "risk": "high",
                "ports": [{"port": 554, "state": "open"}],
            }
        ],
        "192.168.1.0/24",
        "quick",
        "scan_report.md",
    )

    output = capsys.readouterr().out
    assert "Network score: 30/100" in output
    assert "192.168.1.10" in output
    assert "IP camera" in output