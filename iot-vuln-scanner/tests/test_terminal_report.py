from src import terminal_report as ui


def test_print_summary_contains_score_and_device(capsys, device_factory, scan_factory):
    scan = scan_factory([device_factory(risk="high")], network_score=30, risk_counts={"high": 1, "medium": 0, "low": 0})

    ui.print_summary(scan)
    output = capsys.readouterr().out

    assert "Network score: 30/100" in output
    assert "192.168.1.10" in output
    assert "IP camera" in output
    assert "HIGH" in output


def test_print_attention_shows_issues_and_fix(capsys, device_factory, scan_factory):
    scan = scan_factory([device_factory(risk="high", iot_flags={"telnet_open": True})])

    ui.print_attention(scan)
    output = capsys.readouterr().out

    assert "Telnet is open" in output
    assert "Fix:" in output


def test_print_attention_when_everything_is_fine(capsys, device_factory, scan_factory):
    ui.print_attention(scan_factory([device_factory(risk="low")]))
    assert "No device needs attention" in capsys.readouterr().out


def test_device_names_with_brackets_do_not_break_the_output(capsys, device_factory, scan_factory):
    device = device_factory(risk="medium", identity={"type": "[bold]weird[/bold] device", "vendor": "[x]", "model": "m"})

    ui.print_summary(scan_factory([device]))
    ui.print_network_map(scan_factory([device]))

    assert "[bold]weird[/bold]" in capsys.readouterr().out


def test_print_diagnostics_reports_missing_tools(capsys):
    ui.print_diagnostics([{"name": "Nmap", "status": "MISSING", "details": "Install Nmap"}])
    output = capsys.readouterr().out

    assert "MISSING" in output
    assert "Something is missing" in output


def test_print_comparison(capsys, device_factory):
    diff = {
        "old_date": "2026-10-01T10:00:00",
        "new_date": "2026-10-22T10:00:00",
        "old_score": 90,
        "new_score": 70,
        "new_devices": [device_factory(ip="192.168.1.99")],
        "missing_devices": [],
        "changed_devices": [
            {"ip": "192.168.1.10", "old_ip": "192.168.1.10", "type": "IP camera", "opened_ports": [23], "closed_ports": [], "old_risk": "low", "new_risk": "high"}
        ],
    }

    ui.print_comparison(diff)
    output = capsys.readouterr().out

    assert "NEW" in output and "192.168.1.99" in output
    assert "opened 23" in output
    assert "90 -> 70" in output
