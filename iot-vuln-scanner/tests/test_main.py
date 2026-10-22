import json

import pytest

import main
from src import scanner


@pytest.fixture
def fake_network(monkeypatch):
    """Replaces every network call so a full scan runs offline in a second."""
    devices = [
        {"ip": "192.168.1.11", "mac": "00:11:22:33:44:02"},
        {"ip": "192.168.1.10", "mac": "00:11:22:33:44:01"},
    ]
    ports = {
        "192.168.1.10": [{"port": 23, "protocol": "tcp", "state": "open", "service": "telnet", "product": "", "version": "", "cpe": "", "scripts": {}}],
        "192.168.1.11": [],
    }
    monkeypatch.setattr(scanner.discovery, "scan_network", lambda *args, **kwargs: [dict(device) for device in devices])
    monkeypatch.setattr(scanner.discovery, "discover_ssdp", lambda *args, **kwargs: {"192.168.1.11": {"server": "UPnP/1.0 TestTV", "location": "", "types": []}})
    monkeypatch.setattr(scanner.fingerprint, "get_vendor", lambda mac: "Test vendor")
    monkeypatch.setattr(scanner.fingerprint, "get_hostname", lambda ip: "Unknown hostname")
    monkeypatch.setattr(scanner.fingerprint, "scan_ports", lambda ip, **kwargs: ports[ip])
    monkeypatch.setattr(scanner.vuln_check, "check_nvd", lambda *args, **kwargs: pytest.fail("NVD was called"))
    monkeypatch.setattr(scanner.deep_checks, "run_deep_checks", lambda *args, **kwargs: pytest.fail("deep checks in quick mode"))
    return devices


def _scan_argv(tmp_path, *extra):
    return [
        "scan",
        "--network", "192.168.1.0/24",
        "--output", str(tmp_path / "report.md"),
        "--json-output", str(tmp_path / "results.json"),
        "--yes",
        *extra,
    ]


def test_quick_scan_writes_reports(fake_network, tmp_path, capsys):
    exit_code = main.main(_scan_argv(tmp_path, "--html-output", str(tmp_path / "report.html")))

    assert exit_code == 0
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.html").exists()
    results = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert [device["ip"] for device in results["devices"]] == ["192.168.1.10", "192.168.1.11"]
    assert results["devices"][0]["iot_flags"]["telnet_open"] is True
    assert results["devices"][1]["iot_flags"]["upnp_exposed"] is True
    assert results["scan"]["network"] == "192.168.1.0/24"
    assert "Telnet is open" in capsys.readouterr().out


def test_old_style_arguments_still_mean_scan(fake_network, tmp_path):
    argv = _scan_argv(tmp_path)[1:]  # without the "scan" command
    assert main.parse_args(argv).command == "scan"
    assert main.main(argv) == 0


def test_scan_without_yes_and_without_terminal_stops(fake_network, tmp_path, monkeypatch):
    monkeypatch.setattr(main.sys.stdin, "isatty", lambda: False, raising=False)
    argv = [arg for arg in _scan_argv(tmp_path) if arg != "--yes"]

    assert main.main(argv) == 2
    assert not (tmp_path / "report.md").exists()


def test_one_failing_device_does_not_stop_the_scan(fake_network, tmp_path, monkeypatch):
    def broken_scan(ip, **kwargs):
        if ip == "192.168.1.10":
            raise RuntimeError("Nmap got no answer from 192.168.1.10")
        return []

    monkeypatch.setattr(scanner.fingerprint, "scan_ports", broken_scan)

    assert main.main(_scan_argv(tmp_path)) == 0
    results = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert results["devices"][0]["scan_errors"] == ["Nmap got no answer from 192.168.1.10"]


def test_show_and_compare_commands(fake_network, tmp_path, capsys):
    main.main(_scan_argv(tmp_path))
    results = str(tmp_path / "results.json")

    assert main.main(["show", results, "--map"]) == 0
    assert main.main(["show", results, "--ip", "192.168.1.10"]) == 0
    assert main.main(["compare", results, results]) == 0
    output = capsys.readouterr().out
    assert "Network map" in output
    assert "Nothing changed" in output


@pytest.mark.parametrize(
    "network, message",
    [
        ("hello", "not a valid network"),
        ("8.8.8.0/24", "not a private network"),
        ("10.0.0.0/8", "too big"),
    ],
)
def test_bad_networks_are_refused(network, message):
    with pytest.raises(SystemExit, match=message):
        main.resolve_network(network)


def test_auto_network_uses_detection(monkeypatch):
    monkeypatch.setattr(main.discovery, "detect_local_network", lambda: "192.168.0.0/24")
    assert main.resolve_network("auto") == "192.168.0.0/24"


def test_validate_ports():
    assert main.validate_ports("22,80,1000-2000") == "22,80,1000-2000"
    assert main.validate_ports(None) is None
    with pytest.raises(SystemExit):
        main.validate_ports("22;rm -rf")
    with pytest.raises(SystemExit):
        main.validate_ports("70000")


def test_menu_runs_the_chosen_actions(monkeypatch):
    choices = iter(["2", "3", "5"])
    called = []
    monkeypatch.setattr(main.discovery, "detect_local_network", lambda: "192.168.1.0/24")
    monkeypatch.setattr(main.ui, "ask_menu_choice", lambda: next(choices))
    monkeypatch.setattr(main, "run_doctor", lambda *args: called.append("doctor") or 0)
    # "show" without any saved scan must print an error, not close the menu
    monkeypatch.setattr(main, "LATEST_JSON", main.Path("does-not-exist.json"))

    assert main.run_menu() == 0
    assert called == ["doctor"]


def test_config_file_sets_defaults(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"mode": "full", "workers": 2}), encoding="utf-8")

    args = main.parse_args(["scan", "--config", str(config)])

    assert args.mode == "full"
    assert args.workers == 2
