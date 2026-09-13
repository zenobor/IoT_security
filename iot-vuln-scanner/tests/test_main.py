import sys

import main


def test_quick_mode_skips_slow_checks(monkeypatch, tmp_path):
    devices = [
        {"ip": "192.168.1.10", "mac": "AA"},
        {"ip": "192.168.1.11", "mac": "BB"},
    ]
    monkeypatch.setattr(main.discovery, "scan_network", lambda *args, **kwargs: devices)
    monkeypatch.setattr(main.fingerprint, "get_vendor", lambda mac: "Test vendor")
    monkeypatch.setattr(main.fingerprint, "scan_ports", lambda ip: [])
    monkeypatch.setattr(
        main.vuln_check,
        "run_nmap_vuln_scripts",
        lambda ip: (_ for _ in ()).throw(AssertionError("slow Nmap scripts were called")),
    )
    monkeypatch.setattr(
        main.vuln_check,
        "check_nvd",
        lambda *args: (_ for _ in ()).throw(AssertionError("NVD was called")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--output", str(tmp_path / "report.md")],
    )

    main.main()

    assert (tmp_path / "report.md").exists()