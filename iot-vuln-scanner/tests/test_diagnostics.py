from types import SimpleNamespace

from src import diagnostics


def _fake_run(stdout):
    return lambda *args, **kwargs: SimpleNamespace(stdout=stdout)


def test_diagnostics_returns_nmap_and_npcap_entries(monkeypatch):
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: "nmap.exe")
    monkeypatch.setattr(diagnostics.subprocess, "run", _fake_run("STATE : 4 RUNNING"))

    checks = diagnostics.check_system()

    assert [check["name"] for check in checks[:2]] == ["Nmap", "Npcap"]
    assert all(check["status"] == "OK" for check in checks[:2])
    assert {"Admin rights", "Python packages", "Wi-Fi security"} <= {check["name"] for check in checks}


def test_missing_nmap_is_reported(monkeypatch):
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: None)
    monkeypatch.setattr(diagnostics.Path, "exists", lambda self: False)

    assert diagnostics._check_nmap()["status"] == "MISSING"


def test_wifi_check_reads_english_and_italian_netsh(monkeypatch):
    monkeypatch.setattr(diagnostics.sys, "platform", "win32")

    monkeypatch.setattr(diagnostics.subprocess, "run", _fake_run("    Authentication : WPA2-Personal\n    Cipher : CCMP\n"))
    assert diagnostics.check_wifi_security()["status"] == "OK"

    monkeypatch.setattr(diagnostics.subprocess, "run", _fake_run("    Autenticazione : Aperta\n    Crittografia : WEP\n"))
    assert diagnostics.check_wifi_security()["status"] == "WARNING"


def test_wifi_check_handles_garbled_italian_netsh(monkeypatch):
    # Real output from an Italian Windows 11: netsh glues the next field to the value.
    monkeypatch.setattr(diagnostics.sys, "platform", "win32")
    netsh = "    Autenticazione            : WPA3-Personal  (H2E)Crittografia    \n"
    monkeypatch.setattr(diagnostics.subprocess, "run", _fake_run(netsh))

    check = diagnostics.check_wifi_security()

    assert check["status"] == "OK"
    assert check["details"] == "The current connection uses WPA3-Personal (H2E)."


def test_wifi_name_containing_open_is_not_a_warning(monkeypatch):
    monkeypatch.setattr(diagnostics.sys, "platform", "win32")
    netsh = "    SSID : OpenWrt-Home\n    Authentication : WPA3-Personal\n    Cipher : CCMP\n"
    monkeypatch.setattr(diagnostics.subprocess, "run", _fake_run(netsh))

    assert diagnostics.check_wifi_security()["status"] == "OK"


def test_network_checks_are_listed_once():
    names = [check["name"] for check in diagnostics.network_checks()]
    assert "IoT / guest isolation" in names
    assert "Passwords" in names
