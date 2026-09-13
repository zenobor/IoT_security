from src import diagnostics


def test_diagnostics_returns_nmap_and_npcap_entries(monkeypatch):
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: "nmap.exe")
    monkeypatch.setattr(
        diagnostics.subprocess,
        "run",
        lambda *args, **kwargs: type("Result", (), {"stdout": "STATE : 4 RUNNING"})(),
    )

    checks = diagnostics.check_system()

    assert [check["name"] for check in checks[:2]] == ["Nmap", "Npcap"]
    assert all(check["status"] == "OK" for check in checks[:2])