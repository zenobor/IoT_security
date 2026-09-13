from types import SimpleNamespace

from src import deep_checks


def test_http_check_reports_missing_security_headers(monkeypatch):
    response = SimpleNamespace(status_code=200, headers={"Content-Type": "text/html"})
    session = SimpleNamespace(
        trust_env=False,
        get=lambda *args, **kwargs: response,
    )
    monkeypatch.setattr(deep_checks.requests, "Session", lambda: session)

    checks = deep_checks.run_deep_checks("192.168.1.10", [80])

    assert checks[0]["status"] == "warning"
    assert "security headers" in checks[0]["recommendation"]


def test_deep_checks_do_not_probe_without_web_ports():
    checks = deep_checks.run_deep_checks("192.168.1.10", [22, 554])

    assert checks[0]["status"] == "info"
    assert "No HTTP" in checks[0]["evidence"]