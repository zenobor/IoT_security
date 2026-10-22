from types import SimpleNamespace

from src import deep_checks


def _fake_session(monkeypatch, status_code=200, headers=None, text="<html>public panel</html>"):
    response = SimpleNamespace(status_code=status_code, headers=headers or {"Content-Type": "text/html"}, text=text)
    session = SimpleNamespace(trust_env=False, get=lambda *args, **kwargs: response)
    monkeypatch.setattr(deep_checks.requests, "Session", lambda: session)


class FakeSocket:
    """Pretends to be a TCP connection that answers with a fixed message."""

    def __init__(self, answer: bytes):
        self.answer = answer
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        return self.answer[:size]


def test_http_check_reports_missing_headers_and_no_login(monkeypatch):
    _fake_session(monkeypatch)

    checks = deep_checks.run_deep_checks("192.168.1.10", [80])
    by_name = {check["name"]: check for check in checks}

    assert by_name["Web panel :80 headers"]["status"] == "warning"
    assert by_name["Web panel :80 login"]["status"] == "warning"
    assert by_name["Web panel :80 login"]["points"] == 2


def test_http_check_passes_when_login_is_required(monkeypatch):
    _fake_session(monkeypatch, status_code=401)

    checks = deep_checks.run_deep_checks("192.168.1.10", [80])
    login = next(check for check in checks if check["name"] == "Web panel :80 login")

    assert login["status"] == "pass"


def test_web_ports_are_found_from_nmap_service_names():
    services = [
        {"port": 8081, "service": "http", "state": "open"},
        {"port": 9443, "service": "ssl/http", "state": "open"},
    ]
    assert deep_checks._web_ports([8081, 9443], services) == [(8081, False), (9443, True)]


def test_deep_checks_do_not_probe_without_web_ports():
    checks = deep_checks.run_deep_checks("192.168.1.10", [22])

    assert checks[0]["status"] == "info"
    assert "No HTTP" in checks[0]["evidence"]


def test_mqtt_anonymous_broker_is_a_warning(monkeypatch):
    fake = FakeSocket(b"\x20\x02\x00\x00")  # CONNACK, return code 0 = accepted
    monkeypatch.setattr(deep_checks.socket, "create_connection", lambda *args, **kwargs: fake)

    check = deep_checks._mqtt_check("192.168.1.10")

    assert check["status"] == "warning"
    assert check["points"] == 3
    assert fake.sent.startswith(b"\x10")  # we sent a CONNECT packet


def test_mqtt_broker_with_auth_passes(monkeypatch):
    fake = FakeSocket(b"\x20\x02\x00\x05")  # return code 5 = not authorized
    monkeypatch.setattr(deep_checks.socket, "create_connection", lambda *args, **kwargs: fake)

    assert deep_checks._mqtt_check("192.168.1.10")["status"] == "pass"


def test_rtsp_without_password_is_a_warning(monkeypatch):
    fake = FakeSocket(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
    monkeypatch.setattr(deep_checks.socket, "create_connection", lambda *args, **kwargs: fake)

    assert deep_checks._rtsp_check("192.168.1.10", 554)["status"] == "warning"


def test_rtsp_with_password_passes(monkeypatch):
    fake = FakeSocket(b"RTSP/1.0 401 Unauthorized\r\n\r\n")
    monkeypatch.setattr(deep_checks.socket, "create_connection", lambda *args, **kwargs: fake)

    assert deep_checks._rtsp_check("192.168.1.10", 554)["status"] == "pass"


def test_deep_checks_find_sensitive_services(monkeypatch):
    monkeypatch.setattr(deep_checks, "_mqtt_check", lambda ip: {"name": "MQTT broker", "status": "pass"})

    checks = deep_checks.run_deep_checks("192.168.1.10", [1883])
    service_check = next(check for check in checks if check["name"] == "Sensitive service exposure")

    assert service_check["status"] == "warning"
    assert "MQTT" in service_check["evidence"]
