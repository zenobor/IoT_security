"""
deep_checks.py
Read-only checks on the services that Nmap already found open (full mode only).

Nothing here guesses passwords: we only look at what a service answers to a normal,
unauthenticated request. Each warning has "points" that are added to the device risk.
"""

import socket
import ssl

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning


SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
)
WEB_PORTS = {80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888}
HTTPS_PORTS = {443, 8443}
MAX_WEB_PORTS = 4
SOCKET_TIMEOUT = 3


def _check(name: str, status: str, evidence: str, recommendation: str, points: int = 0) -> dict:
    result = {"name": name, "status": status, "evidence": evidence, "recommendation": recommendation}
    if status == "warning":
        result["points"] = points or 1
    return result


def _web_ports(open_ports: list[int], services: list[dict]) -> list[tuple[int, bool]]:
    """Returns (port, is_https) for every port that looks like a web panel."""
    found = {}
    for service in services:
        name = str(service.get("service", "")).lower()
        port = service.get("port")
        if service.get("state", "open") == "open" and port in open_ports and "http" in name:
            found[port] = "https" in name or "ssl" in name or port in HTTPS_PORTS
    for port in open_ports:
        if port in WEB_PORTS and port not in found:
            found[port] = port in HTTPS_PORTS
    return sorted(found.items())[:MAX_WEB_PORTS]


def _http_check(ip: str, port: int, https: bool) -> list[dict]:
    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}:{port}/"
    session = requests.Session()
    session.trust_env = False
    try:
        urllib3.disable_warnings(InsecureRequestWarning)
        # IoT panels almost always use self-signed certificates, so we don't verify them here.
        response = session.get(url, timeout=SOCKET_TIMEOUT, verify=False, allow_redirects=False)
    except requests.RequestException as exc:
        return [
            _check(
                f"Web panel :{port}",
                "info",
                f"Panel did not answer a simple request ({exc.__class__.__name__})",
                "Review the service manually if it should be reachable.",
            )
        ]

    checks = []
    missing_headers = [header for header in SECURITY_HEADERS if header not in response.headers]
    if missing_headers:
        checks.append(
            _check(
                f"Web panel :{port} headers",
                "warning",
                f"HTTP {response.status_code}; missing headers: {', '.join(missing_headers)}",
                "Update the firmware; old web panels often miss basic security headers.",
                points=1,
            )
        )
    else:
        checks.append(
            _check(
                f"Web panel :{port} headers",
                "pass",
                f"HTTP {response.status_code}; recommended headers found",
                "No action needed.",
            )
        )

    body_start = response.text[:100_000].lower()
    has_password_form = 'type="password"' in body_start or "type='password'" in body_start
    if response.status_code in (401, 403):
        checks.append(
            _check(f"Web panel :{port} login", "pass", f"HTTP {response.status_code}; asks for authentication", "No action needed.")
        )
    elif 300 <= response.status_code < 400:
        checks.append(
            _check(
                f"Web panel :{port} login",
                "info",
                f"Redirects to {response.headers.get('Location', 'another page')}",
                "Open the panel in a browser to check it asks for a password.",
            )
        )
    elif has_password_form:
        checks.append(
            _check(f"Web panel :{port} login", "info", "A login form was found; credentials were not tested", "Make sure the default password was changed.")
        )
    else:
        checks.append(
            _check(
                f"Web panel :{port} login",
                "warning",
                "The main page opened without asking for a password",
                "Protect the web panel with a password or turn it off.",
                points=2,
            )
        )
    return checks


def _tls_check(ip: str, port: int) -> dict:
    """Checks that the HTTPS service accepts at least TLS 1.2 (Python refuses older versions)."""
    # Trick: Python's default context already refuses TLS 1.0/1.1, so if the
    # handshake fails the device probably only speaks an old TLS version.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=SOCKET_TIMEOUT) as raw_socket:
            with context.wrap_socket(raw_socket) as tls_socket:
                version = tls_socket.version() or "unknown"
    except ssl.SSLError as exc:
        return _check(
            f"TLS :{port}",
            "warning",
            f"No modern TLS (1.2+) handshake possible: {exc.reason or exc}",
            "Update the firmware so the panel supports TLS 1.2 or 1.3.",
            points=2,
        )
    except OSError as exc:
        return _check(f"TLS :{port}", "info", f"Could not connect ({exc.__class__.__name__})", "Review the service manually.")
    return _check(f"TLS :{port}", "pass", f"Negotiated {version}", "No action needed.")


def _mqtt_connect_packet() -> bytes:
    # Built by hand following the MQTT 3.1.1 spec, so we don't need an MQTT library.
    # The connect flags (0x02) have NO username/password bit set: that's the point
    # of the test, we want to know if the broker lets anyone in.
    client_id = b"iot-scan-check"
    variable_header = b"\x00\x04MQTT\x04\x02\x00\x1e"  # MQTT 3.1.1, clean session, keep-alive 30 s
    payload = len(client_id).to_bytes(2, "big") + client_id
    body = variable_header + payload
    # 0x10 = CONNECT packet type, then the remaining length (fits in one byte here)
    return b"\x10" + bytes([len(body)]) + body


def _mqtt_check(ip: str, port: int = 1883) -> dict:
    """Connects to the MQTT broker WITHOUT a username/password and reads the answer."""
    try:
        with socket.create_connection((ip, port), timeout=SOCKET_TIMEOUT) as sock:
            sock.sendall(_mqtt_connect_packet())
            # CONNACK = 0x20, length 2, flags, return code (0 = accepted)
            answer = sock.recv(4)
            if len(answer) == 4 and answer[0] == 0x20 and answer[3] == 0:
                sock.sendall(b"\xe0\x00")  # DISCONNECT
    except OSError as exc:
        return _check("MQTT broker", "info", f"Could not talk to the broker ({exc.__class__.__name__})", "Review the broker manually.")

    if len(answer) < 4 or answer[0] != 0x20:
        return _check("MQTT broker", "info", "The service did not answer like an MQTT broker", "Review the service manually.")
    if answer[3] == 0:
        return _check(
            "MQTT broker",
            "warning",
            "Accepts connections without a username and password (anyone can read/send messages)",
            "Enable authentication on the broker (and TLS on port 8883).",
            points=3,
        )
    return _check("MQTT broker", "pass", f"Refused an anonymous connection (code {answer[3]})", "No action needed.")


def _rtsp_check(ip: str, port: int) -> dict:
    """Sends an RTSP DESCRIBE without credentials, like a video player would."""
    request = (
        f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "Accept: application/sdp\r\n"
        "User-Agent: iot-vuln-scanner\r\n\r\n"
    )
    try:
        with socket.create_connection((ip, port), timeout=SOCKET_TIMEOUT) as sock:
            sock.sendall(request.encode())
            status_line = sock.recv(1024).decode(errors="replace").split("\r\n", 1)[0]
    except OSError as exc:
        return _check(f"RTSP stream :{port}", "info", f"Could not talk to the service ({exc.__class__.__name__})", "Review the camera manually.")

    # the extra space at the end handles answers like "RTSP/1.0 200" with no reason text
    if " 200 " in status_line + " ":
        return _check(
            f"RTSP stream :{port}",
            "warning",
            "The video stream description was returned without a password",
            "Enable stream authentication in the camera settings.",
            points=3,
        )
    if " 401 " in status_line + " ":
        return _check(f"RTSP stream :{port}", "pass", "Asks for authentication", "No action needed.")
    return _check(
        f"RTSP stream :{port}",
        "info",
        f"Answer: {status_line or 'empty'} (the real stream path may be different)",
        "Check in the camera app that the stream needs a password.",
    )


def _exposed_service_check(open_ports: list[int]) -> dict:
    services = {
        3389: "RDP",
        5900: "VNC",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        9200: "Elasticsearch",
        1883: "MQTT",
        4840: "OPC UA",
        5555: "ADB",
    }
    found = [name for port, name in services.items() if port in open_ports]
    if found:
        return _check(
            "Sensitive service exposure",
            "warning",
            f"Potentially sensitive service(s) exposed: {', '.join(found)}",
            "Restrict these services to trusted hosts or move the device to an isolated IoT network.",
            points=1,
        )
    return _check(
        "Sensitive service exposure",
        "pass",
        "No database, broker, remote-desktop or industrial service was detected.",
        "No action needed from this check.",
    )


def _transport_check(open_ports: list[int]) -> dict:
    insecure_services = {21: "FTP", 23: "Telnet", 2323: "Telnet", 80: "HTTP"}
    found = sorted({name for port, name in insecure_services.items() if port in open_ports})
    if found:
        return _check(
            "Cleartext traffic exposure",
            "warning",
            f"Unencrypted service(s) exposed: {', '.join(found)}",
            "Use HTTPS, SFTP or SSH and disable cleartext services where possible.",
            points=1,
        )
    return _check(
        "Cleartext traffic exposure",
        "pass",
        "No common cleartext service was detected in the scanned ports.",
        "No action needed from this check.",
    )


def _firmware_check(services: list[dict]) -> dict:
    versions = [
        f"{service.get('product', '').strip()} {service.get('version', '').strip()}".strip()
        for service in services
        if service.get("state", "open") == "open" and (service.get("product") or service.get("version"))
    ]
    if versions:
        return _check(
            "Firmware / service version",
            "manual",
            f"Version banner detected: {', '.join(versions[:3])}",
            "Compare this version with the vendor's latest security release.",
        )
    return _check(
        "Firmware / service version",
        "manual",
        "No reliable firmware version banner was detected.",
        "Check the device administration page for firmware updates.",
    )


def run_deep_checks(ip: str, open_ports: list[int], services: list[dict] | None = None) -> list[dict]:
    """Runs read-only checks against the services already found open by Nmap."""
    services = services or []
    checks = []

    web_ports = _web_ports(open_ports, services)
    for port, https in web_ports:
        checks.extend(_http_check(ip, port, https))
        if https:
            checks.append(_tls_check(ip, port))
    if not web_ports:
        checks.append(_check("Web panel review", "info", "No HTTP or HTTPS service was detected.", "No web panel was tested."))

    if 1883 in open_ports:
        checks.append(_mqtt_check(ip))
    for port in (554, 8554):
        if port in open_ports:
            checks.append(_rtsp_check(ip, port))

    checks.append(_transport_check(open_ports))
    checks.append(_exposed_service_check(open_ports))
    checks.append(_firmware_check(services))
    return checks
