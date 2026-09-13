"""Non-invasive checks for services exposed by an IoT device."""

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning


SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
)


def _http_check(ip: str, port: int, https: bool) -> dict:
    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}:{port}/"
    session = requests.Session()
    session.trust_env = False
    try:
        urllib3.disable_warnings(InsecureRequestWarning)
        response = session.get(
            url,
            timeout=3,
            verify=not https,
            allow_redirects=False,
        )
        missing_headers = [
            header for header in SECURITY_HEADERS if header not in response.headers
        ]
        body_start = response.text[:100_000].lower()
        has_password_form = "type=\"password\"" in body_start or "type='password'" in body_start
        if response.status_code in (401, 403):
            auth_status = "pass"
            auth_evidence = f"HTTP {response.status_code}; authentication challenge was returned"
        elif has_password_form:
            auth_status = "info"
            auth_evidence = "A login form was found; credentials were not tested"
        else:
            auth_status = "warning"
            auth_evidence = "The root page returned without an authentication challenge"
        return {
            "name": f"{scheme.upper()} panel",
            "status": "warning" if missing_headers else "pass",
            "evidence": (
                f"HTTP {response.status_code}; missing headers: {', '.join(missing_headers)}"
                if missing_headers
                else f"HTTP {response.status_code}; recommended headers found"
            ),
            "recommendation": (
                "Add security headers to the web panel."
                if missing_headers
                else "No action needed."
            ),
            "authentication": {
                "status": auth_status,
                "evidence": auth_evidence,
            },
        }
    except requests.exceptions.SSLError as exc:
        return {
            "name": f"{scheme.upper()} panel",
            "status": "warning",
            "evidence": f"TLS certificate or handshake problem: {exc}",
            "recommendation": "Install a valid certificate and enable modern TLS.",
        }
    except requests.RequestException as exc:
        return {
            "name": f"{scheme.upper()} panel",
            "status": "info",
            "evidence": f"Panel did not answer a safe request: {exc}",
            "recommendation": "Review the service manually if it should be reachable.",
        }


def run_deep_checks(
    ip: str,
    open_ports: list[int],
    services: list[dict] | None = None,
) -> list[dict]:
    """Run read-only checks against services already found open by Nmap."""
    checks = []
    if 80 in open_ports:
        checks.append(_http_check(ip, 80, https=False))
    if 443 in open_ports:
        checks.append(_http_check(ip, 443, https=True))
    if not checks:
        checks.append(
            {
                "name": "Web panel review",
                "status": "info",
                "evidence": "No HTTP or HTTPS service was detected.",
                "recommendation": "No web panel was tested.",
            }
        )
    checks.append(_transport_check(open_ports))
    checks.append(_firmware_check(services or []))
    checks.append(
        {
            "name": "Weak password audit",
            "status": "manual",
            "evidence": "No password attempts were made; common-password lists are not used for guessing.",
            "recommendation": "Change default passwords and review password policy manually.",
        }
    )
    checks.append(
        {
            "name": "Wi-Fi security",
            "status": "manual",
            "evidence": "Wireless encryption and access-point settings cannot be confirmed from this host scan.",
            "recommendation": "Check the router for WPA2/WPA3, no WEP/TKIP, and a strong Wi-Fi password.",
        }
    )
    checks.append(
        {
            "name": "VLAN / guest isolation",
            "status": "manual",
            "evidence": "A single LAN vantage point cannot prove client isolation or VLAN policy.",
            "recommendation": "Verify guest/IoT isolation in the router or managed switch settings.",
        }
    )
    return checks


def _transport_check(open_ports: list[int]) -> dict:
    insecure_services = {
        21: "FTP",
        23: "Telnet",
        80: "HTTP",
    }
    found = [name for port, name in insecure_services.items() if port in open_ports]
    if found:
        return {
            "name": "Cleartext traffic exposure",
            "status": "warning",
            "evidence": f"Unencrypted service(s) exposed: {', '.join(found)}",
            "recommendation": "Use HTTPS, SFTP or SSH and disable cleartext services where possible.",
        }
    return {
        "name": "Cleartext traffic exposure",
        "status": "pass",
        "evidence": "No common cleartext service was detected in the scanned ports.",
        "recommendation": "No action needed from this check.",
    }


def _firmware_check(services: list[dict]) -> dict:
    versions = [
        f"{service.get('product', '').strip()} {service.get('version', '').strip()}".strip()
        for service in services
        if service.get("product") or service.get("version")
    ]
    if versions:
        return {
            "name": "Firmware / service version",
            "status": "manual",
            "evidence": f"Version banner detected: {versions[0]}",
            "recommendation": "Compare this version with the vendor's latest security release.",
        }
    return {
        "name": "Firmware / service version",
        "status": "manual",
        "evidence": "No reliable firmware version banner was detected.",
        "recommendation": "Check the device administration page for firmware updates.",
    }