"""Non-invasive checks for services exposed by an IoT device."""

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


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
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = session.get(
            url,
            timeout=3,
            verify=not https,
            allow_redirects=False,
        )
        missing_headers = [
            header for header in SECURITY_HEADERS if header not in response.headers
        ]
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


def run_deep_checks(ip: str, open_ports: list[int]) -> list[dict]:
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
    return checks