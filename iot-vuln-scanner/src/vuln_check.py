"""
vuln_check.py
Verifica vulnerabilità note (CVE) per servizi/versioni rilevati.
"""

import os

import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _create_scanner(nmap):
    search_paths = [
        path
        for path in (
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
        )
        if os.path.exists(path)
    ]
    return nmap.PortScanner(nmap_search_path=tuple(search_paths))


def check_nvd(vendor: str, product: str, version: str) -> list[dict]:
    """Interroga la NVD API per CVE note relative a vendor/prodotto/versione."""
    keyword = " ".join(part for part in (vendor, product, version) if part).strip()
    if not keyword:
        return []

    response = requests.get(
        NVD_API_URL,
        params={"keywordSearch": keyword, "resultsPerPage": 20},
        timeout=15,
    )
    response.raise_for_status()

    vulnerabilities = []
    for item in response.json().get("vulnerabilities", []):
        cve = item.get("cve", {})
        descriptions = cve.get("descriptions", [])
        description = next(
            (entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"),
            "",
        )
        metrics = cve.get("metrics", {})
        metric = next(
            (
                entries[0]
                for name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
                if (entries := metrics.get(name))
            ),
            {},
        )
        cvss = metric.get("cvssData", {})
        vulnerabilities.append(
            {
                "id": cve.get("id", "unknown"),
                "description": description,
                "severity": metric.get("baseSeverity", "UNKNOWN"),
                "score": cvss.get("baseScore"),
            }
        )

    return vulnerabilities


def run_nmap_vuln_scripts(ip: str) -> list[str]:
    """Esegue gli script nmap --script vuln su un host."""
    try:
        import nmap
    except ImportError as exc:
        raise RuntimeError(
            "python-nmap non e installato. Esegui: pip install -r requirements.txt"
        ) from exc

    try:
        scanner = _create_scanner(nmap)
    except nmap.nmap.PortScannerError as exc:
        raise RuntimeError(
            "Nmap program was not found. Install Nmap and reopen PowerShell."
        ) from exc
    scanner.scan(
        hosts=ip,
        arguments="-T4 --top-ports 100 --version-light --script vuln --host-timeout 30s",
    )
    if ip not in scanner.all_hosts():
        return []

    findings = []
    for protocol in scanner[ip].all_protocols():
        for port in scanner[ip][protocol]:
            scripts = scanner[ip][protocol][port].get("script", {})
            findings.extend(f"{name}: {output}" for name, output in scripts.items())

    return findings
