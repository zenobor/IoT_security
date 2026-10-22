"""
vuln_check.py
Looks up known vulnerabilities (CVE) for the services/versions found by Nmap.

- NVD API: CVE list for a product version (uses the CPE from Nmap when possible)
- CISA KEV: list of CVEs that are known to be actively exploited
- Nmap "vuln" scripts: we only keep the outputs that say VULNERABLE
"""

import json
import re
import threading
import time
from pathlib import Path

import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR = Path(__file__).parents[1] / "cache"
NVD_CACHE_FILE = CACHE_DIR / "nvd_cache.json"
KEV_CACHE_FILE = CACHE_DIR / "kev.json"
NVD_CACHE_DAYS = 7
KEV_CACHE_DAYS = 1
MAX_CVES_PER_SERVICE = 10

# NVD allows 5 requests every 30 s without an API key (50 with a key).
DELAY_WITHOUT_KEY = 6.5
DELAY_WITH_KEY = 0.7

_nvd_lock = threading.Lock()
_last_request = 0.0
_nvd_cache: dict | None = None


def cpe_to_match_string(cpe: str) -> str | None:
    """Turns an Nmap CPE like 'cpe:/a:openbsd:openssh:7.4' into 'cpe:2.3:a:openbsd:openssh:7.4'.

    Returns None if there is no version, because "all versions of Linux" would match thousands of CVEs.
    """
    if not cpe or not cpe.startswith("cpe:/"):
        return None
    parts = cpe[len("cpe:/"):].split(":")
    if len(parts) < 4 or not parts[3]:
        return None
    return "cpe:2.3:" + ":".join(parts[:4])


def _load_cache() -> dict:
    global _nvd_cache
    if _nvd_cache is None:
        try:
            _nvd_cache = json.loads(NVD_CACHE_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _nvd_cache = {}
    return _nvd_cache


def _save_cache() -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        NVD_CACHE_FILE.write_text(json.dumps(_nvd_cache or {}), encoding="utf-8")
    except OSError:
        pass


def _parse_nvd_response(data: dict) -> list[dict]:
    vulnerabilities = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        description = next(
            (entry.get("value", "") for entry in cve.get("descriptions", []) if entry.get("lang") == "en"),
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
                "severity": metric.get("baseSeverity") or cvss.get("baseSeverity", "UNKNOWN"),
                "score": cvss.get("baseScore"),
                "known_exploited": False,
            }
        )
    vulnerabilities.sort(key=lambda vulnerability: vulnerability["score"] or 0, reverse=True)
    return vulnerabilities[:MAX_CVES_PER_SERVICE]


def _nvd_get(url: str, params: dict, api_key: str | None) -> dict:
    """Calls the NVD API respecting its rate limit, with a few retries if NVD says "slow down"."""
    global _last_request
    headers = {"apiKey": api_key} if api_key else {}
    delay = DELAY_WITH_KEY if api_key else DELAY_WITHOUT_KEY

    for attempt in range(3):
        wait = _last_request + delay - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_request = time.monotonic()
        response = requests.get(url, params=params, headers=headers, timeout=20)
        if response.status_code in (403, 429, 503) and attempt < 2:
            time.sleep(10 * (attempt + 1))
            continue
        response.raise_for_status()
        return response.json()
    return {}


def check_nvd(product: str, version: str, cpe: str = "", api_key: str | None = None) -> list[dict]:
    """Asks the NVD API for known CVEs of one service version.

    With a CPE from Nmap we use NVD's version matching (much more precise).
    Without it we fall back to an exact keyword search on "product version".
    """
    match_string = cpe_to_match_string(cpe)
    if match_string:
        # virtualMatchString also matches CVEs that say "versions up to 7.5",
        # a keyword search would miss those.
        url = NVD_API_URL
        params = {"virtualMatchString": match_string, "resultsPerPage": 100}
    elif product and version:
        # keywordExactMatch is a flag without a value, requests can't send that
        # with params=, so it goes directly in the URL.
        url = NVD_API_URL + "?keywordExactMatch"
        params = {"keywordSearch": f"{product} {version}", "resultsPerPage": 100}
    else:
        return []

    cache_key = url + json.dumps(params, sort_keys=True)
    # The lock is needed because devices are scanned in parallel threads:
    # without it 4 threads would hit NVD at the same time and get blocked.
    with _nvd_lock:
        cache = _load_cache()
        cached = cache.get(cache_key)
        if cached and time.time() - cached["time"] < NVD_CACHE_DAYS * 86400:
            return [dict(vulnerability) for vulnerability in cached["cves"]]

        vulnerabilities = _parse_nvd_response(_nvd_get(url, params, api_key))
        cache[cache_key] = {"time": time.time(), "cves": vulnerabilities}
        _save_cache()
    return [dict(vulnerability) for vulnerability in vulnerabilities]


def load_kev(offline: bool = False) -> set[str]:
    """Returns the CVE ids in the CISA Known Exploited Vulnerabilities catalog (cached for a day)."""
    cached_ids: list[str] = []
    try:
        cached = json.loads(KEV_CACHE_FILE.read_text(encoding="utf-8"))
        cached_ids = cached.get("ids", [])
        if offline or time.time() - cached.get("time", 0) < KEV_CACHE_DAYS * 86400:
            return set(cached_ids)
    except (OSError, json.JSONDecodeError):
        if offline:
            return set()

    try:
        response = requests.get(KEV_URL, timeout=20)
        response.raise_for_status()
        ids = [item["cveID"] for item in response.json().get("vulnerabilities", []) if "cveID" in item]
    except (requests.RequestException, ValueError, KeyError):
        return set(cached_ids)

    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        KEV_CACHE_FILE.write_text(json.dumps({"time": time.time(), "ids": ids}), encoding="utf-8")
    except OSError:
        pass
    return set(ids)


def mark_known_exploited(vulnerabilities: list[dict], kev_ids: set[str]) -> None:
    """Sets known_exploited=True on the CVEs that are in the CISA KEV list."""
    for vulnerability in vulnerabilities:
        vulnerability["known_exploited"] = vulnerability.get("id") in kev_ids


def extract_script_findings(ports: list[dict]) -> list[str]:
    """Keeps only the Nmap script outputs that really report something VULNERABLE."""
    findings = []
    for port in ports:
        for name, output in (port.get("scripts") or {}).items():
            text = str(output)
            upper = text.upper()
            # Most vuln scripts print something even when nothing is wrong
            # (e.g. "Couldn't find any CSRF"), so we only keep real positives.
            if "VULNERABLE" not in upper or "NOT VULNERABLE" in upper:
                continue
            lines = [line.strip(" |_\t") for line in text.splitlines() if line.strip(" |_\t")]
            title = next((line for line in lines if "VULNERABLE" not in line.upper()), lines[0] if lines else name)
            cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
            cve_text = f" ({', '.join(cves)})" if cves else ""
            where = "host" if port.get("protocol") == "host" else f"{port.get('port')}/{port.get('protocol', 'tcp')}"
            findings.append(f"{where} {name}: {title}{cve_text}")
    return findings
