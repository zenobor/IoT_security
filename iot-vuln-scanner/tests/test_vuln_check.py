import pytest

from src import vuln_check


NVD_ANSWER = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-0001",
                "descriptions": [{"lang": "en", "value": "Low bug"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.1, "baseSeverity": "LOW"}}]},
            }
        },
        {
            "cve": {
                "id": "CVE-2023-0002",
                "descriptions": [{"lang": "es", "value": "Hola"}, {"lang": "en", "value": "Critical bug"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            }
        },
    ]
}


@pytest.fixture(autouse=True)
def temporary_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(vuln_check, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(vuln_check, "NVD_CACHE_FILE", tmp_path / "nvd_cache.json")
    monkeypatch.setattr(vuln_check, "KEV_CACHE_FILE", tmp_path / "kev.json")
    monkeypatch.setattr(vuln_check, "_nvd_cache", None)


def test_cpe_to_match_string():
    assert vuln_check.cpe_to_match_string("cpe:/a:openbsd:openssh:7.4") == "cpe:2.3:a:openbsd:openssh:7.4"
    assert vuln_check.cpe_to_match_string("cpe:/o:linux:linux_kernel") is None
    assert vuln_check.cpe_to_match_string("") is None


def test_check_nvd_uses_cpe_and_sorts_by_score(monkeypatch):
    calls = []

    def fake_get(url, params, api_key):
        calls.append(params)
        return NVD_ANSWER

    monkeypatch.setattr(vuln_check, "_nvd_get", fake_get)

    cves = vuln_check.check_nvd("OpenSSH", "7.4", cpe="cpe:/a:openbsd:openssh:7.4")

    assert calls[0]["virtualMatchString"] == "cpe:2.3:a:openbsd:openssh:7.4"
    assert [cve["id"] for cve in cves] == ["CVE-2023-0002", "CVE-2023-0001"]
    assert cves[0]["description"] == "Critical bug"
    assert cves[0]["severity"] == "CRITICAL"


def test_check_nvd_uses_the_cache(monkeypatch):
    calls = []
    monkeypatch.setattr(vuln_check, "_nvd_get", lambda url, params, api_key: calls.append(1) or NVD_ANSWER)

    vuln_check.check_nvd("lighttpd", "1.4")
    vuln_check.check_nvd("lighttpd", "1.4")

    assert len(calls) == 1
    assert vuln_check.NVD_CACHE_FILE.exists()


def test_check_nvd_skips_services_without_version(monkeypatch):
    monkeypatch.setattr(vuln_check, "_nvd_get", lambda *args: pytest.fail("NVD should not be called"))
    assert vuln_check.check_nvd("http", "") == []


def test_mark_known_exploited():
    cves = [{"id": "CVE-1"}, {"id": "CVE-2"}]
    vuln_check.mark_known_exploited(cves, {"CVE-2"})
    assert [cve["known_exploited"] for cve in cves] == [False, True]


def test_load_kev_offline_without_cache_is_empty():
    assert vuln_check.load_kev(offline=True) == set()


def test_extract_script_findings_keeps_only_vulnerable():
    ports = [
        {
            "port": 445,
            "protocol": "tcp",
            "scripts": {
                "smb-vuln-ms17-010": "\n  VULNERABLE:\n  Remote Code Execution in SMBv1\n    State: VULNERABLE\n    IDs: CVE:CVE-2017-0143",
                "http-csrf": "Couldn't find any CSRF vulnerabilities.",
                "ssl-heartbleed": "NOT VULNERABLE",
            },
        }
    ]

    findings = vuln_check.extract_script_findings(ports)

    assert findings == ["445/tcp smb-vuln-ms17-010: Remote Code Execution in SMBv1 (CVE-2017-0143)"]


def test_extract_script_findings_reads_host_scripts():
    ports = [{"port": 0, "protocol": "host", "state": "host-script", "scripts": {"smb-vuln-x": "State: VULNERABLE\nBad SMB"}}]
    assert vuln_check.extract_script_findings(ports) == ["host smb-vuln-x: Bad SMB"]
