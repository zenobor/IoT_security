"""
vuln_check.py
Verifica vulnerabilità note (CVE) per servizi/versioni rilevati.
"""


def check_nvd(vendor: str, product: str, version: str) -> list[dict]:
    """Interroga la NVD API per CVE note relative a vendor/prodotto/versione."""
    # TODO: chiamata HTTP a NVD API (https://nvd.nist.gov/developers)
    raise NotImplementedError


def run_nmap_vuln_scripts(ip: str) -> list[str]:
    """Esegue gli script nmap --script vuln su un host."""
    # TODO: wrapper subprocess/python-nmap
    raise NotImplementedError
