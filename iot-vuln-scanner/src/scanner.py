"""
scanner.py
Connects all the pieces: discovery -> fingerprint -> rules -> CVEs -> deep checks -> score.
The terminal code in main.py only shows the progress, all the work happens here.
"""

import ipaddress
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime

import requests

from src import deep_checks, diagnostics, discovery, fingerprint, rules, scoring, vuln_check


VERSION = "1.1.0"


@dataclass
class ScanOptions:
    network: str
    mode: str = "quick"
    timeout: float = 2
    ports: str | None = None
    nvd: bool = False
    offline: bool = False
    workers: int = 4
    nvd_api_key: str | None = None
    kev_ids: set[str] = field(default_factory=set)


def discover_devices(options: ScanOptions) -> tuple[list[dict], dict[str, dict]]:
    """Finds devices with ARP and asks them for UPnP info with SSDP."""
    devices = discovery.scan_network(options.network, timeout=options.timeout)
    network = ipaddress.ip_network(options.network, strict=False)
    ssdp = {
        ip: info
        for ip, info in discovery.discover_ssdp(timeout=min(options.timeout, 3)).items()
        if ipaddress.ip_address(ip) in network
    }

    # A device can answer SSDP even if it missed the ARP request.
    known_ips = {device["ip"] for device in devices}
    for ip in ssdp:
        if ip not in known_ips:
            devices.append({"ip": ip, "mac": "unknown"})
    devices.sort(key=lambda device: ipaddress.ip_address(device["ip"]))
    return devices, ssdp


def _lookup_cves(ports: list[dict], vendor: str, options: ScanOptions, errors: list[str]) -> list[dict]:
    vulnerabilities = []
    seen = set()
    for port in ports:
        if port.get("state") != "open":
            continue
        product = port.get("product", "") or port.get("service", "")
        version = port.get("version", "")
        try:
            found = vuln_check.check_nvd(product, version, cpe=port.get("cpe", ""), api_key=options.nvd_api_key)
        except requests.RequestException as exc:
            errors.append(f"NVD request failed: {exc.__class__.__name__}")
            break
        for vulnerability in found:
            if vulnerability["id"] in seen:
                continue
            seen.add(vulnerability["id"])
            vulnerability["service"] = f"{product} {version}".strip() or vendor
            vulnerability["port"] = port.get("port")
            vulnerabilities.append(vulnerability)
    vuln_check.mark_known_exploited(vulnerabilities, options.kev_ids)
    return vulnerabilities


def analyse_device(device: dict, options: ScanOptions, ssdp_info: dict | None = None) -> dict:
    """Runs every check on one device and returns its full result."""
    ip = device["ip"]
    started = time.monotonic()
    errors: list[str] = []

    vendor = fingerprint.get_vendor(device["mac"]) if device.get("mac", "unknown") != "unknown" else "Unknown"
    hostname = fingerprint.get_hostname(ip)

    try:
        ports = fingerprint.scan_ports(
            ip,
            port_spec=options.ports,
            mode=options.mode,
            vuln_scripts=options.mode == "full",
        )
    except RuntimeError as exc:
        ports = []
        errors.append(str(exc))

    # Nmap also returns closed/filtered ports, the rules must only see the open ones
    open_ports = [port["port"] for port in ports if port.get("state") == "open"]
    identity = fingerprint.identify_device(vendor, ports, ssdp_info)
    iot_flags = rules.evaluate_rules(open_ports, vendor, answered_ssdp=ssdp_info is not None)

    vulnerabilities = []
    if options.nvd and not options.offline:
        vulnerabilities = _lookup_cves(ports, vendor, options, errors)

    nmap_findings = vuln_check.extract_script_findings(ports)
    deep_findings = []
    if options.mode == "full" and open_ports:
        deep_findings = deep_checks.run_deep_checks(ip, open_ports, ports)

    iot_flags["nmap_findings"] = nmap_findings
    iot_flags["deep_checks"] = deep_findings
    points = scoring.calculate_points(vulnerabilities, iot_flags)

    return {
        **device,
        "hostname": hostname,
        "vendor": vendor,
        "identity": identity,
        "ssdp": ssdp_info or {},
        "ports": ports,
        "vulnerabilities": vulnerabilities,
        "nmap_findings": nmap_findings,
        "deep_checks": deep_findings,
        "scan_errors": errors,
        "iot_flags": iot_flags,
        "risk_points": points,
        "risk": scoring.risk_level(points),
        "scan_seconds": round(time.monotonic() - started, 1),
    }


def _result_or_error(future, device: dict) -> dict:
    try:
        return future.result()
    except Exception as exc:  # one broken device must not stop the whole scan
        return {
            **device,
            "hostname": "Unknown hostname",
            "vendor": "Unknown",
            "identity": {"type": "Unknown network device", "vendor": "Unknown vendor", "model": "Unknown model"},
            "ports": [],
            "vulnerabilities": [],
            "nmap_findings": [],
            "deep_checks": [],
            "iot_flags": {},
            "scan_errors": [f"Unexpected error: {exc}"],
            "risk_points": 0,
            "risk": "low",
        }


def analyse_devices(devices: list[dict], options: ScanOptions, ssdp: dict[str, dict], on_done=None) -> list[dict]:
    """Analyses the devices in parallel (one Nmap process per worker)."""
    # Threads are fine here: most of the time is spent waiting for Nmap and the
    # network, not in Python, so 4 workers make the scan about 4 times faster.
    results = []
    executor = ThreadPoolExecutor(max_workers=max(1, options.workers))
    futures = {
        executor.submit(analyse_device, device, options, ssdp.get(device["ip"])): device
        for device in devices
    }
    pending = set(futures)
    try:
        while pending:
            # Short timeout so Ctrl+C still works on Windows while we wait.
            done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
            for future in done:
                result = _result_or_error(future, futures[future])
                results.append(result)
                if on_done:
                    on_done(result)
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    executor.shutdown(wait=True)

    results.sort(key=lambda device: ipaddress.ip_address(device["ip"]))
    return results


def build_scan(options: ScanOptions, devices: list[dict], started_at: datetime) -> dict:
    """Puts everything in the dict that is saved as JSON and used by the reports."""
    finished_at = datetime.now()
    return {
        "scan": {
            "tool_version": VERSION,
            "network": options.network,
            "mode": options.mode,
            "nvd": options.nvd and not options.offline,
            "started_at": started_at.isoformat(timespec="seconds"),
            "finished_at": finished_at.isoformat(timespec="seconds"),
            "duration_seconds": round((finished_at - started_at).total_seconds()),
            "network_score": scoring.calculate_network_score(devices),
            "risk_counts": scoring.count_risks(devices),
        },
        "network_checks": diagnostics.network_checks(),
        "devices": devices,
    }
