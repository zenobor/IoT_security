"""
Entry point del tool.
"""

import argparse
import json
import re

import requests

from src import discovery
from src import deep_checks, fingerprint, report, rules, scoring, vuln_check
from src.terminal_report import print_summary


def _load_config(path: str | None) -> dict:
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as file:
            config = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not read config file: {exc}") from exc
    if not isinstance(config, dict):
        raise SystemExit("Config file must contain a JSON object")
    return config


def _validate_ports(port_spec: str | None) -> str | None:
    if port_spec is None:
        return None
    if not re.fullmatch(r"[0-9,-]+", port_spec):
        raise SystemExit("Ports must contain only numbers, commas and dashes")
    return port_spec


def main():
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config")
    config_args, _ = config_parser.parse_known_args()
    config = _load_config(config_args.config)

    parser = argparse.ArgumentParser(description="Scan an authorized local IoT network")
    parser.set_defaults(**config)
    parser.add_argument("--config", default=config_args.config)
    parser.add_argument("--network", default="192.168.1.0/24")
    parser.add_argument("--timeout", type=int, default=2)
    parser.add_argument("--ports", help="Ports to scan, for example 22,80,443,554")
    parser.add_argument("--output", default="scan_report.md")
    parser.add_argument("--html-output", help="Also save an HTML report")
    parser.add_argument("--csv-output", help="Also save a CSV report")
    parser.add_argument("--json-output", help="Also save the results as JSON")
    parser.add_argument(
        "--mode",
        choices=("quick", "full"),
        default="quick",
        help="quick is faster; full also runs vulnerability scripts",
    )
    parser.add_argument(
        "--nvd",
        action="store_true",
        help="Query the NVD API for possible CVEs",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Do not use NVD or other Internet services",
    )
    parser.set_defaults(**config)
    args = parser.parse_args()
    port_spec = _validate_ports(args.ports)

    ip_range = args.network
    print(f"Scansione della rete {ip_range}...")

    devices = discovery.scan_network(ip_range, timeout=args.timeout)
    print(f"Trovati {len(devices)} dispositivi.")

    results = []
    nvd_cache = {}
    for number, device in enumerate(devices, start=1):
        ip = device["ip"]
        print(f"Analysing device {number}/{len(devices)}: {ip}", flush=True)
        vendor = fingerprint.get_vendor(device["mac"])
        hostname = "Offline mode" if args.offline else fingerprint.get_hostname(ip)
        scan_errors = []
        print("  [1/3] Checking ports...", flush=True)
        try:
            ports = fingerprint.scan_ports(ip, port_spec=port_spec, mode=args.mode)
        except RuntimeError as exc:
            ports = []
            scan_errors.append(str(exc))
        identity = fingerprint.identify_device(vendor, ports)
        open_ports = [port["port"] for port in ports if port.get("state") == "open"]
        iot_flags = {
            "telnet_open": rules.check_telnet_open(open_ports),
            "ftp_open": rules.check_ftp_open(open_ports),
            "ssh_open": rules.check_ssh_open(open_ports),
            "insecure_http": rules.check_insecure_http(open_ports),
            "upnp_exposed": rules.check_upnp_exposed(open_ports),
            "default_credentials": rules.check_default_credentials(vendor, ip),
        }

        vulnerabilities = []
        if args.nvd and not args.offline:
            print("  [2/4] Checking NVD...", flush=True)
            for port in ports:
                product = port.get("product", "") or port.get("service", "")
                version = port.get("version", "")
                cache_key = (vendor, product, version)
                if product or version:
                    if cache_key not in nvd_cache:
                        try:
                            nvd_cache[cache_key] = vuln_check.check_nvd(
                                vendor, product, version
                            )
                        except requests.RequestException as exc:
                            scan_errors.append(f"NVD request failed: {exc}")
                            nvd_cache[cache_key] = []
                    vulnerabilities.extend(nvd_cache[cache_key])

        nmap_findings = []
        deep_findings = []
        if args.mode == "full":
            print("  [2/3] Running Nmap vulnerability scripts...", flush=True)
            try:
                nmap_findings = vuln_check.run_nmap_vuln_scripts(ip)
            except RuntimeError as exc:
                scan_errors.append(str(exc))
            print("  [3/3] Checking web panels and TLS...", flush=True)
            deep_findings = deep_checks.run_deep_checks(ip, open_ports)
        iot_flags["nmap_findings"] = nmap_findings
        iot_flags["deep_checks"] = deep_findings
        result = {
            **device,
            "hostname": hostname,
            "vendor": vendor,
            "identity": identity,
            "ports": ports,
            "vulnerabilities": vulnerabilities,
            "nmap_findings": nmap_findings,
            "deep_checks": deep_findings,
            "scan_errors": scan_errors,
            "iot_flags": iot_flags,
        }
        result["risk"] = scoring.calculate_risk(vulnerabilities, iot_flags)
        results.append(result)

    report.generate_report(results, args.output)
    if args.json_output:
        report.generate_json_report(results, args.json_output)
    if args.html_output:
        report.generate_html_report(results, args.html_output)
    if args.csv_output:
        report.generate_csv_report(results, args.csv_output)
    print(f"Report salvato in {args.output}")
    print_summary(results, ip_range, args.mode, args.output)


if __name__ == "__main__":
    main()
