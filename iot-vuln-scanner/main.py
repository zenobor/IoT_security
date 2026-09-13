"""
Entry point del tool.
"""

import argparse

from src import discovery
from src import fingerprint, report, rules, scoring, vuln_check


def main():
    parser = argparse.ArgumentParser(description="Scan an authorized local IoT network")
    parser.add_argument("--network", default="192.168.1.0/24")
    parser.add_argument("--timeout", type=int, default=2)
    parser.add_argument("--output", default="scan_report.md")
    args = parser.parse_args()

    ip_range = args.network
    print(f"Scansione della rete {ip_range}...")

    devices = discovery.scan_network(ip_range, timeout=args.timeout)
    print(f"Trovati {len(devices)} dispositivi.")

    results = []
    for device in devices:
        ip = device["ip"]
        vendor = fingerprint.get_vendor(device["mac"])
        ports = fingerprint.scan_ports(ip)
        open_ports = [port["port"] for port in ports if port.get("state") == "open"]
        iot_flags = {
            "telnet_open": rules.check_telnet_open(open_ports),
            "upnp_exposed": rules.check_upnp_exposed(open_ports),
            "default_credentials": rules.check_default_credentials(vendor, ip),
        }

        vulnerabilities = []
        for port in ports:
            if port.get("product") or port.get("version"):
                vulnerabilities.extend(
                    vuln_check.check_nvd(
                        vendor,
                        port.get("product", "") or port.get("service", ""),
                        port.get("version", ""),
                    )
                )

        nmap_findings = vuln_check.run_nmap_vuln_scripts(ip)
        iot_flags["nmap_findings"] = nmap_findings
        result = {
            **device,
            "vendor": vendor,
            "ports": ports,
            "vulnerabilities": vulnerabilities,
            "nmap_findings": nmap_findings,
            "iot_flags": iot_flags,
        }
        result["risk"] = scoring.calculate_risk(vulnerabilities, iot_flags)
        results.append(result)

    report.generate_report(results, args.output)
    print(f"Report salvato in {args.output}")


if __name__ == "__main__":
    main()
