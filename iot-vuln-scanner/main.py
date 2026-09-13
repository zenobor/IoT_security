"""
Entry point del tool.
"""

from src import discovery


def main():
    ip_range = "192.168.1.0/24"  # TODO: rendere configurabile (argparse)
    print(f"Scansione della rete {ip_range}...")

    devices = discovery.scan_network(ip_range)
    print(f"Trovati {len(devices)} dispositivi.")

    # TODO: chiamare fingerprint, vuln_check, rules, scoring, report


if __name__ == "__main__":
    main()
