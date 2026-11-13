"""
demo.py
A scan of a made-up home network, used by "python main.py demo".
Nothing is sent on the network and nothing is saved: it's for screenshots and presentations,
so you don't have to show your real IP and MAC addresses.
"""

import time
from datetime import datetime
from unittest.mock import patch

from src import diagnostics, fingerprint, scanner


NETWORK = "192.168.1.0/24"

# ip -> (mac, vendor, hostname, open ports as (port, service, product, version))
DEVICES = {
    "192.168.1.1": ("50:c7:bf:00:00:01", "TP-Link Technologies", "router.home",
                    [(53, "domain", "", ""), (80, "http", "", ""), (443, "https", "", ""), (7547, "tr069", "", "")]),
    "192.168.1.20": ("c0:56:e3:00:00:02", "Hangzhou Hikvision Digital Technology", "",
                     [(23, "telnet", "", ""), (80, "http", "Hikvision web", ""), (554, "rtsp", "", "")]),
    "192.168.1.35": ("10:d5:61:00:00:03", "Tuya Smart Inc.", "", [(6668, "irdmi", "", "")]),
    "192.168.1.42": ("b8:27:eb:00:00:04", "Raspberry Pi Foundation", "raspberrypi",
                     [(22, "ssh", "OpenSSH", "9.2p1"), (1883, "mqtt", "Mosquitto", "2.0")]),
    "192.168.1.57": ("82:05:57:00:00:05", "Private (randomized) MAC", "",
                     [(5000, "rtsp", "AirTunes", "870.14"), (7000, "rtsp", "AirTunes", "870.14")]),
    "192.168.1.88": ("3c:2a:f4:00:00:06", "Brother Industries", "",
                     [(80, "http", "", ""), (631, "ipp", "", ""), (9100, "jetdirect", "", "")]),
}
SSDP = {"192.168.1.1": {"server": "Linux UPnP/1.0 IGD", "location": "", "types": []}}
NETWORK_CHECKS = [
    {"name": "Wi-Fi security", "status": "OK", "details": "The current connection uses WPA3-Personal."},
    {"name": "IoT / guest isolation", "status": "MANUAL", "details": "Put IoT devices on a guest or separate network (VLAN)."},
    {"name": "Passwords", "status": "MANUAL", "details": "Make sure every device and the router use a unique password."},
]


def _ports(ip: str, **_options) -> list[dict]:
    time.sleep(0.6)  # so the progress bar is visible, like in a real scan
    return [
        {"port": port, "protocol": "tcp", "state": "open", "service": service,
         "product": product, "version": version, "cpe": "", "scripts": {}}
        for port, service, product, version in DEVICES[ip][3]
    ]


def options() -> scanner.ScanOptions:
    return scanner.ScanOptions(network=NETWORK, workers=2)


def discover() -> tuple[list[dict], dict]:
    time.sleep(1)
    return [{"ip": ip, "mac": data[0]} for ip, data in DEVICES.items()], SSDP


def analyse(devices: list[dict], scan_options: scanner.ScanOptions, on_done=None) -> list[dict]:
    """Runs the real analysis code, only the network functions are replaced by the fake data."""
    vendors = {data[0]: data[1] for data in DEVICES.values()}
    hostnames = {ip: data[2] or "Unknown hostname" for ip, data in DEVICES.items()}
    with (
        patch.object(fingerprint, "scan_ports", _ports),
        patch.object(fingerprint, "get_vendor", vendors.get),
        patch.object(fingerprint, "get_hostname", hostnames.get),
    ):
        return scanner.analyse_devices(devices, scan_options, SSDP, on_done=on_done)


def build(scan_options: scanner.ScanOptions, results: list[dict], started_at: datetime) -> dict:
    with patch.object(diagnostics, "network_checks", lambda: NETWORK_CHECKS):
        return scanner.build_scan(scan_options, results, started_at)

