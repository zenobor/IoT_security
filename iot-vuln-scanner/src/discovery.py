"""
discovery.py
Finds the active devices on the local network (ARP scan + SSDP/UPnP discovery).
"""

import ipaddress
import socket
import time

from scapy.config import conf
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


SSDP_ADDRESS = ("239.255.255.250", 1900)
SSDP_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def scan_network(ip_range: str, timeout: float = 2) -> list[dict[str, str]]:
    """
    Sends an ARP request to every address in the range and returns who answered.

    Args:
        ip_range: e.g. "192.168.1.0/24"
        timeout: seconds to wait for ARP replies

    Returns:
        List of dicts, e.g. [{"ip": "192.168.1.5", "mac": "aa:bb:cc:..."}]
    """
    # Broadcast MAC = every device on the LAN receives the "who has this IP?" question
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    # On Windows scapy sometimes picks the wrong interface (VPN, Hyper-V...),
    # so we ask the routing table which interface reaches this network.
    network_address = str(ipaddress.ip_network(ip_range, strict=False).network_address)
    interface, _, _ = conf.route.route(network_address)
    answered, _ = srp(request, iface=interface, timeout=timeout, verbose=False)

    # Some devices answer twice, the dict keeps only one entry per IP
    devices = {}
    for _, received in answered:
        devices.setdefault(received.psrc, {"ip": received.psrc, "mac": received.hwsrc})
    return sorted(devices.values(), key=lambda device: ipaddress.ip_address(device["ip"]))


def detect_local_network() -> str | None:
    """Guess the network (CIDR) of the interface used to reach the Internet."""
    try:
        _, local_ip, _ = conf.route.route("0.0.0.0")
    except Exception:
        return None
    if not local_ip or local_ip == "0.0.0.0":
        return None

    # Look for the "directly connected" route of our IP (gateway 0.0.0.0).
    # Example: 192.168.1.0 / 255.255.255.0 -> 192.168.1.0/24
    local_value = int(ipaddress.ip_address(local_ip))
    best = None
    for route in conf.route.routes:
        network, mask, gateway, _interface, address = route[:5]
        prefix = bin(mask).count("1")
        # skip host routes (/32), the default route (/0) and huge ranges
        if address != local_ip or gateway != "0.0.0.0" or not 16 <= prefix <= 30:
            continue
        # skip routes that don't contain our IP (e.g. the multicast 224.0.0.0/4 route)
        if local_value & mask != network:
            continue
        if best is None or prefix > best.prefixlen:
            best = ipaddress.ip_network((network, prefix))

    # Most home routers use a /24, so it's a good guess if nothing was found
    if best is None:
        best = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(best)


def _parse_ssdp_headers(text: str) -> dict[str, str]:
    headers = {}
    for line in text.split("\r\n")[1:]:
        name, separator, value = line.partition(":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    return headers


def discover_ssdp(timeout: float = 2) -> dict[str, dict]:
    """
    Sends one SSDP M-SEARCH (the UPnP discovery message) and collects the answers.

    Many IoT devices (TVs, speakers, cameras, routers) answer this, and their
    SERVER header often says what the device is.

    Returns:
        Dict keyed by IP, e.g. {"192.168.1.20": {"server": "...", "location": "...", "types": [...]}}
    """
    found: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except OSError:
        return found

    with sock:
        # TTL 2 is enough for a home network, the packet must not leave the LAN
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        # short timeout so the loop below can check the deadline often
        sock.settimeout(0.5)
        try:
            sock.sendto(SSDP_REQUEST.encode(), SSDP_ADDRESS)
        except OSError:
            return found

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, (ip, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            # One device can send many answers (one per UPnP service), we merge them
            headers = _parse_ssdp_headers(data.decode(errors="replace"))
            entry = found.setdefault(ip, {"server": "", "location": "", "types": []})
            entry["server"] = entry["server"] or headers.get("server", "")
            entry["location"] = entry["location"] or headers.get("location", "")
            service_type = headers.get("st", "")
            if service_type and service_type not in entry["types"]:
                entry["types"].append(service_type)

    return found
