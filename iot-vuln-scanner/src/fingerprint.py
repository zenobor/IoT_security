"""
fingerprint.py
Identifies vendor, hostname, open services and device type for each device.
"""

import os
import socket


# Ports checked in quick mode: the usual suspects plus ports that IoT devices love
# (MQTT, RTSP, ADB, TR-069, Tuya, Chromecast, Plex, alternative Telnet...).
IOT_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 139, 143, 443, 445, 515, 554, 631,
    1080, 1883, 1900, 2323, 3000, 3306, 3389, 4840, 5000, 5001, 5432, 5555, 5900,
    6379, 6668, 7000, 7547, 8000, 8008, 8009, 8080, 8081, 8443, 8554, 8883, 8888,
    9000, 9100, 9200, 32400, 49152,
]
QUICK_PORTS = ",".join(str(port) for port in IOT_PORTS)
FULL_PORTS = "1-1024," + ",".join(str(port) for port in IOT_PORTS if port > 1024)

# Words in the MAC vendor name that tell us what kind of device it probably is.
VENDOR_HINTS = [
    (("hikvision", "dahua", "reolink", "axis communications", "foscam", "amcrest", "ezviz", "wyze"), "IP camera"),
    (("espressif", "tuya", "shelly", "sonoff", "itead", "lifx", "signify", "philips lighting"), "Smart home device"),
    (("amazon",), "Amazon device (Echo / Fire TV)"),
    (("google", "nest labs"), "Google / Nest device"),
    (("sonos",), "Smart speaker"),
    (("roku", "lg electronics", "samsung electronics", "tcl", "hisense"), "Smart TV or media player"),
    (("brother", "epson", "canon", "lexmark", "kyocera"), "Network printer"),
    (("tp-link", "netgear", "ubiquiti", "mikrotik", "zyxel", "avm", "d-link", "tenda", "huawei", "zte", "technicolor", "sagemcom"), "Router or network device"),
    (("raspberry pi",), "Raspberry Pi"),
    (("synology", "qnap", "western digital"), "Network storage (NAS)"),
]


def _create_scanner(nmap):
    search_paths = [
        path
        for path in (
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
        )
        if os.path.exists(path)
    ]
    return nmap.PortScanner(nmap_search_path=("nmap", *search_paths))


def is_randomized_mac(mac_address: str) -> bool:
    """Phones and laptops often use a random ("private") MAC. Its 2nd hex digit is 2, 6, A or E."""
    cleaned = mac_address.replace(":", "").replace("-", "")
    return len(cleaned) >= 2 and cleaned[1].lower() in "26ae"


_mac_lookup = None


def get_vendor(mac_address: str) -> str:
    """Returns the manufacturer name from the MAC address (OUI lookup)."""
    global _mac_lookup
    if is_randomized_mac(mac_address):
        return "Private (randomized) MAC"
    try:
        if _mac_lookup is None:
            from mac_vendor_lookup import MacLookup

            _mac_lookup = MacLookup()
        return _mac_lookup.lookup(mac_address)
    except Exception:
        return "Unknown"


def get_hostname(ip: str) -> str:
    """Try to resolve a friendly hostname (reverse DNS) without failing the scan."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return "Unknown hostname"


def identify_device(vendor: str, ports: list[dict], ssdp: dict | None = None) -> dict[str, str]:
    """Builds a readable device identity from vendor, open services and the SSDP answer."""
    open_ports = [port for port in ports if port.get("state") == "open"]
    services = {str(port.get("service", "")).lower() for port in open_ports}
    port_numbers = {port.get("port") for port in open_ports}
    products = [str(port.get("product", "")).strip() for port in open_ports if port.get("product")]
    versions = [str(port.get("version", "")).strip() for port in open_ports if port.get("version")]
    ssdp_server = (ssdp or {}).get("server", "")

    vendor_name = vendor if vendor and vendor != "Unknown" else "Unknown vendor"
    model = products[0] if products else (ssdp_server or "Unknown model")
    lowered_vendor = vendor_name.lower()
    vendor_type = next(
        (device_type for words, device_type in VENDOR_HINTS if any(word in lowered_vendor for word in words)),
        None,
    )

    if "rtsp" in services or port_numbers & {554, 8554}:
        device_type = "IP camera"
    elif vendor_type:
        device_type = vendor_type
    elif "ipp" in services or 9100 in port_numbers:
        device_type = "Network printer"
    elif 5555 in port_numbers:
        device_type = "Android device (TV box / phone)"
    elif "ssh" in services and ("http" in services or "https" in services):
        device_type = "Network device or IoT gateway"
    elif "http" in services or "https" in services:
        device_type = "Web-enabled IoT device"
    elif "microsoft-ds" in services or 445 in port_numbers:
        device_type = "Computer or network storage"
    elif ssdp_server:
        device_type = "UPnP device"
    elif vendor_name == "Private (randomized) MAC":
        device_type = "Phone or laptop (private MAC)"
    else:
        device_type = "Unknown network device"

    if products:
        confidence = "Nmap service match"
    elif vendor_type or ssdp_server:
        confidence = "vendor / UPnP estimate"
    else:
        confidence = "service-based estimate"

    return {
        "type": device_type,
        "vendor": vendor_name,
        "model": model,
        "version": versions[0] if versions else "Unknown version",
        "confidence": confidence,
    }


def build_nmap_arguments(port_spec: str | None, mode: str, vuln_scripts: bool) -> str:
    """Builds the Nmap command line. Full mode scans more ports and can add the safe vuln scripts."""
    if port_spec:
        arguments = f"-T4 -sV --version-light -p {port_spec} --host-timeout 60s"
    elif mode == "full":
        arguments = f"-T4 -sV -p {FULL_PORTS} --host-timeout 180s"
    else:
        arguments = f"-T4 -sV --version-light -p {QUICK_PORTS} --host-timeout 60s"
    if vuln_scripts:
        # "vuln and safe" skips the scripts that could crash a device (DoS / intrusive ones).
        arguments += ' --script "vuln and safe" --script-timeout 30s'
    return arguments


def scan_ports(
    ip: str,
    port_spec: str | None = None,
    mode: str = "quick",
    vuln_scripts: bool = False,
) -> list[dict]:
    """Returns the ports, services and versions found by Nmap on one IP (one single Nmap run)."""
    try:
        import nmap
    except ImportError as exc:
        raise RuntimeError(
            "python-nmap is not installed. Run: pip install -r requirements.txt"
        ) from exc

    try:
        scanner = _create_scanner(nmap)
    except nmap.nmap.PortScannerError as exc:
        raise RuntimeError(
            "Nmap was not found. Install Nmap and reopen the terminal (see: python main.py doctor)."
        ) from exc

    try:
        scanner.scan(hosts=ip, arguments=build_nmap_arguments(port_spec, mode, vuln_scripts))
    except nmap.nmap.PortScannerError as exc:
        raise RuntimeError(f"Nmap scan failed for {ip}: {exc}") from exc

    if ip not in scanner.all_hosts():
        raise RuntimeError(f"Nmap got no answer from {ip} (host timed out or blocked the scan)")

    ports = []
    for protocol in scanner[ip].all_protocols():
        for port in sorted(scanner[ip][protocol]):
            service = scanner[ip][protocol][port]
            ports.append(
                {
                    "port": port,
                    "protocol": protocol,
                    "state": service.get("state", "unknown"),
                    "service": service.get("name", "unknown"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "cpe": service.get("cpe", ""),
                    "scripts": service.get("script", {}),
                }
            )

    # Some vuln scripts (e.g. smb-vuln-*) report for the whole host, not for a port.
    host_scripts = {
        script.get("id", "script"): script.get("output", "")
        for script in scanner[ip].get("hostscript", [])
    }
    if host_scripts:
        ports.append({"port": 0, "protocol": "host", "state": "host-script", "service": "", "scripts": host_scripts})

    return ports
