from src import fingerprint
from src.fingerprint import build_nmap_arguments, get_vendor, identify_device, is_randomized_mac


def test_identify_camera_from_services():
    identity = identify_device(
        "Hikvision",
        [{"port": 554, "state": "open", "service": "rtsp", "product": "Hikvision camera", "version": "5.0"}],
    )

    assert identity["type"] == "IP camera"
    assert identity["vendor"] == "Hikvision"
    assert identity["model"] == "Hikvision camera"


def test_identify_device_from_vendor_hint():
    identity = identify_device("Espressif Inc.", [])
    assert identity["type"] == "Smart home device"


def test_identify_device_uses_ssdp_server_as_model():
    identity = identify_device("Unknown", [], {"server": "Linux UPnP/1.0 Sonos/70.3"})
    assert identity["type"] == "UPnP device"
    assert "Sonos" in identity["model"]


def test_closed_ports_do_not_change_the_type():
    identity = identify_device("Unknown", [{"port": 554, "state": "closed", "service": "rtsp"}])
    assert identity["type"] == "Unknown network device"


def test_randomized_mac_detection():
    assert is_randomized_mac("da:a1:19:00:00:01") is True
    assert is_randomized_mac("00:11:22:33:44:55") is False
    assert get_vendor("da:a1:19:00:00:01") == "Private (randomized) MAC"


def test_nmap_arguments():
    quick = build_nmap_arguments(None, "quick", vuln_scripts=False)
    full = build_nmap_arguments(None, "full", vuln_scripts=True)
    custom = build_nmap_arguments("22,80", "quick", vuln_scripts=False)

    assert "-sV" in quick and "1883" in quick and "--script" not in quick
    assert "1-1024" in full and '"vuln and safe"' in full
    assert "-p 22,80" in custom


def test_scan_ports_parses_nmap_output(monkeypatch):
    class FakeScanner:
        def scan(self, hosts, arguments):
            self.arguments = arguments

        def all_hosts(self):
            return ["192.168.1.10"]

        def __getitem__(self, ip):
            host = {"tcp": {80: {"state": "open", "name": "http", "product": "lighttpd", "version": "1.4", "cpe": "cpe:/a:lighttpd:lighttpd:1.4"}}}
            return type("Host", (dict,), {"all_protocols": lambda self: ["tcp"]})(host)

    monkeypatch.setattr(fingerprint, "_create_scanner", lambda nmap: FakeScanner())

    ports = fingerprint.scan_ports("192.168.1.10")

    assert ports == [
        {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "product": "lighttpd",
            "version": "1.4",
            "cpe": "cpe:/a:lighttpd:lighttpd:1.4",
            "scripts": {},
        }
    ]
