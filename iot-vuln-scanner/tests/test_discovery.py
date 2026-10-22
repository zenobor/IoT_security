import ipaddress
from types import SimpleNamespace

from src import discovery


def test_scan_network_returns_arp_answers(monkeypatch):
    def fake_srp(request, iface, timeout, verbose):
        assert iface
        assert timeout == 3
        assert verbose is False
        return [
            (None, SimpleNamespace(psrc="192.168.1.20", hwsrc="11:22:33:44:55:66")),
            (None, SimpleNamespace(psrc="192.168.1.10", hwsrc="AA:BB:CC:DD:EE:FF")),
            (None, SimpleNamespace(psrc="192.168.1.10", hwsrc="AA:BB:CC:DD:EE:FF")),
        ], []

    monkeypatch.setattr(discovery, "srp", fake_srp)

    # sorted by IP and without duplicates
    assert discovery.scan_network("192.168.1.0/24", timeout=3) == [
        {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"},
        {"ip": "192.168.1.20", "mac": "11:22:33:44:55:66"},
    ]


def test_scan_network_returns_empty_list_without_answers(monkeypatch):
    monkeypatch.setattr(discovery, "srp", lambda *args, **kwargs: ([], []))

    assert discovery.scan_network("192.168.1.0/24") == []


def test_detect_local_network_from_routes(monkeypatch):
    def ip(text):
        return int(ipaddress.ip_address(text))

    fake_route = SimpleNamespace(
        route=lambda destination: ("eth0", "192.168.50.23", "192.168.50.1"),
        routes=[
            (0, 0, "192.168.50.1", "eth0", "192.168.50.23", 1),  # default route
            (ip("224.0.0.0"), ip("240.0.0.0"), "0.0.0.0", "eth0", "192.168.50.23", 1),  # multicast
            (ip("192.168.50.0"), ip("255.255.255.0"), "0.0.0.0", "eth0", "192.168.50.23", 1),
        ],
    )
    monkeypatch.setattr(discovery, "conf", SimpleNamespace(route=fake_route))

    assert discovery.detect_local_network() == "192.168.50.0/24"


def test_detect_local_network_falls_back_to_24(monkeypatch):
    fake_route = SimpleNamespace(route=lambda destination: ("eth0", "10.0.0.7", "10.0.0.1"), routes=[])
    monkeypatch.setattr(discovery, "conf", SimpleNamespace(route=fake_route))

    assert discovery.detect_local_network() == "10.0.0.0/24"


def test_parse_ssdp_headers():
    answer = "HTTP/1.1 200 OK\r\nSERVER: Linux UPnP/1.0 Sonos/70.3\r\nLOCATION: http://192.168.1.30:1400/xml\r\nST: upnp:rootdevice\r\n\r\n"

    headers = discovery._parse_ssdp_headers(answer)

    assert headers["server"] == "Linux UPnP/1.0 Sonos/70.3"
    assert headers["location"] == "http://192.168.1.30:1400/xml"
    assert headers["st"] == "upnp:rootdevice"
