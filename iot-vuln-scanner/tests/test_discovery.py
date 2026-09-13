from types import SimpleNamespace

from src import discovery


def test_scan_network_returns_arp_answers(monkeypatch):
    def fake_srp(request, iface, timeout, verbose):
        assert iface
        assert timeout == 3
        assert verbose is False
        return [
            (None, SimpleNamespace(psrc="192.168.1.10", hwsrc="AA:BB:CC:DD:EE:FF"))
        ], []

    monkeypatch.setattr(discovery, "srp", fake_srp)

    assert discovery.scan_network("192.168.1.0/24", timeout=3) == [
        {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}
    ]


def test_scan_network_returns_empty_list_without_answers(monkeypatch):
    monkeypatch.setattr(discovery, "srp", lambda *args, **kwargs: ([], []))

    assert discovery.scan_network("192.168.1.0/24") == []