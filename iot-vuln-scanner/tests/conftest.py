import pytest


def make_device(ip="192.168.1.10", risk="low", ports=None, **extra):
    """Small fake device result used by many tests."""
    device = {
        "ip": ip,
        "mac": "00:11:22:33:44:55",
        "hostname": "camera.local",
        "vendor": "Test vendor",
        "identity": {"type": "IP camera", "vendor": "Test vendor", "model": "Cam 1"},
        "ports": ports if ports is not None else [{"port": 554, "service": "rtsp", "state": "open"}],
        "vulnerabilities": [],
        "nmap_findings": [],
        "deep_checks": [],
        "scan_errors": [],
        "iot_flags": {},
        "risk": risk,
    }
    device.update(extra)
    return device


def make_scan(devices, **scan_info):
    info = {
        "network": "192.168.1.0/24",
        "mode": "quick",
        "started_at": "2026-10-22T10:00:00",
        "network_score": 80,
        "risk_counts": {"high": 0, "medium": 0, "low": len(devices)},
    }
    info.update(scan_info)
    return {
        "scan": info,
        "network_checks": [{"name": "Wi-Fi security", "status": "OK", "details": "WPA2"}],
        "devices": devices,
    }


@pytest.fixture
def device_factory():
    return make_device


@pytest.fixture
def scan_factory():
    return make_scan
