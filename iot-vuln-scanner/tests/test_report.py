import csv
import json

from src.compare import compare_scans, has_changes
from src.report import generate_csv_report, generate_html_report, generate_json_report, generate_report


def test_markdown_report_has_summary_devices_and_fixes(tmp_path, device_factory, scan_factory):
    risky = device_factory(ip="192.168.1.20", risk="high", iot_flags={"telnet_open": True})
    safe = device_factory(ip="192.168.1.10", risk="low", ports=[{"port": 22, "service": "ssh", "state": "closed"}])
    output_path = tmp_path / "report.md"

    generate_report(scan_factory([safe, risky]), str(output_path))
    content = output_path.read_text(encoding="utf-8")

    assert "Network score | **80/100**" in content
    assert "192.168.1.10" in content and "192.168.1.20" in content
    assert "Telnet is open" in content
    assert "Fix: Disable Telnet" in content
    assert "Wi-Fi security" in content
    # closed ports must not be listed as open
    assert "22 (ssh)" not in content


def test_html_csv_and_json_reports(tmp_path, device_factory, scan_factory):
    scan = scan_factory([device_factory(risk="medium", iot_flags={"upnp_exposed": True})])

    generate_html_report(scan, str(tmp_path / "report.html"))
    generate_csv_report(scan, str(tmp_path / "report.csv"))
    generate_json_report(scan, str(tmp_path / "nested" / "results.json"))

    assert "camera.local" in (tmp_path / "report.html").read_text(encoding="utf-8")
    rows = list(csv.DictReader((tmp_path / "report.csv").open(encoding="utf-8")))
    assert rows[0]["ip"] == "192.168.1.10"
    assert rows[0]["issues"] == "UPnP is enabled"
    assert json.loads((tmp_path / "nested" / "results.json").read_text(encoding="utf-8"))["devices"]


def test_html_report_escapes_device_data(tmp_path, device_factory, scan_factory):
    device = device_factory(hostname="<script>alert(1)</script>")

    generate_html_report(scan_factory([device]), str(tmp_path / "report.html"))

    assert "<script>alert" not in (tmp_path / "report.html").read_text(encoding="utf-8")


def test_compare_scans(device_factory, scan_factory):
    camera = device_factory(ip="192.168.1.10", mac="aa:aa:aa:aa:aa:aa")
    printer = device_factory(ip="192.168.1.11", mac="bb:bb:bb:bb:bb:bb")
    old = scan_factory([camera, printer])

    camera_now = device_factory(
        ip="192.168.1.15",
        mac="aa:aa:aa:aa:aa:aa",
        risk="high",
        ports=[{"port": 554, "state": "open"}, {"port": 23, "state": "open"}],
    )
    phone = device_factory(ip="192.168.1.30", mac="cc:cc:cc:cc:cc:cc")
    new = scan_factory([camera_now, phone])

    diff = compare_scans(old, new)

    assert has_changes(diff)
    assert [device["ip"] for device in diff["new_devices"]] == ["192.168.1.30"]
    assert [device["ip"] for device in diff["missing_devices"]] == ["192.168.1.11"]
    change = diff["changed_devices"][0]
    assert change["opened_ports"] == [23]
    assert change["old_ip"] == "192.168.1.10" and change["ip"] == "192.168.1.15"
    assert (change["old_risk"], change["new_risk"]) == ("low", "high")


def test_compare_same_scan_has_no_changes(device_factory, scan_factory):
    scan = scan_factory([device_factory()])
    assert not has_changes(compare_scans(scan, scan))
