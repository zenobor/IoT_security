from src.rules import (
    check_adb_open,
    check_default_credentials,
    check_ftp_open,
    check_mqtt_open,
    check_insecure_http,
    check_rtsp_open,
    check_ssh_open,
    check_telnet_open,
    check_tr069_open,
    check_upnp_exposed,
    evaluate_rules,
)


def test_check_telnet_open():
    assert check_telnet_open([21, 23, 80]) is True
    assert check_telnet_open([2323]) is True
    assert check_telnet_open([21, 80]) is False


def test_check_upnp_exposed():
    assert check_upnp_exposed([1900]) is True
    assert check_upnp_exposed([80], answered_ssdp=True) is True
    assert check_upnp_exposed([80, 443]) is False
    # 5000 is also Synology / AirPlay, so it should not count as UPnP by itself
    assert check_upnp_exposed([5000]) is False


def test_check_extra_service_rules():
    assert check_ftp_open([21, 80]) is True
    assert check_ssh_open([22]) is True
    assert check_insecure_http([80]) is True
    assert check_insecure_http([80, 443]) is False
    assert check_adb_open([5555]) is True
    assert check_tr069_open([7547]) is True
    assert check_rtsp_open([8554]) is True
    assert check_rtsp_open([80]) is False
    assert check_mqtt_open([1883]) is True
    assert check_mqtt_open([8883]) is False


def test_default_credentials_matches_vendor_names():
    assert check_default_credentials("Hangzhou Hikvision Digital Technology Co.,Ltd.") is True
    assert check_default_credentials("TP-LINK TECHNOLOGIES CO.,LTD.") is True
    assert check_default_credentials("Raspberry Pi Trading Ltd") is True
    assert check_default_credentials("Apple, Inc.") is False


def test_default_credentials_ignores_unknown_and_empty_vendors():
    assert check_default_credentials("") is False
    assert check_default_credentials("Unknown") is False
    assert check_default_credentials("Private (randomized) MAC") is False


def test_default_credentials_uses_whole_words():
    # "axis" is in the list, "Maxis" must not match it
    assert check_default_credentials("Maxis Communications") is False
    assert check_default_credentials("Axis Communications AB") is True


def test_evaluate_rules_returns_all_flags():
    flags = evaluate_rules([23, 80, 5555], "Unknown")

    assert flags["telnet_open"] is True
    assert flags["insecure_http"] is True
    assert flags["adb_open"] is True
    assert flags["default_credentials"] is False
    assert flags["upnp_exposed"] is False
