from src.rules import check_telnet_open, check_upnp_exposed


def test_check_telnet_open_true():
    assert check_telnet_open([21, 23, 80]) is True


def test_check_telnet_open_false():
    assert check_telnet_open([21, 80]) is False


def test_check_upnp_exposed_true():
    assert check_upnp_exposed([1900]) is True


def test_check_upnp_exposed_false():
    assert check_upnp_exposed([80, 443]) is False
