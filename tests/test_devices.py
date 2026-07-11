"""Unit tests for ARP parsing, device listing, and interface detection."""

from throttle import devices as devices_mod
from throttle import utils


# ---------------------------------------------------------------------------
# MAC normalisation
# ---------------------------------------------------------------------------
def test_normalize_mac_pads_octets():
    assert devices_mod.normalize_mac("a:b:c:1:2:3") == "0a:0b:0c:01:02:03"


def test_normalize_mac_lowercases():
    assert devices_mod.normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_incomplete_returns_none():
    assert devices_mod.normalize_mac("(incomplete)") is None
    assert devices_mod.normalize_mac("") is None
    assert devices_mod.normalize_mac("aa:bb:cc") is None
    assert devices_mod.normalize_mac("zz:zz:zz:zz:zz:zz") is None


# ---------------------------------------------------------------------------
# ARP parsing
# ---------------------------------------------------------------------------
def test_parse_arp_output_filters_interface(arp_output):
    parsed = devices_mod.parse_arp_output(arp_output, interface="bridge100")
    ips = {d.ip for d in parsed}
    assert "192.168.2.10" in ips
    assert "192.168.2.11" in ips
    # en0 entry excluded, incomplete entry excluded.
    assert "10.0.0.1" not in ips
    assert "192.168.2.12" not in ips


def test_parse_arp_output_normalises_mac(arp_output):
    parsed = devices_mod.parse_arp_output(arp_output, interface="bridge100")
    by_ip = {d.ip: d for d in parsed}
    assert by_ip["192.168.2.10"].mac == "aa:bb:cc:dd:ee:ff"
    assert by_ip["192.168.2.11"].mac == "0a:0b:0c:01:02:03"


def test_parse_arp_output_no_interface_returns_all(arp_output):
    parsed = devices_mod.parse_arp_output(arp_output)
    ips = {d.ip for d in parsed}
    assert "10.0.0.1" in ips


def test_parse_arp_output_dedupes():
    text = (
        "? (192.168.2.5) at aa:bb:cc:dd:ee:01 on bridge100 ifscope [ethernet]\n"
        "? (192.168.2.5) at aa:bb:cc:dd:ee:01 on bridge100 ifscope [ethernet]\n"
    )
    parsed = devices_mod.parse_arp_output(text, interface="bridge100")
    assert len(parsed) == 1


def test_parse_arp_output_empty():
    assert devices_mod.parse_arp_output("") == []


# ---------------------------------------------------------------------------
# discover_devices (mocked)
# ---------------------------------------------------------------------------
def test_discover_devices(fake_runner, arp_output):
    fake_runner.set_response("arp -a -i bridge100", stdout=arp_output)
    result = devices_mod.discover_devices("bridge100")
    ips = {d.ip for d in result}
    assert "192.168.2.10" in ips


def test_discover_devices_falls_back_without_interface_flag(fake_runner, arp_output):
    # First call (with -i) returns empty, fallback (arp -a) returns data.
    fake_runner.set_response("arp -a -i bridge100", stdout="")
    fake_runner.set_response("arp -a", stdout=arp_output)
    result = devices_mod.discover_devices("bridge100")
    assert any(d.ip == "192.168.2.10" for d in result)


def test_discover_devices_handles_failure(fake_runner):
    fake_runner.set_response("arp", stdout="", returncode=1)
    assert devices_mod.discover_devices("bridge100") == []


# ---------------------------------------------------------------------------
# merge_state
# ---------------------------------------------------------------------------
def test_merge_state_overlays_records():
    live = [devices_mod.Device(ip="192.168.2.10", mac="aa:bb:cc:dd:ee:ff",
                               interface="bridge100")]
    state = {
        "bridge_interface": "bridge100",
        "devices": {
            "192.168.2.10": {
                "mac": "aa:bb:cc:dd:ee:ff", "bandwidth": 256,
                "packet_loss": 5.0, "latency": 20,
                "block_ips": ["8.8.8.8"], "allow_only_ips": [],
            }
        },
    }
    merged = devices_mod.merge_state(live, state)
    assert merged[0].bandwidth == 256
    assert merged[0].block_ips == ["8.8.8.8"]


def test_merge_state_includes_offline_configured_devices():
    live = []
    state = {
        "bridge_interface": "bridge100",
        "devices": {
            "192.168.2.99": {
                "mac": "de:ad:be:ef:00:01", "bandwidth": 0,
                "packet_loss": 0, "latency": 0,
                "block_ips": [], "allow_only_ips": [],
            }
        },
    }
    merged = devices_mod.merge_state(live, state)
    assert len(merged) == 1
    assert merged[0].ip == "192.168.2.99"


def test_merge_state_sorts_by_ip():
    live = [
        devices_mod.Device(ip="192.168.2.20", mac="a", interface="bridge100"),
        devices_mod.Device(ip="192.168.2.3", mac="b", interface="bridge100"),
    ]
    merged = devices_mod.merge_state(live, {"devices": {}})
    assert [d.ip for d in merged] == ["192.168.2.3", "192.168.2.20"]


# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------
def test_parse_default_interface(route_default_output):
    assert utils.parse_default_interface(route_default_output) == "en0"


def test_parse_default_interface_missing():
    assert utils.parse_default_interface("no interface here") is None


def test_parse_bridge_interfaces(ifconfig_output):
    bridges = utils.parse_bridge_interfaces(ifconfig_output)
    # bridge100 has a member; bridge0 does not.
    assert bridges == ["bridge100"]


def test_get_bridge_interface(fake_runner, ifconfig_output):
    fake_runner.set_response("ifconfig", stdout=ifconfig_output)
    assert utils.get_bridge_interface() == "bridge100"


def test_get_active_internet_interface(fake_runner, route_default_output):
    fake_runner.set_response("route -n get default", stdout=route_default_output)
    assert utils.get_active_internet_interface() == "en0"


def test_get_active_internet_interface_failure(fake_runner):
    fake_runner.set_response("route", stdout="", returncode=1)
    assert utils.get_active_internet_interface() is None
