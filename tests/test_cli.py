"""CLI integration tests: argument parsing and subcommand routing."""

import pytest

from throttle import cli, firewall, utils


@pytest.fixture(autouse=True)
def _root_and_state(as_root, temp_state_dir, fake_runner):
    """Every CLI test runs as root, with temp state and mocked subprocess."""

    # Default: pf reported disabled unless a test overrides it.
    fake_runner.set_response("pfctl -s info", stdout="Status: Disabled")
    fake_runner.set_response("ifconfig", stdout="")
    fake_runner.set_response("arp", stdout="")
    fake_runner.set_response("route", stdout="interface: en0\n")
    return fake_runner


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def test_parser_requires_subcommand():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_parser_throttle_args():
    parser = cli.build_parser()
    args = parser.parse_args(
        ["throttle", "--bandwidth", "256k", "--ip", "192.168.2.10",
         "--packet-loss", "5", "--latency", "20"]
    )
    assert args.bandwidth == "256k"
    assert args.ip == "192.168.2.10"
    assert args.packet_loss == 5.0
    assert args.latency == 20


def test_dry_run_flag_parsed():
    parser = cli.build_parser()
    args = parser.parse_args(["--dry-run", "status"])
    assert args.dry_run is True


# ---------------------------------------------------------------------------
# throttle command
# ---------------------------------------------------------------------------
def test_throttle_command_persists_state():
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["throttle", "--bandwidth", "256k", "--ip", "192.168.2.10"])
    assert rc == 0
    state = utils.load_state()
    assert state["devices"]["192.168.2.10"]["bandwidth"] == 256


def test_throttle_requires_target():
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["throttle", "--bandwidth", "256k"])
    assert rc == 1


def test_throttle_all_devices(fake_runner, arp_output):
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    fake_runner.set_response("arp -a -i bridge100", stdout=arp_output)
    rc = cli.main(["throttle", "--bandwidth", "1m", "--all"])
    assert rc == 0
    state = utils.load_state()
    assert "192.168.2.10" in state["devices"]


def test_throttle_bandwidth_zero_blocks():
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["throttle", "--bandwidth", "0", "--ip", "192.168.2.10"])
    assert rc == 0
    state = utils.load_state()
    assert state["devices"]["192.168.2.10"]["bandwidth"] == 0


def test_throttle_invalid_bandwidth_returns_error():
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["throttle", "--bandwidth", "bogus", "--ip", "192.168.2.10"])
    assert rc == 1


# ---------------------------------------------------------------------------
# block / unblock commands
# ---------------------------------------------------------------------------
def test_block_command_adds_block_ips():
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(
        ["block", "--ip", "192.168.2.10", "--block-ips", "8.8.8.8,1.1.1.1"]
    )
    assert rc == 0
    state = utils.load_state()
    assert state["devices"]["192.168.2.10"]["block_ips"] == ["8.8.8.8", "1.1.1.1"]


def test_block_allow_only_mode():
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(
        ["block", "--ip", "192.168.2.10", "--allow-only-ips", "10.0.0.0/24"]
    )
    assert rc == 0
    state = utils.load_state()
    assert state["devices"]["192.168.2.10"]["allow_only_ips"] == ["10.0.0.0/24"]


def test_block_requires_ips():
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["block", "--ip", "192.168.2.10"])
    assert rc == 1


def test_block_invalid_ip_returns_error():
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["block", "--ip", "192.168.2.10", "--block-ips", "999.1.1.1"])
    assert rc == 1


def test_unblock_specific_ip():
    state = utils.default_state()
    state["bridge_interface"] = "bridge100"
    state["devices"]["192.168.2.10"] = utils.new_device_entry("m", 1, 2)
    state["devices"]["192.168.2.10"]["block_ips"] = ["8.8.8.8", "1.1.1.1"]
    utils.save_state(state)

    rc = cli.main(["unblock", "--ip", "192.168.2.10", "--block-ips", "8.8.8.8"])
    assert rc == 0
    result = utils.load_state()
    assert result["devices"]["192.168.2.10"]["block_ips"] == ["1.1.1.1"]


def test_unblock_all_clears_blocks():
    state = utils.default_state()
    state["bridge_interface"] = "bridge100"
    state["devices"]["192.168.2.10"] = utils.new_device_entry("m", 1, 2)
    state["devices"]["192.168.2.10"]["block_ips"] = ["8.8.8.8"]
    utils.save_state(state)

    rc = cli.main(["unblock", "--ip", "192.168.2.10"])
    assert rc == 0
    result = utils.load_state()
    assert result["devices"]["192.168.2.10"]["block_ips"] == []


def test_unblock_nonexistent_device_is_noop():
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["unblock", "--ip", "192.168.2.50"])
    assert rc == 0


def test_unblock_clear_allow():
    state = utils.default_state()
    state["bridge_interface"] = "bridge100"
    state["devices"]["192.168.2.10"] = utils.new_device_entry("m", 1, 2)
    state["devices"]["192.168.2.10"]["allow_only_ips"] = ["1.1.1.1"]
    utils.save_state(state)

    rc = cli.main(["unblock", "--ip", "192.168.2.10", "--clear-allow"])
    assert rc == 0
    result = utils.load_state()
    assert result["devices"]["192.168.2.10"]["allow_only_ips"] == []


def test_unblock_clear_allow_also_clears_blocks():
    state = utils.default_state()
    state["bridge_interface"] = "bridge100"
    state["devices"]["192.168.2.10"] = utils.new_device_entry("m", 1, 2)
    state["devices"]["192.168.2.10"]["block_ips"] = ["8.8.8.8"]
    state["devices"]["192.168.2.10"]["allow_only_ips"] = ["1.1.1.1"]
    utils.save_state(state)

    rc = cli.main(["unblock", "--ip", "192.168.2.10", "--clear-allow"])
    assert rc == 0
    result = utils.load_state()
    assert result["devices"]["192.168.2.10"]["block_ips"] == []
    assert result["devices"]["192.168.2.10"]["allow_only_ips"] == []


def test_block_flushes_device_states(fake_runner):
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["block", "--ip", "192.168.2.10", "--block-ips", "8.8.8.8"])
    assert rc == 0
    assert "pfctl -k 192.168.2.10" in fake_runner.commands()


def test_throttle_flushes_device_states(fake_runner):
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["throttle", "--bandwidth", "256k", "--ip", "192.168.2.10"])
    assert rc == 0
    assert "pfctl -k 192.168.2.10" in fake_runner.commands()


def test_unblock_flushes_device_states(fake_runner):
    state = utils.default_state()
    state["bridge_interface"] = "bridge100"
    state["devices"]["192.168.2.10"] = utils.new_device_entry("m", 1, 2)
    state["devices"]["192.168.2.10"]["block_ips"] = ["8.8.8.8"]
    utils.save_state(state)

    rc = cli.main(["unblock", "--ip", "192.168.2.10"])
    assert rc == 0
    assert "pfctl -k 192.168.2.10" in fake_runner.commands()


# ---------------------------------------------------------------------------
# status / list-devices
# ---------------------------------------------------------------------------
def test_status_runs(capsys):
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["status"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "mac-network-throttle status" in out


def test_list_devices_requires_bridge():
    utils.save_state(utils.default_state())
    rc = cli.main(["list-devices"])
    assert rc == 1


def test_list_devices_outputs_table(fake_runner, arp_output, capsys):
    state = utils.default_state()
    state["bridge_interface"] = "bridge100"
    state["devices"]["192.168.2.10"] = utils.new_device_entry(
        "aa:bb:cc:dd:ee:ff", 1, 2
    )
    state["devices"]["192.168.2.10"]["bandwidth"] = 256
    utils.save_state(state)
    fake_runner.set_response("arp -a -i bridge100", stdout=arp_output)

    rc = cli.main(["list-devices"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "192.168.2.10" in out
    assert "256 kbps" in out


# ---------------------------------------------------------------------------
# privilege enforcement
# ---------------------------------------------------------------------------
def test_non_root_throttle_errors(monkeypatch):
    monkeypatch.setattr(utils, "is_root", lambda: False)
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["throttle", "--bandwidth", "256k", "--ip", "192.168.2.10"])
    assert rc == 1


def test_dry_run_allows_non_root(monkeypatch, capsys):
    monkeypatch.setattr(utils, "is_root", lambda: False)
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["--dry-run", "throttle", "--bandwidth", "256k",
                   "--ip", "192.168.2.10"])
    assert rc == 0


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------
def test_start_no_wait(fake_runner, ifconfig_output, capsys):
    fake_runner.set_response("ifconfig", stdout=ifconfig_output)
    rc = cli.main(["start", "--ssid", "TestNet", "--no-wait", "--source", "en0"])
    assert rc == 0
    state = utils.load_state()
    assert state["running"] is True
    assert state["bridge_interface"] == "bridge100"


def test_start_without_bridge_returns_pending(fake_runner):
    fake_runner.set_response("ifconfig", stdout="")  # no bridge yet
    rc = cli.main(["start", "--no-wait", "--source", "en0"])
    assert rc == 2


# ---------------------------------------------------------------------------
# monitor
# ---------------------------------------------------------------------------
def test_monitor_command(fake_runner, tcpdump_output, capsys):
    state = utils.default_state()
    state["bridge_interface"] = "bridge100"
    utils.save_state(state)
    fake_runner.set_response("tcpdump", stdout=tcpdump_output)
    fake_runner.set_response("host", stdout="")

    rc = cli.main(["monitor", "--ip", "192.168.2.2", "--duration", "3", "--no-resolve"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "142.250.183.14" in out
    # Suggests a ready-to-run block command for the busiest public endpoint.
    assert "block --ip 192.168.2.2 --block-ips 142.250.183.14" in out


def test_monitor_requires_bridge(fake_runner):
    utils.save_state(utils.default_state())
    fake_runner.set_response("ifconfig", stdout="")
    rc = cli.main(["monitor", "--ip", "192.168.2.2"])
    assert rc == 1


def test_monitor_invalid_ip(fake_runner):
    state = utils.default_state()
    state["bridge_interface"] = "bridge100"
    utils.save_state(state)
    rc = cli.main(["monitor", "--ip", "999.1.1.1"])
    assert rc == 1
