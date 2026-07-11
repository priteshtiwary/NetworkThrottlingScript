"""Tests that cleanup removes exactly what was added and restores prior state."""

import pytest

from throttle import cli, firewall, utils


@pytest.fixture(autouse=True)
def _root_and_state(as_root, temp_state_dir, fake_runner):
    fake_runner.set_response("pfctl -s info", stdout="Status: Disabled")
    fake_runner.set_response("ifconfig", stdout="")
    fake_runner.set_response("arp", stdout="")
    return fake_runner


def test_teardown_flushes_anchor_pipes_and_restores(fake_runner):
    state = utils.default_state()
    state["bridge_interface"] = "bridge100"
    state["pf_was_enabled"] = False
    utils.save_state(state)

    cli.teardown()
    commands = fake_runner.commands()

    assert f"pfctl -a {utils.PF_ANCHOR} -F all" in commands  # anchor flushed
    assert "dnctl -q flush" in commands                      # pipes flushed
    # Must NOT reload the file: that would flush Internet Sharing NAT anchors.
    assert not any("pfctl -f /etc/pf.conf" in c for c in commands)
    assert "pfctl -d" in commands                            # pf disabled (was off)


def test_teardown_keeps_pf_enabled_when_it_was_on(fake_runner):
    state = utils.default_state()
    state["pf_was_enabled"] = True
    utils.save_state(state)

    cli.teardown()
    commands = fake_runner.commands()
    assert not any("pfctl -f /etc/pf.conf" in c for c in commands)
    assert "pfctl -d" not in commands


def test_teardown_clears_state_file(fake_runner):
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    assert utils.load_state()["bridge_interface"] == "bridge100"

    cli.teardown()
    # State file removed -> fresh default returned.
    assert utils.load_state()["bridge_interface"] is None


def test_stop_when_nothing_running(fake_runner):
    # No state file at all -> stop must still succeed cleanly.
    utils.clear_state()
    rc = cli.main(["stop"])
    assert rc == 0
    # Even with nothing configured, cleanup commands are safe/idempotent.
    assert "dnctl -q flush" in fake_runner.commands()


def test_stop_keep_hotspot_does_not_unload_daemon(fake_runner):
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["stop", "--keep-hotspot"])
    assert rc == 0
    assert not any("launchctl unload" in c for c in fake_runner.commands())


def test_stop_default_stops_hotspot(fake_runner):
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    rc = cli.main(["stop"])
    assert rc == 0
    assert any("launchctl unload" in c for c in fake_runner.commands())


def test_dry_run_teardown_does_not_clear_state(fake_runner):
    utils.save_state({**utils.default_state(), "bridge_interface": "bridge100"})
    cli.teardown(dry_run=True)
    # Dry-run must not mutate persisted state.
    assert utils.load_state()["bridge_interface"] == "bridge100"


def test_cleanup_removes_exactly_added_rules_roundtrip(fake_runner):
    """Capture rule state before/after: after teardown the anchor is empty."""

    state = utils.default_state()
    state["bridge_interface"] = "bridge100"
    state["devices"]["192.168.2.10"] = utils.new_device_entry("m", 1, 2)
    state["devices"]["192.168.2.10"]["bandwidth"] = 256
    utils.save_state(state)

    # Rules exist before cleanup.
    before = firewall.build_anchor_rules(utils.load_state())
    assert "dummynet" in before

    cli.teardown()

    # After cleanup, state is gone so regenerated rules contain no device rules.
    after = firewall.build_anchor_rules(utils.load_state())
    assert "dummynet" not in after
    assert "192.168.2.10" not in after


def test_signal_handler_triggers_teardown(monkeypatch, fake_runner):
    called = {}

    def fake_teardown(dry_run=False, stop_hotspot=False):
        called["done"] = True

    monkeypatch.setattr(cli, "teardown", fake_teardown)
    cli._install_signal_handlers(dry_run=False)

    import signal

    handler = signal.getsignal(signal.SIGINT)
    with pytest.raises(SystemExit):
        handler(signal.SIGINT, None)
    assert called.get("done") is True
