"""Unit tests for pf rule generation and IP validation."""

import pytest

from throttle import firewall, utils


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [
        ("192.168.1.1", "192.168.1.1"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("192.168.1.128/25", "192.168.1.128/25"),
        ("192.168.1.200/24", "192.168.1.0/24"),  # host bits masked
        ("8.8.8.8", "8.8.8.8"),
    ],
)
def test_validate_ip_or_cidr_valid(value, expected):
    assert firewall.validate_ip_or_cidr(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "999.1.1.1", "not-an-ip", "192.168.1.0/33", "10.0.0.0/-1", "1.2.3"],
)
def test_validate_ip_or_cidr_invalid(value):
    with pytest.raises(ValueError):
        firewall.validate_ip_or_cidr(value)


def test_validate_ip_list_dedupes_and_canonicalises():
    result = firewall.validate_ip_list("8.8.8.8, 8.8.8.8 ,10.0.0.5/24")
    assert result == ["8.8.8.8", "10.0.0.0/24"]


def test_validate_ip_list_from_iterable():
    result = firewall.validate_ip_list(["1.1.1.1", "", "2.2.2.2"])
    assert result == ["1.1.1.1", "2.2.2.2"]


def test_validate_ip_list_overlapping_cidrs_kept_distinct():
    # Overlapping ranges are distinct network strings and both retained.
    result = firewall.validate_ip_list("10.0.0.0/8,10.0.0.0/16")
    assert result == ["10.0.0.0/8", "10.0.0.0/16"]


# ---------------------------------------------------------------------------
# Per-device rule generation
# ---------------------------------------------------------------------------
def test_build_device_rules_throttle_only():
    record = {
        "bandwidth": 256, "download_pipe": 2, "upload_pipe": 1,
        "block_ips": [], "allow_only_ips": [],
    }
    rules = firewall.build_device_rules("192.168.2.10", record, "bridge100")
    assert rules == [
        "dummynet in on bridge100 from 192.168.2.10 to any pipe 1",
        "dummynet out on bridge100 from any to 192.168.2.10 pipe 2",
    ]


def test_build_device_rules_full_block_short_circuits():
    record = {"bandwidth": 0, "download_pipe": 2, "upload_pipe": 1}
    rules = firewall.build_device_rules("192.168.2.10", record, "bridge100")
    assert rules == [
        "block drop on bridge100 from 192.168.2.10 to any",
        "block drop on bridge100 from any to 192.168.2.10",
    ]


def test_build_device_rules_block_specific_ips():
    record = {
        "bandwidth": -1, "download_pipe": 2, "upload_pipe": 1,
        "block_ips": ["8.8.8.8"], "allow_only_ips": [],
    }
    rules = firewall.build_device_rules("192.168.2.10", record, "bridge100")
    assert "block drop on bridge100 from 192.168.2.10 to 8.8.8.8" in rules
    assert "block drop on bridge100 from 8.8.8.8 to 192.168.2.10" in rules
    # No dummynet rules when unlimited.
    assert not any("dummynet" in rule for rule in rules)


def test_build_device_rules_allow_only_mode():
    record = {
        "bandwidth": -1, "download_pipe": 2, "upload_pipe": 1,
        "block_ips": [], "allow_only_ips": ["1.1.1.1"],
    }
    rules = firewall.build_device_rules("192.168.2.10", record, "bridge100")
    # Deny-all must come before the permits (last-match-wins).
    deny_index = rules.index("block drop on bridge100 from 192.168.2.10 to any")
    pass_index = rules.index("pass on bridge100 from 192.168.2.10 to 1.1.1.1")
    assert deny_index < pass_index


def test_build_device_rules_throttle_plus_block_combined():
    record = {
        "bandwidth": 512, "download_pipe": 4, "upload_pipe": 3,
        "block_ips": ["9.9.9.9"], "allow_only_ips": [],
    }
    rules = firewall.build_device_rules("192.168.2.20", record, "bridge100")
    assert any("dummynet" in r for r in rules)
    assert "block drop on bridge100 from 192.168.2.20 to 9.9.9.9" in rules
    # Blocks come after shaping so they always win.
    assert rules.index("block drop on bridge100 from 192.168.2.20 to 9.9.9.9") > 1


# ---------------------------------------------------------------------------
# Anchor ruleset generation
# ---------------------------------------------------------------------------
def test_build_anchor_rules_empty_without_bridge():
    text = firewall.build_anchor_rules({"devices": {}})
    assert "Managed by mac-network-throttle" in text


def test_build_anchor_rules_multiple_devices():
    state = {
        "bridge_interface": "bridge100",
        "devices": {
            "192.168.2.10": {
                "bandwidth": 256, "download_pipe": 2, "upload_pipe": 1,
                "block_ips": [], "allow_only_ips": [],
            },
            "192.168.2.11": {
                "bandwidth": 0, "download_pipe": 4, "upload_pipe": 3,
                "block_ips": [], "allow_only_ips": [],
            },
        },
    }
    text = firewall.build_anchor_rules(state)
    assert "# device 192.168.2.10" in text
    assert "# device 192.168.2.11" in text
    assert "pipe 1" in text
    assert "block drop on bridge100 from any to 192.168.2.11" in text


# ---------------------------------------------------------------------------
# Augmented pf.conf
# ---------------------------------------------------------------------------
def test_build_augmented_pf_conf_appends_anchors():
    base = 'anchor "com.apple/*" all\n'
    text = firewall.build_augmented_pf_conf(base)
    assert f'dummynet-anchor "{utils.PF_ANCHOR}"' in text
    assert f'anchor "{utils.PF_ANCHOR}"' in text


def test_build_augmented_pf_conf_is_idempotent():
    base = 'anchor "com.apple/*" all\n'
    once = firewall.build_augmented_pf_conf(base)
    twice = firewall.build_augmented_pf_conf(once)
    assert once == twice


def test_build_augmented_pf_conf_adds_trailing_newline():
    text = firewall.build_augmented_pf_conf("anchor \"x\"")
    assert text.endswith("\n")


# ---------------------------------------------------------------------------
# pf mutations (mocked subprocess)
# ---------------------------------------------------------------------------
def test_is_pf_enabled_true(fake_runner, pfctl_info_output):
    fake_runner.set_response("pfctl -s info", stdout=pfctl_info_output)
    assert firewall.is_pf_enabled() is True


def test_is_pf_enabled_false(fake_runner):
    fake_runner.set_response("pfctl -s info", stdout="Status: Disabled")
    assert firewall.is_pf_enabled() is False


def test_enable_anchor_loads_and_enables(fake_runner, monkeypatch):
    monkeypatch.setattr(firewall, "read_system_pf_conf", lambda: "anchor \"x\"\n")
    firewall.enable_anchor()
    commands = fake_runner.commands()
    assert "pfctl -f -" in commands
    assert "pfctl -e" in commands
    # The augmented config with our anchor was piped in.
    assert any(utils.PF_ANCHOR in (text or "") for text in fake_runner.inputs())


def test_load_anchor_rules(fake_runner):
    firewall.load_anchor_rules("# rules\n")
    assert f"pfctl -a {utils.PF_ANCHOR} -f -" in fake_runner.commands()


def test_flush_anchor(fake_runner):
    firewall.flush_anchor()
    assert f"pfctl -a {utils.PF_ANCHOR} -F all" in fake_runner.commands()


def test_restore_pf_disables_when_not_previously_enabled(fake_runner):
    firewall.restore_pf(was_enabled=False)
    commands = fake_runner.commands()
    assert "pfctl -f /etc/pf.conf" in commands
    assert "pfctl -d" in commands


def test_restore_pf_keeps_enabled(fake_runner):
    firewall.restore_pf(was_enabled=True)
    commands = fake_runner.commands()
    assert "pfctl -f /etc/pf.conf" in commands
    assert "pfctl -d" not in commands


def test_apply_rules_returns_loaded_text(fake_runner):
    state = {
        "bridge_interface": "bridge100",
        "devices": {
            "192.168.2.10": {
                "bandwidth": 256, "download_pipe": 2, "upload_pipe": 1,
                "block_ips": [], "allow_only_ips": [],
            }
        },
    }
    text = firewall.apply_rules(state)
    assert "dummynet" in text
    assert text in (fake_runner.inputs())
