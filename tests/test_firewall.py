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
        "block drop quick on bridge100 from 192.168.2.10 to any",
        "block drop quick on bridge100 from any to 192.168.2.10",
    ]


def test_build_device_rules_block_specific_ips():
    record = {
        "bandwidth": -1, "download_pipe": 2, "upload_pipe": 1,
        "block_ips": ["8.8.8.8"], "allow_only_ips": [],
    }
    rules = firewall.build_device_rules("192.168.2.10", record, "bridge100")
    assert "block drop quick on bridge100 from 192.168.2.10 to 8.8.8.8" in rules
    assert "block drop quick on bridge100 from 8.8.8.8 to 192.168.2.10" in rules
    # No dummynet rules when unlimited.
    assert not any("dummynet" in rule for rule in rules)


def test_build_device_rules_allow_only_mode():
    record = {
        "bandwidth": -1, "download_pipe": 2, "upload_pipe": 1,
        "block_ips": [], "allow_only_ips": ["1.1.1.1"],
    }
    rules = firewall.build_device_rules("192.168.2.10", record, "bridge100")
    # Permits must come before the deny-all (quick, first-match-wins).
    pass_index = rules.index("pass quick on bridge100 from 192.168.2.10 to 1.1.1.1")
    deny_index = rules.index("block drop quick on bridge100 from 192.168.2.10 to any")
    assert pass_index < deny_index


def test_build_device_rules_throttle_plus_block_combined():
    record = {
        "bandwidth": 512, "download_pipe": 4, "upload_pipe": 3,
        "block_ips": ["9.9.9.9"], "allow_only_ips": [],
    }
    rules = firewall.build_device_rules("192.168.2.20", record, "bridge100")
    assert any("dummynet" in r for r in rules)
    assert "block drop quick on bridge100 from 192.168.2.20 to 9.9.9.9" in rules
    # Blocks come after shaping so they always win.
    assert rules.index("block drop quick on bridge100 from 192.168.2.20 to 9.9.9.9") > 1


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
    assert "block drop quick on bridge100 from any to 192.168.2.11" in text


# ---------------------------------------------------------------------------
# Anchor placement + pf.conf reference management
# ---------------------------------------------------------------------------
def test_anchor_is_top_level():
    # macOS does not evaluate runtime children of com.apple/*, so our anchor
    # must be a plain top-level anchor.
    assert utils.PF_ANCHOR == "mac_throttle"
    assert "/" not in utils.PF_ANCHOR


def test_add_references_appends_both_anchors():
    text = firewall.add_references('anchor "com.apple/*" all\n')
    assert f'dummynet-anchor "{utils.PF_ANCHOR}"' in text
    assert f'anchor "{utils.PF_ANCHOR}"' in text
    assert firewall.PF_CONF_BEGIN in text


def test_add_references_is_idempotent():
    once = firewall.add_references('anchor "com.apple/*" all\n')
    twice = firewall.add_references(once)
    assert once == twice


def test_strip_references_removes_block():
    base = 'anchor "com.apple/*" all\n'
    added = firewall.add_references(base)
    stripped = firewall.strip_references(added)
    assert firewall.PF_CONF_BEGIN not in stripped
    assert f'anchor "{utils.PF_ANCHOR}"' not in stripped


def test_add_then_strip_roundtrip():
    base = 'anchor "com.apple/*" all\n'
    assert firewall.strip_references(firewall.add_references(base)).strip() == base.strip()


def test_ensure_pf_conf_references_writes_when_missing(monkeypatch):
    written = {}
    monkeypatch.setattr(firewall, "read_system_pf_conf", lambda: 'anchor "x"\n')
    monkeypatch.setattr(
        firewall, "write_system_pf_conf",
        lambda text, dry_run=False: written.update(text=text),
    )
    changed = firewall.ensure_pf_conf_references()
    assert changed is True
    assert firewall.PF_CONF_BEGIN in written["text"]


def test_ensure_pf_conf_references_noop_when_present(monkeypatch):
    conf = firewall.add_references('anchor "x"\n')
    monkeypatch.setattr(firewall, "read_system_pf_conf", lambda: conf)
    monkeypatch.setattr(
        firewall, "write_system_pf_conf",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not write")),
    )
    assert firewall.ensure_pf_conf_references() is False


def test_pf_conf_reference_roundtrip_on_real_file(safe_pf_conf):
    # safe_pf_conf redirects SYSTEM_PF_CONF to a temp file seeded with a stub.
    assert firewall.ensure_pf_conf_references() is True
    written = safe_pf_conf.read_text()
    assert firewall.PF_CONF_BEGIN in written
    assert f'dummynet-anchor "{utils.PF_ANCHOR}"' in written
    # Idempotent: a second ensure does not change the file.
    assert firewall.ensure_pf_conf_references() is False
    # Removal cleans the block back out.
    assert firewall.remove_pf_conf_references() is True
    assert firewall.PF_CONF_BEGIN not in safe_pf_conf.read_text()
    assert firewall.remove_pf_conf_references() is False


def test_read_system_pf_conf_falls_back_when_missing(monkeypatch):
    monkeypatch.setattr(firewall, "SYSTEM_PF_CONF", "/nonexistent/path/pf.conf")
    text = firewall.read_system_pf_conf()
    assert 'anchor "com.apple/*"' in text


def test_write_system_pf_conf_dry_run_does_not_write(safe_pf_conf, capsys):
    original = safe_pf_conf.read_text()
    firewall.write_system_pf_conf("REPLACED", dry_run=True)
    assert safe_pf_conf.read_text() == original
    assert "[DRY-RUN]" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# pf mutations (mocked subprocess)
# ---------------------------------------------------------------------------
def test_is_pf_enabled_true(fake_runner, pfctl_info_output):
    fake_runner.set_response("pfctl -s info", stdout=pfctl_info_output)
    assert firewall.is_pf_enabled() is True


def test_is_pf_enabled_false(fake_runner):
    fake_runner.set_response("pfctl -s info", stdout="Status: Disabled")
    assert firewall.is_pf_enabled() is False


def test_is_anchor_active(fake_runner):
    fake_runner.set_response("pfctl -sr", stdout='anchor "mac_throttle" all\n')
    assert firewall.is_anchor_active() is True
    fake_runner.set_response("pfctl -sr", stdout='anchor "com.apple/*" all\n')
    assert firewall.is_anchor_active() is False


def test_enable_anchor_reloads_once_when_not_active(fake_runner, monkeypatch):
    monkeypatch.setattr(firewall, "ensure_pf_conf_references", lambda dry_run=False: True)
    monkeypatch.setattr(firewall, "is_anchor_active", lambda: False)
    firewall.enable_anchor()
    commands = fake_runner.commands()
    assert f"pfctl -f {firewall.SYSTEM_PF_CONF}" in commands  # one-time activation
    assert "pfctl -e" in commands


def test_enable_anchor_skips_reload_when_active(fake_runner, monkeypatch):
    monkeypatch.setattr(firewall, "ensure_pf_conf_references", lambda dry_run=False: False)
    monkeypatch.setattr(firewall, "is_anchor_active", lambda: True)
    firewall.enable_anchor()
    commands = fake_runner.commands()
    # Already active -> no reload -> no client disruption.
    assert not any(c.startswith("pfctl -f ") for c in commands)
    assert "pfctl -e" in commands


def test_load_anchor_rules(fake_runner):
    firewall.load_anchor_rules("# rules\n")
    assert f"pfctl -a {utils.PF_ANCHOR} -f -" in fake_runner.commands()


def test_flush_anchor(fake_runner):
    firewall.flush_anchor()
    assert f"pfctl -a {utils.PF_ANCHOR} -F all" in fake_runner.commands()


def test_restore_pf_disables_when_not_previously_enabled(fake_runner, monkeypatch):
    monkeypatch.setattr(firewall, "remove_pf_conf_references", lambda dry_run=False: True)
    firewall.restore_pf(was_enabled=False)
    commands = fake_runner.commands()
    # Must NOT reload the file (that would flush Internet Sharing NAT anchors).
    assert not any("pfctl -f /etc/pf.conf" in c for c in commands)
    assert "pfctl -d" in commands


def test_restore_pf_keeps_enabled(fake_runner, monkeypatch):
    monkeypatch.setattr(firewall, "remove_pf_conf_references", lambda dry_run=False: True)
    firewall.restore_pf(was_enabled=True)
    commands = fake_runner.commands()
    assert not any("pfctl -f /etc/pf.conf" in c for c in commands)
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
