"""Unit tests for utils: command execution, privilege checks, state helpers."""

import subprocess

import pytest

from throttle import utils


# ---------------------------------------------------------------------------
# run_command (real subprocess path + dry-run)
# ---------------------------------------------------------------------------
def test_run_command_executes_real_process(temp_state_dir):
    result = utils.run_command(["echo", "hello"])
    assert result.ok
    assert result.stdout.strip() == "hello"


def test_run_command_captures_failure(temp_state_dir):
    result = utils.run_command(["false"])
    assert not result.ok
    assert result.returncode != 0


def test_run_command_check_raises(temp_state_dir):
    with pytest.raises(RuntimeError):
        utils.run_command(["false"], check=True)


def test_run_command_dry_run_does_not_execute(temp_state_dir, capsys):
    result = utils.run_command(["rm", "-rf", "/"], dry_run=True)
    assert result.ok
    out = capsys.readouterr().out
    assert "[DRY-RUN] rm -rf /" in out


def test_run_command_dry_run_prints_input(temp_state_dir, capsys):
    utils.run_command(["pfctl", "-f", "-"], dry_run=True, input_text="rule a\nrule b")
    out = capsys.readouterr().out
    assert "rule a" in out
    assert "rule b" in out


def test_run_command_with_input(temp_state_dir):
    result = utils.run_command(["cat"], input_text="piped")
    assert result.stdout == "piped"


# ---------------------------------------------------------------------------
# Privilege checks
# ---------------------------------------------------------------------------
def test_require_root_passes_when_root(monkeypatch):
    monkeypatch.setattr(utils, "is_root", lambda: True)
    utils.require_root()  # no exception


def test_require_root_passes_on_dry_run(monkeypatch):
    monkeypatch.setattr(utils, "is_root", lambda: False)
    utils.require_root(dry_run=True)  # no exception


def test_require_root_raises_without_root(monkeypatch):
    monkeypatch.setattr(utils, "is_root", lambda: False)
    with pytest.raises(PermissionError):
        utils.require_root()


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------
def test_default_state_shape():
    state = utils.default_state()
    assert state["running"] is False
    assert state["devices"] == {}
    assert state["next_pipe"] == 1


def test_save_and_load_state_roundtrip(temp_state_dir):
    state = utils.default_state()
    state["bridge_interface"] = "bridge100"
    utils.save_state(state)
    loaded = utils.load_state()
    assert loaded["bridge_interface"] == "bridge100"


def test_load_state_missing_returns_default(temp_state_dir):
    assert utils.load_state()["bridge_interface"] is None


def test_load_state_corrupt_returns_default(temp_state_dir):
    utils.ensure_state_dir()
    with open(utils.get_state_file(), "w", encoding="utf-8") as handle:
        handle.write("{not valid json")
    assert utils.load_state()["running"] is False


def test_clear_state_is_idempotent(temp_state_dir):
    utils.save_state(utils.default_state())
    utils.clear_state()
    utils.clear_state()  # second call must not raise
    assert utils.load_state()["bridge_interface"] is None


def test_allocate_pipe_pair_increments():
    state = utils.default_state()
    first = utils.allocate_pipe_pair(state)
    second = utils.allocate_pipe_pair(state)
    assert first == (1, 2)
    assert second == (3, 4)
    assert state["next_pipe"] == 5


def test_new_device_entry_defaults():
    entry = utils.new_device_entry("aa:bb:cc:dd:ee:ff", 1, 2)
    assert entry["mac"] == "aa:bb:cc:dd:ee:ff"
    assert entry["bandwidth"] == -1
    assert entry["block_ips"] == []
    assert entry["allow_only_ips"] == []


# ---------------------------------------------------------------------------
# State dir resolution
# ---------------------------------------------------------------------------
def test_get_state_dir_env_override(monkeypatch):
    monkeypatch.setenv("THROTTLE_STATE_DIR", "/tmp/custom-throttle-dir")
    assert utils.get_state_dir() == "/tmp/custom-throttle-dir"
    assert utils.get_state_file().endswith("state.json")
    assert utils.get_log_file().endswith("throttle.log")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def test_log_action_writes(temp_state_dir):
    utils.log_action("test-entry-123")
    with open(utils.get_log_file(), "r", encoding="utf-8") as handle:
        assert "test-entry-123" in handle.read()
