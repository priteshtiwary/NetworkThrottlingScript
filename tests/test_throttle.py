"""Unit tests for bandwidth parsing and dnctl command generation."""

import pytest

from throttle import throttle
from throttle.throttle import BLOCKED, UNLIMITED


# ---------------------------------------------------------------------------
# parse_bandwidth
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [
        ("unlimited", UNLIMITED),
        ("0", BLOCKED),
        ("block", BLOCKED),
        ("50k", 50),
        ("100k", 100),
        ("256k", 256),
        ("512k", 512),
        ("1m", 1000),
        ("3m", 3000),
        ("5m", 5000),
        ("10m", 10000),
        ("768", 768),
        ("2048", 2048),
        ("1.5m", 1500),
        ("2mbps", 2000),
        ("300kbps", 300),
        ("UNLIMITED", UNLIMITED),
        ("256K", 256),
    ],
)
def test_parse_bandwidth_valid(value, expected):
    assert throttle.parse_bandwidth(value) == expected


@pytest.mark.parametrize("value", ["-5", "-1m", "abc", "", "12x", "kk"])
def test_parse_bandwidth_invalid(value):
    with pytest.raises(ValueError):
        throttle.parse_bandwidth(value)


def test_parse_bandwidth_none():
    with pytest.raises(ValueError):
        throttle.parse_bandwidth(None)


# ---------------------------------------------------------------------------
# describe_bandwidth
# ---------------------------------------------------------------------------
def test_describe_bandwidth():
    assert throttle.describe_bandwidth(UNLIMITED) == "unlimited"
    assert throttle.describe_bandwidth(BLOCKED) == "blocked (0 kbps)"
    assert throttle.describe_bandwidth(256) == "256 kbps"
    assert throttle.describe_bandwidth(1000) == "1 Mbps"
    assert throttle.describe_bandwidth(5000) == "5 Mbps"
    assert throttle.describe_bandwidth(1500) == "1500 kbps"


# ---------------------------------------------------------------------------
# build_pipe_config
# ---------------------------------------------------------------------------
def test_build_pipe_config_basic():
    cmd = throttle.build_pipe_config(1, 256)
    assert cmd == ["dnctl", "pipe", "1", "config", "bw", "256Kbit/s"]


def test_build_pipe_config_with_loss_and_latency():
    cmd = throttle.build_pipe_config(3, 1000, packet_loss=10.0, latency_ms=50)
    assert cmd == [
        "dnctl", "pipe", "3", "config", "bw", "1000Kbit/s",
        "plr", "0.1000", "delay", "50",
    ]


def test_build_pipe_config_clamps_packet_loss():
    cmd = throttle.build_pipe_config(1, 100, packet_loss=250)
    assert "plr" in cmd
    assert cmd[cmd.index("plr") + 1] == "1.0000"


def test_build_pipe_config_rejects_nonpositive():
    with pytest.raises(ValueError):
        throttle.build_pipe_config(1, 0)
    with pytest.raises(ValueError):
        throttle.build_pipe_config(1, UNLIMITED)


def test_build_pipe_delete():
    assert throttle.build_pipe_delete(7) == ["dnctl", "pipe", "7", "delete"]


# ---------------------------------------------------------------------------
# apply_pipes
# ---------------------------------------------------------------------------
def _state_with_device(bandwidth, loss=0.0, latency=0):
    return {
        "devices": {
            "192.168.2.10": {
                "download_pipe": 1,
                "upload_pipe": 2,
                "bandwidth": bandwidth,
                "packet_loss": loss,
                "latency": latency,
            }
        }
    }


def test_apply_pipes_configures_positive_bandwidth(fake_runner):
    issued = throttle.apply_pipes(_state_with_device(256))
    assert ["dnctl", "pipe", "1", "config", "bw", "256Kbit/s"] in issued
    assert ["dnctl", "pipe", "2", "config", "bw", "256Kbit/s"] in issued
    assert len(issued) == 2


def test_apply_pipes_deletes_when_unlimited(fake_runner):
    issued = throttle.apply_pipes(_state_with_device(UNLIMITED))
    assert ["dnctl", "pipe", "1", "delete"] in issued
    assert ["dnctl", "pipe", "2", "delete"] in issued


def test_apply_pipes_deletes_when_blocked(fake_runner):
    issued = throttle.apply_pipes(_state_with_device(BLOCKED))
    assert all("delete" in cmd for cmd in issued)


def test_apply_pipes_skips_device_without_pipes(fake_runner):
    state = {"devices": {"1.2.3.4": {"bandwidth": 256}}}
    assert throttle.apply_pipes(state) == []


def test_flush_pipes(fake_runner):
    throttle.flush_pipes()
    assert ["dnctl", "-q", "flush"] in fake_runner.calls[0]["cmd"] or \
        "dnctl -q flush" in fake_runner.commands()


def test_flush_pipes_dry_run(fake_runner):
    throttle.flush_pipes(dry_run=True)
    assert fake_runner.calls[0]["dry_run"] is True
