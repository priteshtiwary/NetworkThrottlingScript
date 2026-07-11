"""Shared pytest fixtures.

The whole test suite mocks the single subprocess seam (``utils.run_command``)
so nothing here touches the real network, requires root, or runs pfctl/dnctl.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from throttle import utils

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def read_fixture(name: str) -> str:
    with open(FIXTURE_DIR / name, "r", encoding="utf-8") as handle:
        return handle.read()


@pytest.fixture
def arp_output() -> str:
    return read_fixture("arp_output.txt")


@pytest.fixture
def ifconfig_output() -> str:
    return read_fixture("ifconfig_output.txt")


@pytest.fixture
def pfctl_sr_output() -> str:
    return read_fixture("pfctl_sr_output.txt")


@pytest.fixture
def pfctl_info_output() -> str:
    return read_fixture("pfctl_info_output.txt")


@pytest.fixture
def route_default_output() -> str:
    return read_fixture("route_default_output.txt")


@pytest.fixture
def temp_state_dir(tmp_path, monkeypatch):
    """Point state + logs at a temporary directory for the test."""

    monkeypatch.setenv("THROTTLE_STATE_DIR", str(tmp_path))
    # Reset the cached logger so it re-attaches handlers under the new dir.
    import logging

    logging.getLogger("mac_network_throttle").handlers.clear()
    return tmp_path


class FakeRunner:
    """Records commands and returns canned results keyed by command prefix."""

    def __init__(self):
        self.calls = []
        self.responses = {}

    def set_response(self, prefix: str, stdout: str = "", returncode: int = 0):
        self.responses[prefix] = (stdout, returncode)

    def __call__(self, cmd, *, dry_run=False, input_text=None, check=False):
        self.calls.append(
            {"cmd": list(cmd), "dry_run": dry_run, "input_text": input_text}
        )
        joined = " ".join(cmd)
        stdout, returncode = "", 0
        # Prefer the longest (most specific) matching prefix.
        for prefix in sorted(self.responses, key=len, reverse=True):
            if joined.startswith(prefix):
                stdout, returncode = self.responses[prefix]
                break
        return utils.CommandResult(
            args=list(cmd), returncode=returncode, stdout=stdout, stderr=""
        )

    def commands(self):
        return [" ".join(call["cmd"]) for call in self.calls]

    def inputs(self):
        return [call["input_text"] for call in self.calls if call["input_text"]]


@pytest.fixture
def fake_runner(monkeypatch):
    """Install a :class:`FakeRunner` as the subprocess seam in every module."""

    runner = FakeRunner()
    for module_name in ("utils", "devices", "throttle", "firewall", "hotspot", "cli"):
        module = __import__(f"throttle.{module_name}", fromlist=["run_command"])
        if hasattr(module, "utils"):
            monkeypatch.setattr(module.utils, "run_command", runner, raising=True)
    monkeypatch.setattr(utils, "run_command", runner, raising=True)
    return runner


@pytest.fixture
def as_root(monkeypatch):
    monkeypatch.setattr(utils, "is_root", lambda: True)
    monkeypatch.setattr(utils.os, "geteuid", lambda: 0, raising=False)
