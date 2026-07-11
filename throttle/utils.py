"""Shared helpers: subprocess execution, privilege checks, interface detection,
logging, and persistent state management.

All external command execution flows through :func:`run_command` so that unit
tests can mock a single seam and ``--dry-run`` can be honoured uniformly.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Sequence

# Name of the pf anchor this tool loads its rules into. Chosen to be unlikely to
# collide with anything already present in the system ruleset.
PF_ANCHOR = "mac_throttle"

# Default location for runtime state + logs. Overridable for tests / packaging.
DEFAULT_STATE_DIR = "/var/run/mac-network-throttle"
STATE_FILENAME = "state.json"
LOG_FILENAME = "throttle.log"

_LOGGER_NAME = "mac_network_throttle"


# ---------------------------------------------------------------------------
# Filesystem locations
# ---------------------------------------------------------------------------
def get_state_dir() -> str:
    """Return the directory used for state + logs.

    Honours the ``THROTTLE_STATE_DIR`` environment variable so tests can point
    it at a temporary directory without monkeypatching module globals.
    """

    return os.environ.get("THROTTLE_STATE_DIR", DEFAULT_STATE_DIR)


def get_state_file() -> str:
    return os.path.join(get_state_dir(), STATE_FILENAME)


def get_log_file() -> str:
    return os.path.join(get_state_dir(), LOG_FILENAME)


def ensure_state_dir() -> str:
    state_dir = get_state_dir()
    os.makedirs(state_dir, exist_ok=True)
    return state_dir


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def get_logger() -> logging.Logger:
    """Return a configured module logger that writes to the log file.

    Safe to call repeatedly; handlers are only attached once.
    """

    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    try:
        ensure_state_dir()
        file_handler = logging.FileHandler(get_log_file())
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        # If we cannot write the log file (e.g. no permissions during a
        # dry-run as a normal user), fall back to stderr only.
        pass

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.propagate = False
    return logger


def log_action(message: str) -> None:
    """Record a rule/state change to the log file with a timestamp."""

    get_logger().info(message)


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------
@dataclass
class CommandResult:
    """Result of running (or pretending to run) an external command."""

    args: Sequence[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_command(
    cmd: Sequence[str],
    *,
    dry_run: bool = False,
    input_text: Optional[str] = None,
    check: bool = False,
) -> CommandResult:
    """Execute ``cmd`` and return a :class:`CommandResult`.

    When ``dry_run`` is true the command is logged but not executed and a
    successful, empty result is returned. This is the single subprocess seam
    for the whole package, which keeps unit tests simple.
    """

    printable = " ".join(cmd)
    if input_text is not None:
        preview = input_text.strip().replace("\n", " ; ")
        log_action(f"[cmd] {printable}  <<< {preview}")
    else:
        log_action(f"[cmd] {printable}")

    if dry_run:
        # Surface the exact command that would run so operators can audit it.
        print(f"[DRY-RUN] {printable}")
        if input_text:
            for line in input_text.splitlines():
                print(f"[DRY-RUN]   | {line}")
        return CommandResult(args=list(cmd), returncode=0, stdout="", stderr="")

    completed = subprocess.run(
        list(cmd),
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )
    result = CommandResult(
        args=list(cmd),
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
    if check and not result.ok:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {printable}\n{result.stderr}"
        )
    return result


# ---------------------------------------------------------------------------
# Privilege checks
# ---------------------------------------------------------------------------
def is_root() -> bool:
    return os.geteuid() == 0


def require_root(dry_run: bool = False) -> None:
    """Exit with a clear message when root is required but not held.

    During ``--dry-run`` we allow non-root execution so operators can preview
    the commands without elevated privileges.
    """

    if dry_run or is_root():
        return
    raise PermissionError(
        "This command changes system network state and must be run as root. "
        "Re-run with sudo, e.g. 'sudo mac-throttle <command>'."
    )


# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------
def parse_default_interface(route_output: str) -> Optional[str]:
    """Extract the interface name from ``route -n get default`` output."""

    match = re.search(r"^\s*interface:\s*(\S+)", route_output, re.MULTILINE)
    return match.group(1) if match else None


def get_active_internet_interface(dry_run: bool = False) -> Optional[str]:
    """Return the interface carrying the default route (the internet uplink)."""

    result = run_command(["route", "-n", "get", "default"], dry_run=False)
    if not result.ok:
        return None
    return parse_default_interface(result.stdout)


def parse_bridge_interfaces(ifconfig_output: str) -> List[str]:
    """Return the names of bridge interfaces that currently have members.

    Internet Sharing creates a NAT bridge (commonly ``bridge100``) and attaches
    the shared interface as a member. We pick bridges that have at least one
    ``member:`` line so idle/empty bridges are ignored.
    """

    bridges: List[str] = []
    current: Optional[str] = None
    has_member = False

    for line in ifconfig_output.splitlines():
        header = re.match(r"^(bridge\d+):", line)
        if header:
            if current and has_member:
                bridges.append(current)
            current = header.group(1)
            has_member = False
            continue
        if re.match(r"^[a-z0-9]+:", line):
            # A different (non-bridge) interface block started.
            if current and has_member:
                bridges.append(current)
            current = None
            has_member = False
            continue
        if current and "member:" in line:
            has_member = True

    if current and has_member:
        bridges.append(current)
    return bridges


def get_bridge_interface(dry_run: bool = False) -> Optional[str]:
    """Detect the active Internet Sharing bridge interface dynamically."""

    result = run_command(["ifconfig"], dry_run=False)
    if not result.ok:
        return None
    bridges = parse_bridge_interfaces(result.stdout)
    return bridges[0] if bridges else None


# ---------------------------------------------------------------------------
# Persistent state
# ---------------------------------------------------------------------------
def default_state() -> dict:
    """Return a fresh, empty state document."""

    return {
        "running": False,
        "bridge_interface": None,
        "source_interface": None,
        "wifi_interface": None,
        "ssid": None,
        "pf_was_enabled": False,
        "next_pipe": 1,
        "devices": {},
    }


def load_state() -> dict:
    """Load persisted state, returning a default document if none exists."""

    path = get_state_file()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default_state()

    state = default_state()
    state.update(data)
    return state


def save_state(state: dict) -> None:
    ensure_state_dir()
    with open(get_state_file(), "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)


def clear_state() -> None:
    """Remove the on-disk state file if present."""

    try:
        os.remove(get_state_file())
    except FileNotFoundError:
        pass


def allocate_pipe_pair(state: dict) -> tuple:
    """Reserve and return a ``(download_pipe, upload_pipe)`` number pair."""

    download = state["next_pipe"]
    upload = state["next_pipe"] + 1
    state["next_pipe"] += 2
    return download, upload


def new_device_entry(mac: Optional[str], download_pipe: int, upload_pipe: int) -> dict:
    """Return a fresh per-device state record."""

    return {
        "mac": mac,
        "download_pipe": download_pipe,
        "upload_pipe": upload_pipe,
        # Bandwidth sentinel: -1 unlimited, 0 full block, >0 kbps.
        "bandwidth": -1,
        "packet_loss": 0.0,
        "latency": 0,
        "block_ips": [],
        "allow_only_ips": [],
    }
