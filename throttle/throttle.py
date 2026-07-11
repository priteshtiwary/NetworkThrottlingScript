"""Bandwidth throttling via dnctl (dummynet) pipe management.

A dummynet *pipe* models a link with a bandwidth limit and optional packet loss
and latency. pf rules (see :mod:`throttle.firewall`) steer per-device traffic
into these pipes. Each device gets two pipes: one for download, one for upload.
"""

from __future__ import annotations

from typing import List, Optional

from . import utils

# Bandwidth sentinels shared across the package.
UNLIMITED = -1
BLOCKED = 0

# Named presets mapped to kbps (or a sentinel). Keys are matched case-insensitively.
PRESETS = {
    "0": BLOCKED,
    "block": BLOCKED,
    "50k": 50,
    "100k": 100,
    "256k": 256,
    "512k": 512,
    "1m": 1000,
    "3m": 3000,
    "5m": 5000,
    "10m": 10000,
    "unlimited": UNLIMITED,
}


def parse_bandwidth(value: str) -> int:
    """Parse a CLI bandwidth string into a kbps value or sentinel.

    Accepts named presets (``256k``, ``1m``, ``unlimited``), plain integers
    interpreted as kbps, and ``<n>k`` / ``<n>m`` suffixed values. Returns
    :data:`UNLIMITED` (-1), :data:`BLOCKED` (0), or a positive kbps integer.

    Raises :class:`ValueError` for negative or unparseable input.
    """

    if value is None:
        raise ValueError("bandwidth value is required")

    token = str(value).strip().lower()
    if token in PRESETS:
        return PRESETS[token]

    try:
        if token.endswith("m"):
            kbps = int(round(float(token[:-1]) * 1000))
        elif token.endswith("k"):
            kbps = int(round(float(token[:-1])))
        elif token.endswith("kbps"):
            kbps = int(round(float(token[:-4])))
        elif token.endswith("mbps"):
            kbps = int(round(float(token[:-4]) * 1000))
        else:
            kbps = int(round(float(token)))
    except ValueError as exc:
        raise ValueError(f"invalid bandwidth value: {value!r}") from exc

    if kbps < 0:
        raise ValueError(f"bandwidth cannot be negative: {value!r}")
    return kbps


def describe_bandwidth(kbps: int) -> str:
    """Human-readable description of a bandwidth sentinel/value."""

    if kbps == UNLIMITED:
        return "unlimited"
    if kbps == BLOCKED:
        return "blocked (0 kbps)"
    if kbps >= 1000 and kbps % 1000 == 0:
        return f"{kbps // 1000} Mbps"
    return f"{kbps} kbps"


def build_pipe_config(
    pipe_num: int,
    bandwidth_kbps: int,
    packet_loss: float = 0.0,
    latency_ms: int = 0,
) -> List[str]:
    """Build the ``dnctl pipe N config ...`` argument list.

    ``bandwidth_kbps`` must be a positive kbps value (callers must not pass the
    :data:`UNLIMITED` or :data:`BLOCKED` sentinels here). Packet loss is a
    percentage (0-100) and latency is one-way milliseconds.
    """

    if bandwidth_kbps <= 0:
        raise ValueError("build_pipe_config requires a positive kbps value")

    cmd = ["dnctl", "pipe", str(pipe_num), "config", "bw", f"{bandwidth_kbps}Kbit/s"]

    if packet_loss and packet_loss > 0:
        # dummynet plr is a fraction between 0 and 1.
        fraction = max(0.0, min(1.0, float(packet_loss) / 100.0))
        cmd += ["plr", f"{fraction:.4f}"]

    if latency_ms and latency_ms > 0:
        cmd += ["delay", f"{int(latency_ms)}"]

    return cmd


def build_pipe_delete(pipe_num: int) -> List[str]:
    """Build the ``dnctl pipe N delete`` argument list."""

    return ["dnctl", "pipe", str(pipe_num), "delete"]


def apply_pipes(state: dict, dry_run: bool = False) -> List[List[str]]:
    """(Re)configure all dummynet pipes implied by ``state``.

    Only devices with a positive kbps limit get pipes configured. Devices that
    are unlimited or fully blocked have their pipes deleted so no stale limit
    lingers. Returns the list of commands issued (useful for tests/auditing).
    """

    issued: List[List[str]] = []
    for record in state.get("devices", {}).values():
        bandwidth = record.get("bandwidth", UNLIMITED)
        download = record.get("download_pipe")
        upload = record.get("upload_pipe")
        if download is None or upload is None:
            continue

        if bandwidth > 0:
            for pipe in (download, upload):
                cmd = build_pipe_config(
                    pipe,
                    bandwidth,
                    packet_loss=record.get("packet_loss", 0.0),
                    latency_ms=record.get("latency", 0),
                )
                utils.run_command(cmd, dry_run=dry_run)
                issued.append(cmd)
        else:
            for pipe in (download, upload):
                cmd = build_pipe_delete(pipe)
                utils.run_command(cmd, dry_run=dry_run)
                issued.append(cmd)
    return issued


def flush_pipes(dry_run: bool = False) -> None:
    """Remove every dummynet pipe. Used during cleanup."""

    utils.run_command(["dnctl", "-q", "flush"], dry_run=dry_run)
