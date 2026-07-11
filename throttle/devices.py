"""Connected-device discovery via the ARP table on the NAT bridge interface."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from . import utils

# Matches a line of ``arp -a`` output, e.g.
#   ? (192.168.2.10) at aa:bb:cc:dd:ee:ff on bridge100 ifscope [ethernet]
_ARP_LINE = re.compile(
    r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+"
    r"(?P<mac>[0-9a-fA-F:]+|\(incomplete\))\s+on\s+(?P<iface>\S+)"
)


@dataclass
class Device:
    """A client observed on the bridge interface."""

    ip: str
    mac: Optional[str]
    interface: str
    bandwidth: int = -1
    packet_loss: float = 0.0
    latency: int = 0
    block_ips: List[str] = field(default_factory=list)
    allow_only_ips: List[str] = field(default_factory=list)


def normalize_mac(mac: str) -> Optional[str]:
    """Normalise a MAC to zero-padded, lowercase colon notation.

    macOS ``arp`` prints octets without leading zeros (e.g. ``a:b:c:1:2:3``).
    Returns ``None`` for incomplete entries.
    """

    if not mac or mac == "(incomplete)":
        return None
    parts = mac.split(":")
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(part, 16):02x}" for part in parts)
    except ValueError:
        return None


def parse_arp_output(arp_output: str, interface: Optional[str] = None) -> List[Device]:
    """Parse ``arp -a`` output into :class:`Device` records.

    When ``interface`` is given, only entries on that interface are returned.
    Incomplete ARP entries (no resolved MAC) are skipped.
    """

    devices: List[Device] = []
    seen = set()
    for line in arp_output.splitlines():
        match = _ARP_LINE.search(line)
        if not match:
            continue
        iface = match.group("iface")
        if interface and iface != interface:
            continue
        mac = normalize_mac(match.group("mac"))
        if mac is None:
            continue
        ip = match.group("ip")
        if ip in seen:
            continue
        seen.add(ip)
        devices.append(Device(ip=ip, mac=mac, interface=iface))
    return devices


def discover_devices(interface: str, dry_run: bool = False) -> List[Device]:
    """Query the live ARP table for clients on ``interface``."""

    result = utils.run_command(["arp", "-a", "-i", interface], dry_run=False)
    if not result.ok or not result.stdout.strip():
        # Some macOS versions do not support ``-i``; fall back to full table.
        result = utils.run_command(["arp", "-a"], dry_run=False)
    if not result.ok:
        return []
    return parse_arp_output(result.stdout, interface=interface)


def merge_state(devices: List[Device], state: dict) -> List[Device]:
    """Overlay persisted throttle/block state onto discovered devices.

    Devices present in state but not currently in the ARP table are appended so
    that ``list-devices`` still shows configured-but-idle clients.
    """

    by_ip = {device.ip: device for device in devices}
    for ip, record in state.get("devices", {}).items():
        device = by_ip.get(ip)
        if device is None:
            device = Device(
                ip=ip,
                mac=record.get("mac"),
                interface=state.get("bridge_interface") or "",
            )
            by_ip[ip] = device
        device.bandwidth = record.get("bandwidth", -1)
        device.packet_loss = record.get("packet_loss", 0.0)
        device.latency = record.get("latency", 0)
        device.block_ips = list(record.get("block_ips", []))
        device.allow_only_ips = list(record.get("allow_only_ips", []))
    return sorted(by_ip.values(), key=lambda d: tuple(int(o) for o in d.ip.split(".")))
