"""Live traffic monitoring for a connected device.

Captures the destination endpoints a client device (e.g. an STB) is talking to
by running ``tcpdump`` on the NAT bridge interface, filtered to that device's
IP. This reveals the CDN/server IPs behind a video session so they can be
blocked with the ``block`` command.

The capture is read-only observation; it never changes network state. All
parsing is done by pure functions so it can be unit-tested against sample
``tcpdump`` output without touching the network.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import utils

# tcpdump -nn line, e.g.
#   12:00:00.123456 IP 192.168.2.2.51514 > 142.250.183.14.443: Flags [S], ...
#   12:00:00.123456 IP 142.250.183.14.443 > 192.168.2.2.51514: Flags [S.], ...
_TCPDUMP_IP_LINE = re.compile(
    r"\bIP6?\s+"
    r"(?P<src>[0-9a-fA-F:.]+?)(?:\.(?P<sport>\d+))?\s+>\s+"
    r"(?P<dst>[0-9a-fA-F:.]+?)(?:\.(?P<dport>\d+))?:\s"
)


@dataclass
class Endpoint:
    """A remote endpoint the monitored device communicated with."""

    ip: str
    packets: int = 0
    ports: set = field(default_factory=set)
    hostname: Optional[str] = None

    @property
    def is_private(self) -> bool:
        try:
            return ipaddress.ip_address(self.ip).is_private
        except ValueError:
            return False


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_tcpdump(output: str, device_ip: str) -> List[Endpoint]:
    """Parse ``tcpdump -nn`` output into remote endpoints for ``device_ip``.

    For each captured packet the *other* side of the conversation (i.e. not the
    device itself) is recorded. Endpoints are returned ordered by packet count,
    descending. Multicast/broadcast and the device's own IP are excluded.
    """

    endpoints: "OrderedDict[str, Endpoint]" = OrderedDict()

    for line in output.splitlines():
        match = _TCPDUMP_IP_LINE.search(line)
        if not match:
            continue
        src = match.group("src")
        dst = match.group("dst")
        if not _looks_like_ip(src) or not _looks_like_ip(dst):
            continue

        # Determine the remote endpoint (the side that is not the device).
        if src == device_ip:
            remote, port = dst, match.group("dport")
        elif dst == device_ip:
            remote, port = src, match.group("sport")
        else:
            # Packet unrelated to the device (shouldn't happen with a host
            # filter, but guard anyway).
            continue

        if remote == device_ip:
            continue
        try:
            addr = ipaddress.ip_address(remote)
        except ValueError:
            continue
        if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
            continue

        endpoint = endpoints.get(remote)
        if endpoint is None:
            endpoint = Endpoint(ip=remote)
            endpoints[remote] = endpoint
        endpoint.packets += 1
        if port:
            endpoint.ports.add(int(port))

    return sorted(endpoints.values(), key=lambda e: e.packets, reverse=True)


def resolve_hostname(ip: str, dry_run: bool = False) -> Optional[str]:
    """Reverse-resolve ``ip`` to a hostname using ``host`` (best effort)."""

    result = utils.run_command(["host", "-W", "1", ip], dry_run=False)
    if not result.ok:
        return None
    # e.g. "14.183.250.142.in-addr.arpa domain name pointer bom12s...net."
    match = re.search(r"domain name pointer\s+(\S+?)\.?$", result.stdout, re.MULTILINE)
    return match.group(1) if match else None


def monitor_device(
    device_ip: str,
    bridge: str,
    duration: int = 15,
    resolve: bool = True,
    dry_run: bool = False,
) -> List[Endpoint]:
    """Capture ``device_ip`` traffic on ``bridge`` for ``duration`` seconds.

    Uses ``tcpdump -G <duration> -W 1 -w <file>`` to capture for a fixed time
    and exit cleanly (the portable way to time-limit tcpdump on macOS), then
    reads the capture back as text for parsing. Returns the remote endpoints
    seen, ordered by packet count. When ``resolve`` is set, each public
    endpoint is annotated with its reverse-DNS hostname.
    """

    capture_file = os.path.join(utils.ensure_state_dir(), "capture.pcap")

    capture_cmd = [
        "tcpdump",
        "-i", bridge,
        "-nn",
        "-G", str(int(duration)),
        "-W", "1",
        "-w", capture_file,
        "host", device_ip,
    ]
    utils.run_command(capture_cmd, dry_run=dry_run)
    if dry_run:
        return []

    read_cmd = ["tcpdump", "-nn", "-t", "-r", capture_file, "host", device_ip]
    result = utils.run_command(read_cmd, dry_run=False)
    try:
        os.remove(capture_file)
    except OSError:
        pass

    endpoints = parse_tcpdump(result.stdout, device_ip)
    if resolve:
        for endpoint in endpoints:
            if not endpoint.is_private:
                endpoint.hostname = resolve_hostname(endpoint.ip, dry_run=dry_run)
    return endpoints
