"""pf (packet filter) anchor and rule management.

Design goals:

* Never clobber the system ruleset. We append a ``dummynet-anchor`` and an
  ``anchor`` reference to the *existing* ``/etc/pf.conf`` and load our per-device
  rules into that anchor with ``pfctl -a mac_throttle -f -``.
* Rules use *last-match-wins* semantics (no ``quick``). Because our anchor is
  evaluated last, our decisions override the (typically permissive) base ruleset
  without needing to know its contents.
* All rule text is produced by pure functions so it can be unit-tested without
  touching the kernel.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List

from . import utils
from .throttle import BLOCKED


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_ip_or_cidr(value: str) -> str:
    """Validate and canonicalise an IP address or CIDR range.

    Returns the canonical string form. Raises :class:`ValueError` for invalid
    input. A bare address is returned as-is; a CIDR is normalised to its
    network address (host bits masked off).
    """

    token = (value or "").strip()
    if not token:
        raise ValueError("empty IP/CIDR value")

    if "/" in token:
        network = ipaddress.ip_network(token, strict=False)
        return str(network)

    # Raises ValueError if not a valid address.
    return str(ipaddress.ip_address(token))


def validate_ip_list(values) -> List[str]:
    """Validate a comma-joined or iterable list of IPs/CIDRs.

    Duplicate entries are removed while preserving order.
    """

    if isinstance(values, str):
        items = [part.strip() for part in values.split(",")]
    else:
        items = list(values)

    result: List[str] = []
    for item in items:
        if not item:
            continue
        canonical = validate_ip_or_cidr(item)
        if canonical not in result:
            result.append(canonical)
    return result


# ---------------------------------------------------------------------------
# Rule generation (pure functions)
# ---------------------------------------------------------------------------
def build_device_rules(ip: str, record: dict, bridge: str) -> List[str]:
    """Build the ordered pf rules for a single device.

    Rule ordering relies on last-match-wins (no ``quick``): later rules override
    earlier ones. Order is: shaping (dummynet) → allow-only deny+permit →
    explicit blocks. This lets throttling and filtering coexist on one device.
    """

    rules: List[str] = []
    bandwidth = record.get("bandwidth", -1)

    # Full block short-circuits everything else for this device.
    if bandwidth == BLOCKED:
        rules.append(f"block drop on {bridge} from {ip} to any")
        rules.append(f"block drop on {bridge} from any to {ip}")
        return rules

    # Bandwidth shaping: steer traffic into the device's pipes.
    if bandwidth > 0:
        upload = record["upload_pipe"]
        download = record["download_pipe"]
        rules.append(f"dummynet in on {bridge} from {ip} to any pipe {upload}")
        rules.append(f"dummynet out on {bridge} from any to {ip} pipe {download}")

    # Whitelist mode: deny all for the device, then permit the allowed set.
    allow_only = record.get("allow_only_ips") or []
    if allow_only:
        rules.append(f"block drop on {bridge} from {ip} to any")
        rules.append(f"block drop on {bridge} from any to {ip}")
        for allowed in allow_only:
            rules.append(f"pass on {bridge} from {ip} to {allowed}")
            rules.append(f"pass on {bridge} from {allowed} to {ip}")

    # Explicit destination blocks (applied last so they always win).
    for blocked in record.get("block_ips") or []:
        rules.append(f"block drop on {bridge} from {ip} to {blocked}")
        rules.append(f"block drop on {bridge} from {blocked} to {ip}")

    return rules


def build_anchor_rules(state: dict) -> str:
    """Build the complete anchor ruleset text for the current state."""

    bridge = state.get("bridge_interface")
    lines: List[str] = [
        "# Managed by mac-network-throttle. Do not edit by hand.",
    ]
    if not bridge:
        return "\n".join(lines) + "\n"

    for ip, record in sorted(state.get("devices", {}).items()):
        device_rules = build_device_rules(ip, record, bridge)
        if device_rules:
            lines.append(f"# device {ip}")
            lines.extend(device_rules)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# pf state queries + mutations
# ---------------------------------------------------------------------------
def is_pf_enabled(dry_run: bool = False) -> bool:
    """Return True when pf reports ``Status: Enabled``."""

    result = utils.run_command(["pfctl", "-s", "info"], dry_run=False)
    return bool(re.search(r"Status:\s+Enabled", result.stdout))


def enable_anchor(dry_run: bool = False) -> None:
    """Ensure pf is enabled so our anchor is evaluated.

    We do NOT reload or rewrite the main ruleset. Our rules live under the
    ``com.apple/*`` wildcard anchor that ``/etc/pf.conf`` already references, so
    simply enabling pf is enough for them to take effect. Crucially, this avoids
    flushing the Internet Sharing NAT/DHCP anchors that macOS inserts into the
    main ruleset at runtime -- reloading the ruleset from the file would drop
    them and disconnect connected clients.

    ``pfctl -e`` is a no-op (harmless warning) when pf is already enabled.
    """

    utils.run_command(["pfctl", "-e"], dry_run=dry_run)


def load_anchor_rules(rules_text: str, dry_run: bool = False) -> None:
    """Load per-device rules into our anchor, replacing any previous rules."""

    utils.run_command(
        ["pfctl", "-a", utils.PF_ANCHOR, "-f", "-"],
        dry_run=dry_run,
        input_text=rules_text,
    )


def flush_anchor(dry_run: bool = False) -> None:
    """Remove all rules from our anchor without touching the base ruleset."""

    utils.run_command(
        ["pfctl", "-a", utils.PF_ANCHOR, "-F", "all"], dry_run=dry_run
    )


def restore_pf(was_enabled: bool, dry_run: bool = False) -> None:
    """Restore the prior pf enable/disable state.

    We deliberately do NOT reload ``/etc/pf.conf``: our rules only ever lived in
    our own anchor (already flushed by :func:`flush_anchor`), and reloading the
    file would flush the runtime Internet Sharing NAT/DHCP anchors and drop
    connected clients. If pf was disabled before we started, we disable it
    again; otherwise we leave it as the system had it.
    """

    if not was_enabled:
        utils.run_command(["pfctl", "-d"], dry_run=dry_run)


def apply_rules(state: dict, dry_run: bool = False) -> str:
    """Regenerate and load the anchor ruleset from ``state``.

    Returns the rule text that was loaded (useful for logging/tests).
    """

    rules_text = build_anchor_rules(state)
    load_anchor_rules(rules_text, dry_run=dry_run)
    return rules_text
