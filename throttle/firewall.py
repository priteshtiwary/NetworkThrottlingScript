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
SYSTEM_PF_CONF = "/etc/pf.conf"
PF_CONF_BEGIN = "# --- mac-network-throttle (managed): do not edit this block ---"
PF_CONF_END = "# --- end mac-network-throttle ---"


def build_reference_block() -> str:
    """Return the marked ``/etc/pf.conf`` block that references our anchor."""

    return (
        f"{PF_CONF_BEGIN}\n"
        f'dummynet-anchor "{utils.PF_ANCHOR}"\n'
        f'anchor "{utils.PF_ANCHOR}"\n'
        f"{PF_CONF_END}\n"
    )


def pf_conf_has_references(conf_text: str) -> bool:
    return PF_CONF_BEGIN in conf_text


def add_references(conf_text: str) -> str:
    """Append our marked reference block to ``conf_text`` (idempotent)."""

    if pf_conf_has_references(conf_text):
        return conf_text
    text = conf_text if conf_text.endswith("\n") else conf_text + "\n"
    return text + build_reference_block()


def strip_references(conf_text: str) -> str:
    """Remove our marked reference block from ``conf_text`` (idempotent)."""

    if PF_CONF_BEGIN not in conf_text:
        return conf_text
    pattern = re.compile(
        rf"\n?{re.escape(PF_CONF_BEGIN)}.*?{re.escape(PF_CONF_END)}\n?",
        re.DOTALL,
    )
    return pattern.sub("\n", conf_text)


def read_system_pf_conf() -> str:
    try:
        with open(SYSTEM_PF_CONF, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        # Minimal sane default mirroring a stock macOS pf.conf.
        return (
            'scrub-anchor "com.apple/*"\n'
            'nat-anchor "com.apple/*"\n'
            'rdr-anchor "com.apple/*"\n'
            'dummynet-anchor "com.apple/*"\n'
            'anchor "com.apple/*"\n'
            'load anchor "com.apple" from "/etc/pf.anchors/com.apple"\n'
        )


def write_system_pf_conf(text: str, dry_run: bool = False) -> None:
    if dry_run:
        print(f"[DRY-RUN] would write {SYSTEM_PF_CONF} with our anchor block")
        return
    with open(SYSTEM_PF_CONF, "w", encoding="utf-8") as handle:
        handle.write(text)


def ensure_pf_conf_references(dry_run: bool = False) -> bool:
    """Persist our anchor references into ``/etc/pf.conf``. Returns True if changed."""

    conf = read_system_pf_conf()
    if pf_conf_has_references(conf):
        return False
    write_system_pf_conf(add_references(conf), dry_run=dry_run)
    utils.log_action("Persisted anchor references into /etc/pf.conf")
    return True


def remove_pf_conf_references(dry_run: bool = False) -> bool:
    """Remove our anchor references from ``/etc/pf.conf``. Returns True if changed."""

    conf = read_system_pf_conf()
    if not pf_conf_has_references(conf):
        return False
    write_system_pf_conf(strip_references(conf), dry_run=dry_run)
    utils.log_action("Removed anchor references from /etc/pf.conf")
    return True


def is_anchor_active(dry_run: bool = False) -> bool:
    """Return True when the running main ruleset already references our anchor."""

    result = utils.run_command(["pfctl", "-sr"], dry_run=False)
    return f'anchor "{utils.PF_ANCHOR}"' in result.stdout


def is_pf_enabled(dry_run: bool = False) -> bool:
    """Return True when pf reports ``Status: Enabled``."""

    result = utils.run_command(["pfctl", "-s", "info"], dry_run=False)
    return bool(re.search(r"Status:\s+Enabled", result.stdout))


def enable_anchor(dry_run: bool = False) -> None:
    """Make the main ruleset reference our anchor, then enable pf.

    Our per-device rules live in the top-level ``mac_throttle`` anchor, which
    only takes effect if the main ruleset references it via ``anchor`` and
    ``dummynet-anchor``. We persist those two references into ``/etc/pf.conf``
    (idempotently, inside a clearly-marked block) so that on every boot they
    load *before* Internet Sharing adds its NAT anchors -- the two then coexist
    and no runtime reload is ever needed.

    A reload is only performed the very first time, when the reference is not yet
    active in the running ruleset. That single reload briefly flushes the
    Internet Sharing NAT (a few seconds' hotspot blip) before it is re-added.
    Once active, subsequent runs skip the reload entirely, so connected clients
    are not disturbed.
    """

    ensure_pf_conf_references(dry_run=dry_run)
    if not is_anchor_active():
        # One-time activation. Warn because Internet Sharing NAT is flushed and
        # re-established, briefly interrupting connected clients.
        utils.log_action(
            "Activating pf anchor references via reload; the hotspot may blip "
            "briefly while Internet Sharing re-establishes NAT."
        )
        utils.run_command(["pfctl", "-f", SYSTEM_PF_CONF], dry_run=dry_run)
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


def kill_states(ip: str, dry_run: bool = False) -> None:
    """Drop all pf state entries involving ``ip``.

    Newly loaded block/throttle rules only affect connections that have to be
    (re)established: pf passes packets belonging to an existing state without
    re-evaluating the ruleset. macOS Internet Sharing creates those states with
    ``keep state``, so an in-progress stream keeps flowing after a ``block``
    until its state is torn down. Flushing the device's states forces the next
    packet to be re-evaluated so the new rules take effect immediately.
    """

    utils.run_command(["pfctl", "-k", ip], dry_run=dry_run)


def restore_pf(was_enabled: bool, dry_run: bool = False) -> None:
    """Restore the prior pf state and remove our persisted anchor references.

    We remove our marked block from ``/etc/pf.conf`` so future boots are clean,
    but deliberately do NOT reload the ruleset here: the anchor is already
    emptied by :func:`flush_anchor`, and reloading would flush the runtime
    Internet Sharing NAT and drop connected clients. The now-inert reference
    disappears on the next boot. If pf was disabled before we started, we
    disable it again.
    """

    remove_pf_conf_references(dry_run=dry_run)
    if not was_enabled:
        utils.run_command(["pfctl", "-d"], dry_run=dry_run)


def apply_rules(state: dict, dry_run: bool = False) -> str:
    """Regenerate and load the anchor ruleset from ``state``.

    Returns the rule text that was loaded (useful for logging/tests).
    """

    rules_text = build_anchor_rules(state)
    load_anchor_rules(rules_text, dry_run=dry_run)
    return rules_text
