"""Command-line interface and orchestration for mac-network-throttle.

Subcommands: start, stop, status, throttle, block, unblock, list-devices.
Each state-changing command rebuilds the full dnctl pipe set and pf anchor
ruleset from persisted state (idempotent reconcile), so partial/overlapping
changes never leave inconsistent kernel state.
"""

from __future__ import annotations

import argparse
import signal
import sys
import time
from typing import List, Optional

from . import devices as devices_mod
from . import firewall, hotspot, throttle, utils


# ---------------------------------------------------------------------------
# Reconcile: make the kernel match persisted state
# ---------------------------------------------------------------------------
def reconcile(state: dict, dry_run: bool = False) -> None:
    """Apply all dummynet pipes and pf anchor rules implied by ``state``."""

    throttle.apply_pipes(state, dry_run=dry_run)
    firewall.apply_rules(state, dry_run=dry_run)


def ensure_device(state: dict, ip: str, mac: Optional[str] = None) -> dict:
    """Return the state record for ``ip``, creating it (with pipes) if new."""

    devices = state.setdefault("devices", {})
    record = devices.get(ip)
    if record is None:
        download, upload = utils.allocate_pipe_pair(state)
        record = utils.new_device_entry(mac, download, upload)
        devices[ip] = record
    elif mac and not record.get("mac"):
        record["mac"] = mac
    return record


def target_ips(state: dict, ip_arg: Optional[str], all_flag: bool) -> List[str]:
    """Resolve the set of device IPs a command should act on."""

    if all_flag:
        live = {
            d.ip
            for d in devices_mod.discover_devices(
                state.get("bridge_interface") or ""
            )
        }
        known = set(state.get("devices", {}).keys())
        return sorted(live | known)
    if ip_arg:
        return [firewall.validate_ip_or_cidr(ip_arg)]
    return []


# ---------------------------------------------------------------------------
# Cleanup / teardown
# ---------------------------------------------------------------------------
def teardown(dry_run: bool = False, stop_hotspot: bool = False) -> None:
    """Remove every rule/pipe this tool created and restore original state."""

    state = utils.load_state()
    utils.log_action("Tearing down: flushing anchor, pipes, restoring pf")

    firewall.flush_anchor(dry_run=dry_run)
    throttle.flush_pipes(dry_run=dry_run)
    firewall.restore_pf(state.get("pf_was_enabled", False), dry_run=dry_run)

    if stop_hotspot:
        hotspot.stop_sharing(dry_run=dry_run)

    if not dry_run:
        utils.clear_state()
    print("All throttling rules, pipes, and anchors removed. Network state restored.")


def _install_signal_handlers(dry_run: bool) -> None:
    def handler(signum, _frame):
        print(f"\nReceived signal {signum}; cleaning up...")
        teardown(dry_run=dry_run, stop_hotspot=False)
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------
def cmd_start(args: argparse.Namespace) -> int:
    utils.require_root(dry_run=args.dry_run)
    state = utils.load_state()

    source = args.source or utils.get_active_internet_interface()
    if not source:
        print("Could not detect the active internet interface. Use --source.",
              file=sys.stderr)
        return 1

    state["source_interface"] = source
    state["wifi_interface"] = args.wifi
    state["ssid"] = args.ssid
    state["pf_was_enabled"] = firewall.is_pf_enabled()

    print(hotspot.setup_guide(args.ssid, args.password))
    hotspot.configure_sharing(source, dry_run=args.dry_run)
    hotspot.start_sharing(dry_run=args.dry_run)

    bridge = args.bridge or hotspot.detect_bridge(dry_run=args.dry_run)
    if not bridge and not args.dry_run:
        print("NAT bridge interface not detected yet. Enable Internet Sharing "
              "(see guide above), then re-run 'start'.", file=sys.stderr)
        state["bridge_interface"] = None
        utils.save_state(state)
        return 2

    state["bridge_interface"] = bridge or "bridge100"
    state["running"] = True

    firewall.enable_anchor(dry_run=args.dry_run)
    reconcile(state, dry_run=args.dry_run)
    utils.save_state(state)

    print(f"Hotspot armed. Source={source} Bridge={state['bridge_interface']} "
          f"SSID={args.ssid}")

    if args.no_wait or args.dry_run:
        return 0

    _install_signal_handlers(args.dry_run)
    print("Running in the foreground. Press Ctrl-C to stop and clean up.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:  # pragma: no cover - defensive
        teardown(dry_run=args.dry_run)
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    utils.require_root(dry_run=args.dry_run)
    teardown(dry_run=args.dry_run, stop_hotspot=not args.keep_hotspot)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    state = utils.load_state()
    running = state.get("running")
    bridge = state.get("bridge_interface")
    pf_on = firewall.is_pf_enabled()

    device_count = 0
    if bridge:
        device_count = len(devices_mod.discover_devices(bridge))

    print("mac-network-throttle status")
    print(f"  running:          {bool(running)}")
    print(f"  pf enabled:       {pf_on}")
    print(f"  source interface: {state.get('source_interface')}")
    print(f"  bridge interface: {bridge}")
    print(f"  ssid:             {state.get('ssid')}")
    print(f"  connected devices:{device_count}")
    print(f"  managed devices:  {len(state.get('devices', {}))}")
    print("  active anchor rules:")
    for line in firewall.build_anchor_rules(state).splitlines():
        print(f"    {line}")
    return 0


def cmd_throttle(args: argparse.Namespace) -> int:
    utils.require_root(dry_run=args.dry_run)
    state = utils.load_state()

    bandwidth = throttle.parse_bandwidth(args.bandwidth)
    ips = target_ips(state, args.ip, args.all)
    if not ips:
        print("Specify --ip <addr> or --all.", file=sys.stderr)
        return 1

    for ip in ips:
        record = ensure_device(state, ip)
        record["bandwidth"] = bandwidth
        record["packet_loss"] = float(args.packet_loss)
        record["latency"] = int(args.latency)
        utils.log_action(
            f"throttle {ip} -> {throttle.describe_bandwidth(bandwidth)} "
            f"loss={args.packet_loss}% latency={args.latency}ms"
        )

    reconcile(state, dry_run=args.dry_run)
    utils.save_state(state)
    print(f"Applied {throttle.describe_bandwidth(bandwidth)} to: {', '.join(ips)}")
    return 0


def cmd_block(args: argparse.Namespace) -> int:
    utils.require_root(dry_run=args.dry_run)
    state = utils.load_state()

    ips = target_ips(state, args.ip, args.all)
    if not ips:
        print("Specify --ip <addr> or --all.", file=sys.stderr)
        return 1

    block_list = firewall.validate_ip_list(args.block_ips) if args.block_ips else []
    allow_list = (
        firewall.validate_ip_list(args.allow_only_ips) if args.allow_only_ips else []
    )
    if not block_list and not allow_list:
        print("Specify --block-ips and/or --allow-only-ips.", file=sys.stderr)
        return 1

    for ip in ips:
        record = ensure_device(state, ip)
        for entry in block_list:
            if entry not in record["block_ips"]:
                record["block_ips"].append(entry)
        if allow_list:
            record["allow_only_ips"] = allow_list
        utils.log_action(
            f"block {ip}: block_ips={record['block_ips']} "
            f"allow_only={record['allow_only_ips']}"
        )

    reconcile(state, dry_run=args.dry_run)
    utils.save_state(state)
    print(f"Updated blocking rules for: {', '.join(ips)}")
    return 0


def cmd_unblock(args: argparse.Namespace) -> int:
    utils.require_root(dry_run=args.dry_run)
    state = utils.load_state()

    ips = target_ips(state, args.ip, args.all)
    if not ips:
        print("Specify --ip <addr> or --all.", file=sys.stderr)
        return 1

    remove = firewall.validate_ip_list(args.block_ips) if args.block_ips else []

    for ip in ips:
        record = state.get("devices", {}).get(ip)
        if record is None:
            continue
        if args.clear_allow:
            record["allow_only_ips"] = []
        if remove:
            record["block_ips"] = [
                entry for entry in record["block_ips"] if entry not in remove
            ]
        elif not args.clear_allow:
            # No specific IPs and not clearing allow-list -> clear all blocks.
            record["block_ips"] = []
        utils.log_action(f"unblock {ip}: block_ips={record['block_ips']}")

    reconcile(state, dry_run=args.dry_run)
    utils.save_state(state)
    print(f"Updated unblock rules for: {', '.join(ips)}")
    return 0


def cmd_list_devices(args: argparse.Namespace) -> int:
    state = utils.load_state()
    bridge = state.get("bridge_interface")
    if not bridge:
        print("No bridge interface known. Run 'start' first.", file=sys.stderr)
        return 1

    live = devices_mod.discover_devices(bridge)
    merged = devices_mod.merge_state(live, state)

    header = f"{'IP':<16}{'MAC':<20}{'BANDWIDTH':<16}{'BLOCKED':<24}{'ALLOW-ONLY'}"
    print(header)
    print("-" * len(header))
    for device in merged:
        blocked = ",".join(device.block_ips) or "-"
        allow = ",".join(device.allow_only_ips) or "-"
        print(
            f"{device.ip:<16}{(device.mac or '-'):<20}"
            f"{throttle.describe_bandwidth(device.bandwidth):<16}"
            f"{blocked:<24}{allow}"
        )
    if not merged:
        print("(no devices found)")
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mac-throttle",
        description="Turn a Mac into a network-throttling WiFi hotspot.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the pfctl/dnctl commands without executing them.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # start
    p_start = sub.add_parser("start", help="Enable the hotspot and arm throttling.")
    p_start.add_argument("--ssid", default="MacThrottle", help="WiFi network name.")
    p_start.add_argument("--password", default="", help="WiFi password.")
    p_start.add_argument("--source", help="Uplink interface (auto-detected).")
    p_start.add_argument("--wifi", default="en1", help="WiFi interface for sharing.")
    p_start.add_argument("--bridge", help="Override NAT bridge interface detection.")
    p_start.add_argument(
        "--no-wait",
        action="store_true",
        help="Set up and exit instead of running in the foreground.",
    )
    p_start.set_defaults(func=cmd_start)

    # stop
    p_stop = sub.add_parser("stop", help="Remove all rules and restore state.")
    p_stop.add_argument(
        "--keep-hotspot",
        action="store_true",
        help="Leave Internet Sharing running; only remove throttle/block rules.",
    )
    p_stop.set_defaults(func=cmd_stop)

    # status
    p_status = sub.add_parser("status", help="Show hotspot state and active rules.")
    p_status.set_defaults(func=cmd_status)

    # throttle
    p_throttle = sub.add_parser("throttle", help="Set per-device bandwidth.")
    p_throttle.add_argument(
        "--bandwidth",
        required=True,
        help="Preset (256k, 1m, unlimited, 0) or raw kbps value.",
    )
    p_throttle.add_argument("--ip", help="Target device IP.")
    p_throttle.add_argument("--all", action="store_true", help="All connected devices.")
    p_throttle.add_argument(
        "--packet-loss", type=float, default=0.0, help="Packet loss percent (0-100)."
    )
    p_throttle.add_argument(
        "--latency", type=int, default=0, help="One-way latency in ms."
    )
    p_throttle.set_defaults(func=cmd_throttle)

    # block
    p_block = sub.add_parser("block", help="Block/whitelist destinations for a device.")
    p_block.add_argument("--ip", help="Target device IP.")
    p_block.add_argument("--all", action="store_true", help="All connected devices.")
    p_block.add_argument("--block-ips", help="Comma-separated IPs/CIDRs to block.")
    p_block.add_argument(
        "--allow-only-ips",
        help="Comma-separated IPs/CIDRs; block everything else (whitelist mode).",
    )
    p_block.set_defaults(func=cmd_block)

    # unblock
    p_unblock = sub.add_parser("unblock", help="Remove blocking rules for a device.")
    p_unblock.add_argument("--ip", help="Target device IP.")
    p_unblock.add_argument("--all", action="store_true", help="All connected devices.")
    p_unblock.add_argument(
        "--block-ips",
        help="Specific IPs/CIDRs to unblock (default: clear all blocks).",
    )
    p_unblock.add_argument(
        "--clear-allow",
        action="store_true",
        help="Also clear the allow-only (whitelist) list.",
    )
    p_unblock.set_defaults(func=cmd_unblock)

    # list-devices
    p_list = sub.add_parser("list-devices", help="List connected clients + rules.")
    p_list.set_defaults(func=cmd_list_devices)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (PermissionError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
