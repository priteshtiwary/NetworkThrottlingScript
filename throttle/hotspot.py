"""Internet Sharing (WiFi hotspot) management.

Reality check: macOS does not expose a fully-supported, stable command-line API
for configuring the *WiFi* side of Internet Sharing (SSID/password) across every
release from Monterey (12) through Sequoia (15). The old ``airport`` utility that
some scripts abused was removed, and the ``com.apple.nat.plist`` layout for the
WiFi network is undocumented and version-specific.

Therefore this module:

* Programmatically writes the NAT sharing configuration (source → destination
  interface) into ``com.apple.nat.plist`` on a best-effort basis.
* Attempts to (re)start the Internet Sharing daemon.
* Detects the resulting NAT bridge interface dynamically.
* Provides an explicit, copy-pasteable manual setup guide describing the single
  step (creating/naming the WiFi network + password in System Settings) that may
  require a human on some macOS versions.
"""

from __future__ import annotations

from typing import Optional

from . import utils

NAT_PLIST = "/Library/Preferences/SystemConfiguration/com.apple.nat.plist"
SHARING_DAEMON = "/System/Library/LaunchDaemons/com.apple.InternetSharing.plist"


SETUP_GUIDE = """\
Internet Sharing manual setup (one-time, GUI step required on some macOS versions)
==================================================================================
Automating the WiFi SSID/password for Internet Sharing is not reliably supported
by the macOS command line across all versions (Monterey–Sequoia). Configure the
WiFi network once via the GUI; this tool handles everything else programmatically.

1. Open System Settings → General → Sharing.
2. Click the (i) next to "Internet Sharing".
3. "Share your connection from:" choose your uplink (e.g. Ethernet or Wi-Fi/en0).
4. "To computers using:" tick "Wi-Fi".
5. Click "Wi-Fi Options…" and set:
      Network Name (SSID): {ssid}
      Security:            WPA2/WPA3 Personal
      Password:            {password}
6. Toggle "Internet Sharing" ON (authenticate if prompted).

Once the hotspot is running, re-run:  sudo mac-throttle start --no-wait
to detect the NAT bridge interface and arm throttling/blocking.
"""


def setup_guide(ssid: str, password: str) -> str:
    """Return the manual setup guide filled in with the requested credentials."""

    return SETUP_GUIDE.format(ssid=ssid, password=password or "<choose a password>")


def build_nat_plist_commands(source_interface: str) -> list:
    """Build ``defaults write`` commands that enable NAT sharing from a source.

    These configure the NAT/PF sharing state; the WiFi network parameters are
    handled by the GUI step (see :data:`SETUP_GUIDE`).
    """

    return [
        ["defaults", "write", NAT_PLIST, "NAT", "-dict",
         "Enabled", "-int", "1",
         "PrimaryInterface", "-dict",
         "Device", source_interface,
         "Enabled", "-int", "1"],
    ]


def configure_sharing(source_interface: str, dry_run: bool = False) -> None:
    """Write the NAT sharing configuration for ``source_interface``."""

    for cmd in build_nat_plist_commands(source_interface):
        utils.run_command(cmd, dry_run=dry_run)
    utils.log_action(f"Configured Internet Sharing source interface: {source_interface}")


def start_sharing(dry_run: bool = False) -> None:
    """Attempt to start the Internet Sharing daemon."""

    utils.run_command(
        ["launchctl", "load", "-w", SHARING_DAEMON], dry_run=dry_run
    )
    utils.log_action("Requested Internet Sharing daemon start")


def stop_sharing(dry_run: bool = False) -> None:
    """Attempt to stop the Internet Sharing daemon."""

    utils.run_command(
        ["launchctl", "unload", "-w", SHARING_DAEMON], dry_run=dry_run
    )
    utils.log_action("Requested Internet Sharing daemon stop")


def detect_bridge(dry_run: bool = False) -> Optional[str]:
    """Return the active NAT bridge interface, if Internet Sharing is up."""

    return utils.get_bridge_interface(dry_run=dry_run)
