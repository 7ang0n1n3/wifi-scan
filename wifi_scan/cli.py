"""Command-line interface for wifi-scan."""

import argparse
import asyncio
import sys
from typing import Optional

from .constants import _CHANNELS_2GHZ, _CHANNELS_5GHZ, _CHANNELS_ALL


def _check_root():
    """Warn if not running as root (monitor mode requires CAP_NET_ADMIN)."""
    import os
    if os.geteuid() != 0:
        print("[!] Warning: wifi-scan requires root (or CAP_NET_RAW + CAP_NET_ADMIN)")
        print("    Run with: sudo wifi-scan  OR  sudo python -m wifi_scan")
        print()


def _auto_detect_interface() -> Optional[str]:
    """Return the first available wireless interface."""
    from .scanner import _find_wireless_interfaces
    ifaces = _find_wireless_interfaces()
    return ifaces[0] if ifaces else None


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wifi-scan",
        description=(
            "WiFi scanner with monitor-mode packet capture, MAC randomization\n"
            "detection, IE fingerprint correlation, and SQLite/CSV/JSON output.\n\n"
            "  --correlate  tracks devices across MAC rotations via IE fingerprinting\n"
            "               (groups devices sharing the same probe request IE sequence)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Positional: target MAC
    p.add_argument(
        "mac", nargs="?", default=None,
        help="Target a specific BSSID/MAC address",
    )

    # Scan mode
    mode = p.add_argument_group("Scan mode")
    mode_ex = mode.add_mutually_exclusive_group()
    mode_ex.add_argument(
        "-a", "--all", dest="scan_all", action="store_true",
        help="Discover all devices (default when no target given)",
    )
    mode_ex.add_argument(
        "--ssid", metavar="SSID",
        help="Track a specific SSID (partial match, case-insensitive)",
    )
    mode_ex.add_argument(
        "--correlate", action="store_true",
        help="Correlate devices across MAC randomization using IE fingerprinting",
    )

    # Interface
    iface = p.add_argument_group("Interface")
    iface.add_argument(
        "-i", "--interface", metavar="IFACE",
        help="Wireless interface to use (default: auto-detect). "
             "Monitor mode is configured automatically.",
    )

    # Channel selection
    ch_grp = p.add_argument_group("Channel")
    ch_ex = ch_grp.add_mutually_exclusive_group()
    ch_ex.add_argument(
        "--channel", type=int, metavar="N",
        help="Stay on a single channel (disables hopping)",
    )
    ch_ex.add_argument(
        "--2ghz", dest="two_ghz", action="store_true",
        help="2.4 GHz channels only (1–13)",
    )
    ch_ex.add_argument(
        "--5ghz", dest="five_ghz", action="store_true",
        help="5 GHz channels only",
    )
    ch_grp.add_argument(
        "--no-hop", action="store_true",
        help="Disable channel hopping (stay on the first selected channel)",
    )
    ch_grp.add_argument(
        "--hop-interval", type=float, default=None, metavar="SEC",
        help="Seconds to dwell on each channel before hopping (default: 0.1, min: 0.05)",
    )

    # Frame types
    frame = p.add_argument_group("Capture")
    frame.add_argument(
        "--frame-types", choices=["all", "beacon", "probe"], default="all",
        help="Frame types to capture: all, beacon, or probe (default: all)",
    )

    # Output
    out = p.add_argument_group("Output")
    out.add_argument(
        "--output", choices=["csv", "json", "jsonl"],
        help="Batch output format written at end of scan",
    )
    out.add_argument(
        "-o", "--output-file", metavar="FILE",
        help="Output file path (use - for stdout, default: wifi-scan-<ts>.<ext>)",
    )
    out.add_argument(
        "--log", metavar="FILE",
        help="Real-time CSV log file (written during scan)",
    )
    out.add_argument(
        "--db", metavar="FILE",
        help="SQLite database file for persistent storage",
    )

    # Signal tuning
    tuning = p.add_argument_group("Signal tuning")
    tuning.add_argument(
        "--min-rssi", type=int, metavar="DBM",
        help="Ignore devices below this RSSI threshold (e.g. -80)",
    )
    tuning.add_argument(
        "--rssi-window", type=int, default=1, metavar="N",
        help="RSSI averaging window (1 = no averaging, default: 1)",
    )
    tuning.add_argument(
        "--environment", choices=["free_space", "outdoor", "indoor"],
        default="indoor",
        help="Path-loss exponent for distance estimation (default: indoor)",
    )
    tuning.add_argument(
        "--ref-rssi", type=int, default=-37, metavar="DBM",
        help="Reference RSSI at 1 m for distance estimation (default: -37)",
    )
    tuning.add_argument(
        "--name-filter", metavar="PATTERN",
        help="Case-insensitive SSID substring filter",
    )
    tuning.add_argument(
        "--alert-within", type=float, metavar="METERS",
        help="Print a proximity alert when a device is within this distance",
    )

    # UI
    ui = p.add_argument_group("User interface")
    ui.add_argument("--tui", action="store_true",
                    help="Show live curses TUI device table")
    ui.add_argument("--gui", action="store_true",
                    help="Open Flask web radar GUI in browser")
    ui.add_argument("--gui-port", type=int, default=5000, metavar="PORT",
                    help="Web GUI port (default: 5000)")

    # GPS
    gps = p.add_argument_group("GPS")
    gps.add_argument("--no-gps", action="store_true",
                     help="Disable GPS stamping via gpsd")

    # Verbosity / timing
    misc = p.add_argument_group("Misc")
    misc.add_argument("-t", "--timeout", type=float, metavar="SECONDS",
                      help="Scan duration (default: run until Ctrl+C)")
    vq = misc.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true",
                    help="Show non-matching / extra detail")
    vq.add_argument("-q", "--quiet", action="store_true",
                    help="Summary only, no per-device output")
    misc.add_argument("--config", metavar="FILE",
                      help="Path to configuration file (TOML or JSON)")

    return p


def main():
    parser = _build_parser()
    args = parser.parse_args()

    # Merge config file
    from .config import load_config, merge_with_cli
    cfg = load_config(args.config)
    if cfg:
        merge_with_cli(args, cfg)

    # Check root
    _check_root()

    # Resolve interface
    if args.interface is None:
        args.interface = _auto_detect_interface()
        if args.interface is None:
            print("Error: No wireless interface found.")
            print("  Specify one with:  -i <interface>")
            sys.exit(1)
        print(f"[*] Using interface: {args.interface}")

    # Monitor mode — set up automatically
    from .scanner import _setup_monitor, _get_interface_mode
    current_mode = _get_interface_mode(args.interface)
    if current_mode == "monitor":
        print(f"[*] {args.interface} is already in monitor mode")
        monitor_iface, cleanup_fn = args.interface, lambda: None
    else:
        print(f"[*] Configuring monitor mode on {args.interface}...")
        try:
            monitor_iface, cleanup_fn = _setup_monitor(args.interface)
            if monitor_iface != args.interface:
                print(f"[*] Virtual monitor interface created: {monitor_iface} "
                      f"(WiFi connection on {args.interface} preserved)")
            else:
                print(f"[*] {args.interface} switched to monitor mode")
        except RuntimeError as e:
            print(f"Error: {e}")
            sys.exit(1)
    args.interface = monitor_iface

    # Build channel list
    if args.channel:
        channels = [args.channel]
        no_hop = True
    elif args.two_ghz:
        channels = _CHANNELS_2GHZ
        no_hop = args.no_hop
    elif args.five_ghz:
        channels = _CHANNELS_5GHZ
        no_hop = args.no_hop
    else:
        channels = _CHANNELS_ALL
        no_hop = args.no_hop

    # Scan mode
    target_mac = args.mac
    target_ssid = args.ssid
    correlate = args.correlate
    scan_all = args.scan_all or (not target_mac and not target_ssid and not correlate)

    from .scanner import WiFiScanner
    scanner = WiFiScanner(
        interface=args.interface,
        target_mac=target_mac,
        target_ssid=target_ssid,
        correlate=correlate,
        scan_all=scan_all,
        frame_types=args.frame_types,
        output_format=args.output,
        output_file=args.output_file,
        log_file=args.log,
        db_path=args.db,
        min_rssi=args.min_rssi,
        rssi_window=args.rssi_window,
        environment=args.environment,
        ref_rssi=args.ref_rssi,
        alert_within=args.alert_within,
        name_filter=args.name_filter,
        channels=channels,
        no_hop=no_hop,
        hop_interval=args.hop_interval,
        no_gps=args.no_gps,
        tui=args.tui,
        gui=args.gui,
        gui_port=args.gui_port,
        verbose=args.verbose,
        quiet=args.quiet,
        timeout=args.timeout,
        cleanup_fn=cleanup_fn,
    )

    try:
        asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\nError: Permission denied — run with sudo")
        sys.exit(1)
