"""Terminal UI (curses) functions for wifi-scan."""

import os
import signal
import sys
import time
from collections import deque

_HAS_CURSES = False
try:
    import curses
    _HAS_CURSES = True
except ImportError:
    pass


def make_sparkline(rssi_samples: deque, width: int = 8) -> str:
    """Build a unicode block-character sparkline from RSSI samples.

    RSSI range clamped to [-100, -30] dBm, normalized to 0–1.
    Returns a string of ``width`` characters, left-padded with spaces when
    fewer than ``width`` samples are available.
    """
    BLOCKS = " ▁▂▃▄▅▆▇█"
    RSSI_MIN, RSSI_MAX = -100, -30
    samples = list(rssi_samples)[-width:]
    result = []
    for rssi in samples:
        clamped = max(RSSI_MIN, min(RSSI_MAX, rssi))
        normalized = (clamped - RSSI_MIN) / (RSSI_MAX - RSSI_MIN)
        level = int(normalized * (len(BLOCKS) - 1))
        result.append(BLOCKS[level])
    return " " * (width - len(result)) + "".join(result)


def install_sigwinch_handler(scanner):
    """Install SIGWINCH handler to flag pending TUI resize.  No-op on Windows."""
    if sys.platform == "win32":
        return

    def _handler(signum, frame):
        try:
            rows, cols = os.get_terminal_size()
            if _HAS_CURSES:
                curses.resizeterm(rows, cols)
        except OSError:
            pass
        scanner._tui_resize_pending = True

    signal.signal(signal.SIGWINCH, _handler)


def redraw_tui(scanner, screen):
    """Redraw the live TUI device table.

    Adaptive column layout:
    - ≥110 cols: full view with Vendor, Type, Enc, Signal sparkline
    - <110 cols: compact layout
    """
    if not _HAS_CURSES:
        return
    try:
        if getattr(scanner, "_tui_resize_pending", False):
            screen.clear()
            scanner._tui_resize_pending = False

        screen.erase()
        h, w = screen.getmaxyx()

        elapsed = time.time() - scanner._tui_start
        n_aps = sum(1 for d in scanner.tui_devices.values() if d.get("device_type") == "AP")
        n_sta = sum(1 for d in scanner.tui_devices.values() if d.get("device_type") == "Station")
        header = (f" wifi-scan | APs: {n_aps}  Stations: {n_sta}"
                  f"  Detections: {scanner.seen_count}"
                  f"  Elapsed: {elapsed:.0f}s")
        if scanner.correlate:
            groups = scanner.correlator.groups()
            header += f"  FP groups: {len(groups)}"
        screen.addnstr(0, 0, header.ljust(w - 1), w - 1,
                       curses.A_BOLD | curses.A_REVERSE)

        # Settings bar
        iface = getattr(scanner, "interface", "?")
        settings = f" iface:{iface}"
        if scanner.environment != "free_space":
            settings += f" | env:{scanner.environment}"
        if scanner.rssi_window > 1:
            settings += f" | avg:{scanner.rssi_window}"
        if scanner.min_rssi is not None:
            settings += f" | min:{scanner.min_rssi}"
        if scanner.alert_within is not None:
            settings += f" | alert:<{scanner.alert_within}m"
        ch = getattr(scanner, "_current_channel", None)
        if ch:
            settings += f" | ch:{ch}"
        if scanner._gps is not None:
            fix = scanner._gps.fix
            if fix is not None:
                settings += f" | GPS:{fix['lat']:.5f},{fix['lon']:.5f}"
            elif scanner._gps.connected:
                settings += " | GPS:no-fix"
            else:
                settings += " | GPS:offline"
        screen.addnstr(1, 0, settings, w - 1, curses.A_DIM)

        wide_mode = w >= 110

        if wide_mode:
            col_fmt = " {:<17s} {:<16s} {:>4s} {:>5s} {:>7s} {:>4s} {:>3s} {:>5s} {:>8s} {:<10s} {:<7s} {:<8s}"
            col_hdr = col_fmt.format(
                "Address", "SSID/Probing", "Type", "RSSI", "Dist", "Ch", "Enc",
                "Seen", "Last", "Vendor", "Rand", "Signal")
        else:
            col_fmt = " {:<17s} {:<16s} {:>4s} {:>5s} {:>7s} {:>4s} {:>5s} {:>8s}"
            col_hdr = col_fmt.format(
                "Address", "SSID/Probing", "Type", "RSSI", "Dist", "Ch",
                "Seen", "Last")

        screen.addnstr(3, 0, col_hdr, w - 1, curses.A_UNDERLINE)

        sorted_devs = sorted(
            scanner.tui_devices.values(),
            key=lambda d: d.get("rssi") or -999,
            reverse=True,
        )

        row = 4
        for dev in sorted_devs:
            if row >= h - 1:
                remaining = len(sorted_devs) - (row - 4)
                screen.addnstr(h - 1, 0,
                                f" ... {remaining} more (resize terminal)", w - 1)
                break

            addr = (dev.get("address") or "")[:17]
            dtype_short = (dev.get("device_type") or "?")[:4]
            rssi_val = dev.get("rssi")
            rssi_str = str(rssi_val) if rssi_val is not None else ""
            dist_val = dev.get("est_distance")
            dist_str = f"~{dist_val:.1f}m" if isinstance(dist_val, (int, float)) else ""
            ch_str = str(dev.get("channel") or "")
            seen_str = f"{dev.get('times_seen', 1)}x"
            last_str = dev.get("last_seen", "")[:8]

            # Display SSID for APs, probe targets for stations
            if dev.get("device_type") == "AP":
                name_str = (dev.get("ssid") or "[hidden]")[:16]
            else:
                probes = dev.get("probe_ssids", "") or ""
                first_probe = probes.split(",")[0].strip() if probes else ""
                name_str = first_probe[:16] or "[scanning]"

            if wide_mode:
                enc_short = (dev.get("encryption") or "")[:7]
                vendor = (dev.get("vendor") or "")[:10]
                rand_str = "yes" if dev.get("is_randomized") else "no"
                spark = make_sparkline(
                    scanner.rssi_history.get(
                        (dev.get("address") or "").upper(), deque()),
                    width=8,
                )
                line = col_fmt.format(
                    addr, name_str, dtype_short, rssi_str, dist_str,
                    ch_str, enc_short, seen_str, last_str, vendor, rand_str, spark,
                )
            else:
                line = col_fmt.format(
                    addr, name_str, dtype_short, rssi_str, dist_str,
                    ch_str, seen_str, last_str,
                )

            attr = curses.A_NORMAL
            if dev.get("is_randomized"):
                attr = curses.A_DIM
            if dev.get("device_type") == "AP":
                attr = curses.A_NORMAL
            if (scanner.correlate and dev.get("ie_fingerprint")
                    and len(scanner.correlator.correlated_macs(
                        dev.get("ie_fingerprint", ""))) > 1):
                attr |= curses.A_BOLD   # correlated device
            if (scanner.alert_within is not None
                    and isinstance(dist_val, (int, float))
                    and dist_val <= scanner.alert_within):
                attr |= curses.A_STANDOUT

            screen.addnstr(row, 0, line, w - 1, attr)
            row += 1

        footer = " Press Ctrl+C to stop"
        if scanner.log_file:
            footer += f"  |  Logging to {scanner.log_file}"
        if getattr(scanner, "db_path", None):
            footer += f"  |  DB: {scanner.db_path}"
        screen.addnstr(h - 1, 0, footer, w - 1, curses.A_DIM)
        screen.refresh()

    except curses.error:
        pass
