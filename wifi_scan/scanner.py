"""WiFiScanner — core 802.11 monitor-mode scanner for wifi-scan.

Architecture mirrors btrpa-scan's BLEScanner:
- Scapy AsyncSniffer replaces bleak BleakScanner
- Beacon frames (from APs) replace BLE advertisements
- Probe requests (from stations) replace BLE scan requests
- MAC randomization detection replaces RPA detection
- IE fingerprint correlation replaces IRK resolution
"""

import asyncio
import csv
import platform
import signal
import subprocess
import threading
import time
from collections import deque
from typing import Dict, List, Optional, Set

try:
    from scapy.layers.dot11 import (
        Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
        Dot11AssoReq, Dot11ReassoReq, Dot11Elt, RadioTap,
    )
    from scapy.sendrecv import AsyncSniffer
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False

from .constants import (
    _FIELDNAMES, _ENV_PATH_LOSS, _TUI_REFRESH_INTERVAL,
    _SCAN_POLL_INTERVAL, _TIMED_SCAN_POLL_INTERVAL, _GPS_STARTUP_DELAY,
    _CHANNELS_2GHZ, _CHANNELS_5GHZ, _CHANNELS_ALL, _CHANNEL_HOP_INTERVAL,
    _BANNER,
)
from .crypto import FingerprintCorrelator, estimate_distance, is_randomized
from .detection import (
    extract_ies, get_ssid, get_channel, get_rssi, get_encryption,
    parse_vendor_ies, parse_ht_caps, parse_vht_caps,
    compute_ie_fingerprint, compute_frame_fingerprint,
)
from .gps import GpsdReader
from .gui_server import GuiServer, _HAS_FLASK
from .lookup import get_oui_vendor
from .output import build_record, record_device, write_output, SqliteRecorder
from .tui import redraw_tui, install_sigwinch_handler
from .utils import _normalize_mac

_HAS_CURSES = False
try:
    import curses
    _HAS_CURSES = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Interface helpers
# ---------------------------------------------------------------------------

def _find_wireless_interfaces() -> List[str]:
    """Discover wireless interfaces via iw or /sys/class/net."""
    try:
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        ifaces = []
        for line in r.stdout.splitlines():
            s = line.strip()
            if s.startswith("Interface "):
                ifaces.append(s[len("Interface "):].strip())
        if ifaces:
            return ifaces
    except Exception:
        pass
    try:
        import os
        return [
            iface for iface in os.listdir("/sys/class/net")
            if os.path.exists(f"/sys/class/net/{iface}/wireless")
        ]
    except Exception:
        return []


def _get_interface_mode(iface: str) -> Optional[str]:
    """Return the current iw mode of an interface (e.g. 'managed', 'monitor')."""
    try:
        r = subprocess.run(["iw", "dev", iface, "info"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            s = line.strip()
            if s.startswith("type "):
                return s[5:].strip()
    except Exception:
        pass
    return None


def _setup_monitor(iface: str):
    """Automatically configure a monitor-mode interface for scanning.

    Strategy (in order):
    1. If ``iface`` is already in monitor mode — use it as-is, no cleanup needed.
    2. Try adding a virtual monitor interface ``<iface>mon`` alongside the
       existing managed interface (non-destructive, keeps WiFi connected).
       Supported by most Intel / Atheros / Broadcom drivers.
    3. Fall back to switching ``iface`` itself to monitor mode (disconnects any
       active WiFi association for the duration of the scan).

    Returns
    -------
    (monitor_iface, cleanup_fn)
        ``monitor_iface`` is the interface name to sniff on.
        ``cleanup_fn()`` tears down whatever was set up; call it on exit.

    Raises
    ------
    RuntimeError
        If none of the above strategies succeed.
    """
    current_mode = _get_interface_mode(iface)

    # Already in monitor mode — nothing to do
    if current_mode == "monitor":
        return iface, lambda: None

    mon_iface = iface + "mon"

    # Strategy 1: virtual monitor interface (keeps managed connection alive)
    try:
        subprocess.run(
            ["iw", "dev", iface, "interface", "add", mon_iface, "type", "monitor"],
            check=True, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["ip", "link", "set", mon_iface, "up"],
            check=True, capture_output=True, timeout=10,
        )

        def _cleanup_virtual():
            try:
                subprocess.run(["ip", "link", "set", mon_iface, "down"],
                               capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", mon_iface, "del"],
                               capture_output=True, timeout=5)
            except Exception:
                pass

        return mon_iface, _cleanup_virtual

    except subprocess.CalledProcessError:
        pass

    # Strategy 2: take the interface itself into monitor mode
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                       check=True, capture_output=True, timeout=10)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],
                       check=True, capture_output=True, timeout=10)
        subprocess.run(["ip", "link", "set", iface, "up"],
                       check=True, capture_output=True, timeout=10)

        def _cleanup_restore():
            try:
                subprocess.run(["ip", "link", "set", iface, "down"],
                               capture_output=True, timeout=5)
                subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                               capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", iface, "up"],
                               capture_output=True, timeout=5)
            except Exception:
                pass

        return iface, _cleanup_restore

    except subprocess.CalledProcessError:
        pass

    raise RuntimeError(
        f"Could not configure {iface} for monitor mode.\n"
        f"  Try manually:  sudo iw dev {iface} set type monitor"
    )


def _set_channel(iface: str, channel: int):
    """Set interface channel (best-effort)."""
    try:
        subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)],
                       capture_output=True, timeout=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Channel hopper
# ---------------------------------------------------------------------------

class _ChannelHopper:
    def __init__(self, iface: str, channels: List[int],
                 interval: float = _CHANNEL_HOP_INTERVAL):
        self._iface = iface
        self._channels = channels
        self._interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.current: int = channels[0] if channels else 1

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self):
        while not self._stop.is_set():
            for ch in self._channels:
                if self._stop.is_set():
                    return
                self.current = ch
                _set_channel(self._iface, ch)
                self._stop.wait(self._interval)


# ---------------------------------------------------------------------------
# WiFiScanner
# ---------------------------------------------------------------------------

class WiFiScanner:
    def __init__(
        self,
        interface: Optional[str] = None,
        target_mac: Optional[str] = None,
        target_ssid: Optional[str] = None,
        correlate: bool = False,
        scan_all: bool = False,
        frame_types: str = "all",
        output_format: Optional[str] = None,
        output_file: Optional[str] = None,
        log_file: Optional[str] = None,
        db_path: Optional[str] = None,
        min_rssi: Optional[int] = None,
        rssi_window: int = 1,
        environment: str = "indoor",
        ref_rssi: int = -37,
        alert_within: Optional[float] = None,
        name_filter: Optional[str] = None,
        channels: Optional[List[int]] = None,
        no_hop: bool = False,
        no_gps: bool = False,
        tui: bool = False,
        gui: bool = False,
        gui_port: int = 5000,
        verbose: bool = False,
        quiet: bool = False,
        timeout: Optional[float] = None,
        cleanup_fn=None,
    ):
        # Interface
        self.interface = interface
        self._cleanup_fn = cleanup_fn  # called on exit to tear down monitor mode

        # Targeting
        self.target_mac = _normalize_mac(target_mac) if target_mac else None
        self.target_ssid = target_ssid
        self.targeted = target_mac is not None
        self.ssid_targeted = target_ssid is not None
        self.correlate = correlate
        self.scan_all = not (self.targeted or self.ssid_targeted or correlate)

        # Frame types to capture: "beacon", "probe", "all"
        self.frame_types = frame_types

        # Counters and state
        self.seen_count = 0
        self.unique_devices: Dict[str, int] = {}   # mac → seen count
        self.running = True

        # Per-device data
        self.device_ssids: Dict[str, str] = {}         # mac → SSID (for APs)
        self.probe_ssids: Dict[str, Set[str]] = {}      # mac → set of probed SSIDs
        self.device_types: Dict[str, str] = {}          # mac → "AP" | "Station"
        self.frame_fingerprints: Dict[str, str] = {}    # mac → frame fingerprint
        self.device_best_gps: Dict[str, dict] = {}      # mac → {lat, lon, rssi}

        # RSSI sliding window (same as btrpa-scan)
        self.rssi_window = max(1, rssi_window)
        self.rssi_history: Dict[str, deque] = {}

        # IE fingerprint correlator (WiFi analog of IRK resolution)
        self.correlator = FingerprintCorrelator()
        self.correlation_count = 0   # number of new correlations found

        # Options
        self.verbose = verbose
        self.quiet = quiet
        self.min_rssi = min_rssi
        self.environment = environment
        self.ref_rssi = ref_rssi
        self.alert_within = alert_within
        self.name_filter = name_filter
        self.timeout = timeout

        # Output
        self.output_format = output_format
        self.output_file = output_file
        self.records: List[dict] = []
        self._accumulate_records = (output_format is not None)
        self.log_file = log_file
        self._log_writer = None
        self._log_fh = None

        # Channels
        if channels is not None:
            self.channels = channels
        else:
            self.channels = _CHANNELS_ALL
        self.no_hop = no_hop
        self._current_channel: Optional[int] = None
        self._hopper: Optional[_ChannelHopper] = None

        # GPS
        self._gps = GpsdReader() if not no_gps else None

        # TUI
        self.tui = tui
        self.tui_devices: Dict[str, dict] = {}
        self._tui_screen = None
        self._tui_start = 0.0
        self._tui_resize_pending = False

        # GUI
        self.gui = gui
        self.gui_port = gui_port
        self._gui_server: Optional[GuiServer] = None

        # SQLite
        self.db_path = db_path
        self._db_recorder: Optional[SqliteRecorder] = None

        # Thread safety
        self._cb_lock = threading.Lock()

    # -----------------------------------------------------------------------
    # RSSI averaging
    # -----------------------------------------------------------------------

    def _avg_rssi(self, addr: str, rssi: int) -> int:
        if addr not in self.rssi_history:
            self.rssi_history[addr] = deque(maxlen=self.rssi_window)
        self.rssi_history[addr].append(rssi)
        return round(sum(self.rssi_history[addr]) / len(self.rssi_history[addr]))

    # -----------------------------------------------------------------------
    # Packet callback (runs in scapy's sniffer thread)
    # -----------------------------------------------------------------------

    def packet_callback(self, pkt):
        with self._cb_lock:
            self._process_packet(pkt)

    def _process_packet(self, pkt):
        if not _HAS_SCAPY:
            return
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]
        subtype = getattr(dot11, "subtype", -1)
        frame_type = getattr(dot11, "type", -1)

        # Only management frames (type 0)
        if frame_type != 0:
            return

        if subtype == 8:    # Beacon
            if self.frame_types not in ("beacon", "all"):
                return
            self._process_beacon(pkt)
        elif subtype == 4:  # Probe Request
            if self.frame_types not in ("probe", "all"):
                return
            self._process_probe_request(pkt)
        elif subtype == 5:  # Probe Response
            if self.frame_types == "all":
                self._process_beacon(pkt)  # treat like beacon (has same AP info)
        elif subtype in (0, 2):  # Association / Reassociation Request
            if self.frame_types == "all":
                self._process_assoc_request(pkt)

    def _process_beacon(self, pkt):
        """Process a Beacon or Probe Response frame from an AP."""
        dot11 = pkt[Dot11]
        bssid = _normalize_mac(dot11.addr2 or dot11.addr3 or "")
        if not bssid:
            return

        rssi = get_rssi(pkt)
        if rssi is None:
            rssi = -99

        avg = self._avg_rssi(bssid, rssi)
        effective_rssi = avg if self.rssi_window > 1 else rssi

        if self.min_rssi is not None and effective_rssi < self.min_rssi:
            return

        ies = extract_ies(pkt)
        ssid = get_ssid(ies)
        channel = get_channel(pkt, ies)
        encryption = get_encryption(pkt, ies)

        if self.name_filter and self.name_filter.lower() not in (ssid or "").lower():
            return
        if self.ssid_targeted and self.target_ssid:
            if self.target_ssid.lower() not in (ssid or "").lower():
                return

        vendor = get_oui_vendor(bssid)
        vendor_ies = parse_vendor_ies(ies)
        ht_caps = None
        vht_caps = None
        for tag_id, data in ies:
            if tag_id == 45:
                ht_caps = parse_ht_caps(data)
            elif tag_id == 191:
                vht_caps = parse_vht_caps(data)

        fp = compute_frame_fingerprint(pkt)
        adv_changed = (bssid in self.frame_fingerprints
                       and self.frame_fingerprints[bssid] != fp)
        self.frame_fingerprints[bssid] = fp

        seen = self.unique_devices.get(bssid, 0) + 1
        self.unique_devices[bssid] = seen
        self.device_types[bssid] = "AP"
        self.device_ssids[bssid] = ssid
        self.seen_count += 1

        if self.targeted and self.target_mac and self.target_mac not in bssid:
            if self.verbose:
                pass  # could log non-matching
            return

        rec = build_record(
            self, bssid, ssid, "AP", rssi,
            avg if self.rssi_window > 1 else None,
            channel, encryption, False, vendor, None, None,
            None, vendor_ies, ht_caps, vht_caps, seen, adv_changed,
        )
        if self.targeted:
            label = f"TARGET AP  —  detection #{seen}"
        elif self.ssid_targeted:
            label = f"SSID MATCH  —  {ssid}  (#{seen})"
        else:
            label = f"AP #{len([d for d in self.device_types.values() if d == 'AP'])}  —  seen {seen}x"
        record_device(self, rec, label)

    def _process_probe_request(self, pkt):
        """Process a Probe Request frame from a WiFi station (client)."""
        dot11 = pkt[Dot11]
        src_mac = _normalize_mac(dot11.addr2 or "")
        if not src_mac:
            return

        rssi = get_rssi(pkt)
        if rssi is None:
            rssi = -99

        avg = self._avg_rssi(src_mac, rssi)
        effective_rssi = avg if self.rssi_window > 1 else rssi

        if self.min_rssi is not None and effective_rssi < self.min_rssi:
            return

        ies = extract_ies(pkt)
        probed_ssid = get_ssid(ies)   # empty = wildcard probe
        channel = get_channel(pkt, ies)

        # Track probed SSIDs per station
        if src_mac not in self.probe_ssids:
            self.probe_ssids[src_mac] = set()
        if probed_ssid:
            self.probe_ssids[src_mac].add(probed_ssid)

        if self.name_filter:
            probes = self.probe_ssids.get(src_mac, set())
            if not any(self.name_filter.lower() in s.lower() for s in probes):
                return

        if self.targeted and self.target_mac and self.target_mac not in src_mac:
            return

        rand = is_randomized(src_mac)
        vendor = get_oui_vendor(src_mac) if not rand else None
        vendor_ies = parse_vendor_ies(ies)
        ht_caps = None
        vht_caps = None
        for tag_id, data in ies:
            if tag_id == 45:
                ht_caps = parse_ht_caps(data)
            elif tag_id == 191:
                vht_caps = parse_vht_caps(data)

        # IE fingerprint (WiFi analog of BLE RPA)
        ie_fp = compute_ie_fingerprint(ies)
        fp = compute_frame_fingerprint(pkt)
        adv_changed = (src_mac in self.frame_fingerprints
                       and self.frame_fingerprints.get(src_mac) != fp)
        self.frame_fingerprints[src_mac] = fp

        seen = self.unique_devices.get(src_mac, 0) + 1
        self.unique_devices[src_mac] = seen
        self.device_types[src_mac] = "Station"
        self.seen_count += 1

        probe_list = sorted(self.probe_ssids.get(src_mac, set()))

        rec = build_record(
            self, src_mac, probed_ssid, "Station", rssi,
            avg if self.rssi_window > 1 else None,
            channel, "N/A", rand, vendor, ie_fp, probe_list,
            None, vendor_ies, ht_caps, vht_caps, seen, adv_changed,
        )

        # Correlate mode: fingerprint-based tracking across MAC rotations
        correlated_label = ""
        if self.correlate and ie_fp:
            existing = self.correlator.correlated_macs(ie_fp)
            self.correlator.update(src_mac, ie_fp)
            new_group = self.correlator.correlated_macs(ie_fp)
            if len(new_group) > 1 and existing and src_mac not in existing:
                self.correlation_count += 1
                other = sorted(new_group - {src_mac})
                correlated_label = f"  [FP match: {', '.join(other[:2])}]"

        if self.correlate and not correlated_label and len(
                self.correlator.correlated_macs(ie_fp)) > 1:
            correlated_label = f"  [correlated]"
        elif self.correlate:
            self.correlator.update(src_mac, ie_fp)

        if self.targeted:
            label = f"TARGET STATION  —  detection #{seen}"
        elif self.correlate and correlated_label:
            label = f"FP CORRELATED  —  addr #{seen}{correlated_label}"
        else:
            n_sta = len([d for d in self.device_types.values() if d == "Station"])
            label = f"STATION #{n_sta}  —  seen {seen}x"

        record_device(self, rec, label)

    def _process_assoc_request(self, pkt):
        """Process an Association or Reassociation Request (station → AP)."""
        dot11 = pkt[Dot11]
        src_mac = _normalize_mac(dot11.addr2 or "")
        bssid = _normalize_mac(dot11.addr1 or "")
        if not src_mac:
            return

        ies = extract_ies(pkt)
        ssid = get_ssid(ies)
        if ssid and src_mac:
            if src_mac not in self.probe_ssids:
                self.probe_ssids[src_mac] = set()
            self.probe_ssids[src_mac].add(ssid)
            # Update TUI entry if known
            if src_mac in self.tui_devices:
                probe_list = sorted(self.probe_ssids[src_mac])
                self.tui_devices[src_mac]["probe_ssids"] = ",".join(probe_list)

    # -----------------------------------------------------------------------
    # Main scan flow
    # -----------------------------------------------------------------------

    async def scan(self):
        if not _HAS_SCAPY:
            print("Error: 'scapy' is not installed.")
            print("Install with:  pip install scapy")
            return

        loop = asyncio.get_running_loop()
        if platform.system() != "Windows":
            loop.add_signal_handler(signal.SIGINT, self.stop)
            loop.add_signal_handler(signal.SIGTERM, self.stop)

        if self._gps is not None:
            self._gps.start()
            await asyncio.sleep(_GPS_STARTUP_DELAY)

        if self.log_file:
            self._log_fh = open(self.log_file, "w", newline="")
            self._log_writer = csv.DictWriter(self._log_fh, fieldnames=_FIELDNAMES)
            self._log_writer.writeheader()
            self._log_fh.flush()

        if self.db_path:
            import sys as _sys
            self._db_recorder = SqliteRecorder(self.db_path)
            self._db_recorder.open(cli_args=" ".join(_sys.argv))

        if self.gui:
            self._gui_server = GuiServer(port=self.gui_port)
            self._gui_server.start()

        if self.tui and _HAS_CURSES:
            self._tui_screen = curses.initscr()
            curses.noecho()
            curses.cbreak()
            curses.curs_set(0)
            if curses.has_colors():
                curses.start_color()
                curses.use_default_colors()
            install_sigwinch_handler(self)

        elapsed = 0.0
        try:
            elapsed = await self._scan_loop()
        finally:
            if self._tui_screen is not None and _HAS_CURSES:
                curses.curs_set(1)
                curses.nocbreak()
                curses.echo()
                curses.endwin()
                self._tui_screen = None

            if self._gps is not None:
                self._gps.stop()

            if self._log_fh is not None:
                self._log_fh.close()
                self._log_fh = None
                self._log_writer = None

            if self._db_recorder is not None:
                self._db_recorder.close()
                self._db_recorder = None

            if self._cleanup_fn is not None:
                self._cleanup_fn()

        if self.gui and self._gui_server is not None:
            self._gui_server.emit_status({
                "elapsed": round(elapsed, 1),
                "total_detections": self.seen_count,
                "unique_count": len(self.unique_devices),
                "scanning": False,
            })

        if self._gui_server is not None:
            self._gui_server.stop()

        if not self.gui:
            self._print_summary(elapsed)
        write_output(self)

    def _poll_tick(self, start: float):
        if self._tui_screen is not None:
            if self._hopper is not None:
                self._current_channel = self._hopper.current
            redraw_tui(self, self._tui_screen)
        if self.gui and self._gui_server is not None:
            el = time.time() - start
            self._gui_server.emit_status({
                "elapsed": round(el, 1),
                "total_detections": self.seen_count,
                "unique_count": len(self.unique_devices),
                "scanning": True,
            })
            if self._gps is not None:
                fix = self._gps.fix
                if fix is not None:
                    self._gui_server.emit_gps(fix)

    async def _scan_loop(self) -> float:
        if not self.quiet and not self.tui and not self.gui:
            self._print_header()

        # Start channel hopper
        if not self.no_hop and len(self.channels) > 1:
            self._hopper = _ChannelHopper(self.interface, self.channels)
            self._hopper.start()
        else:
            if self.channels:
                _set_channel(self.interface, self.channels[0])
                self._current_channel = self.channels[0]

        # BPF filter for management frames only
        bpf = "type mgt"

        sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self.packet_callback,
            filter=bpf,
            store=False,
        )
        sniffer.start()
        start = time.time()
        self._tui_start = start

        try:
            if self.timeout is None:
                while self.running:
                    self._poll_tick(start)
                    await asyncio.sleep(
                        _TUI_REFRESH_INTERVAL if self.tui else _SCAN_POLL_INTERVAL
                    )
            else:
                while self.running and (time.time() - start) < self.timeout:
                    self._poll_tick(start)
                    await asyncio.sleep(_TIMED_SCAN_POLL_INTERVAL)
        except asyncio.CancelledError:
            pass
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass
            if self._hopper is not None:
                self._hopper.stop()

        return time.time() - start

    def _print_header(self):
        print(_BANNER)
        if self.targeted:
            print(f"Mode: TARGETED — searching for {self.target_mac}")
        elif self.ssid_targeted:
            print(f"Mode: SSID TARGET — searching for SSID '{self.target_ssid}'")
        elif self.correlate:
            print("Mode: CORRELATE — tracking devices across MAC randomization")
            print("  Devices with matching IE fingerprints will be grouped")
        else:
            print("Mode: DISCOVER ALL — capturing all 802.11 management frames")

        frames = {"all": "beacon + probe requests", "beacon": "beacons only",
                  "probe": "probe requests only"}.get(self.frame_types, self.frame_types)
        print(f"Frame types: {frames}")
        print(f"Interface: {self.interface}")

        if self.rssi_window > 1:
            print(f"RSSI averaging: window of {self.rssi_window}")
        if self.environment != "free_space":
            print(f"Environment: {self.environment} (n={_ENV_PATH_LOSS[self.environment]})")
        if self.min_rssi is not None:
            print(f"Min RSSI: {self.min_rssi} dBm")
        if self.name_filter:
            print(f"Name filter: \"{self.name_filter}\"")
        if self.alert_within is not None:
            print(f"Proximity alert: within {self.alert_within} m")
        if self.log_file:
            print(f"Live log: {self.log_file}")
        if self.db_path:
            print(f"SQLite DB: {self.db_path}")
        if self._gps is not None:
            fix = self._gps.fix
            if fix is not None:
                print(f"GPS: connected ({fix['lat']:.6f}, {fix['lon']:.6f})")
            elif self._gps.connected:
                print("GPS: waiting for fix")
            else:
                print("GPS: gpsd not available — continuing without GPS")
        if self.timeout is None:
            print("Running continuously  |  Press Ctrl+C to stop")
        else:
            print(f"Timeout: {self.timeout}s  |  Press Ctrl+C to stop")
        print("—" * 60)

    def _print_summary(self, elapsed: float):
        n_aps = sum(1 for t in self.device_types.values() if t == "AP")
        n_sta = sum(1 for t in self.device_types.values() if t == "Station")
        print(f"\n{'—'*60}")
        print(f"Scan complete — {elapsed:.1f}s elapsed")
        print(f"  Total detections : {self.seen_count}")
        print(f"  Unique APs       : {n_aps}")
        print(f"  Unique stations  : {n_sta}")

        if self.correlate:
            groups = self.correlator.groups()
            print(f"  FP correlations  : {len(groups)} group(s) found")
            if groups:
                print(f"\n  Correlated MAC groups (same device, different MACs):")
                for fp, macs in sorted(groups, key=lambda x: len(x[1]), reverse=True):
                    print(f"    FP {fp}: {', '.join(sorted(macs))}")

        if not self.targeted and self.unique_devices:
            has_gps = bool(self.device_best_gps)
            if has_gps:
                print(f"\n  {'Address':<20} {'Type':<8} {'Seen':>6}  Best GPS")
                print(f"  {'—'*20} {'—'*8} {'—'*6}  {'—'*24}")
            else:
                print(f"\n  {'Address':<20} {'Type':<8} {'Seen':>6}")
                print(f"  {'—'*20} {'—'*8} {'—'*6}")
            for addr, cnt in sorted(self.unique_devices.items(),
                                     key=lambda x: x[1], reverse=True)[:20]:
                dtype = self.device_types.get(addr, "?")
                line = f"  {addr:<20} {dtype:<8} {cnt:>5}x"
                if has_gps:
                    bg = self.device_best_gps.get(addr)
                    if bg:
                        line += f"  {bg['lat']:.6f}, {bg['lon']:.6f}"
                print(line)

    def stop(self):
        if not self.tui and not self.gui and self.running:
            print("\nStopping scan...")
        self.running = False
