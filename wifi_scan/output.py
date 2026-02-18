"""Record building, console output, CSV/JSON/JSONL/SQLite persistence for wifi-scan."""

import csv
import json
import sqlite3
import sys
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from .constants import _FIELDNAMES
from .utils import _timestamp

if TYPE_CHECKING:
    from .scanner import WiFiScanner


# ---------------------------------------------------------------------------
# Record building
# ---------------------------------------------------------------------------

def build_record(scanner: "WiFiScanner", addr: str,
                 ssid: str, device_type: str, rssi: int,
                 avg_rssi: Optional[int], channel: Optional[int],
                 encryption: str, is_randomized: bool,
                 vendor: Optional[str], ie_fingerprint: Optional[str],
                 probe_ssids: Optional[List[str]], capabilities: Optional[str],
                 vendor_ies: Optional[List[Dict]], ht_caps: Optional[str],
                 vht_caps: Optional[str], seen_count: int,
                 adv_changed: Optional[bool]) -> Dict[str, Any]:
    """Build a flat detection record dict for output/storage."""
    gps = None
    if scanner._gps is not None:
        gps = scanner._gps.fix

    dist = None
    if rssi is not None:
        from .crypto import estimate_distance
        dist = estimate_distance(rssi, ref_rssi=scanner.ref_rssi,
                                 environment=scanner.environment)

    record: Dict[str, Any] = {
        "timestamp": _timestamp(),
        "address": addr,
        "ssid": ssid or "",
        "device_type": device_type,
        "rssi": rssi,
        "avg_rssi": avg_rssi,
        "channel": channel,
        "encryption": encryption,
        "is_randomized": int(is_randomized),
        "vendor": vendor or "",
        "ie_fingerprint": ie_fingerprint or "",
        "probe_ssids": ",".join(probe_ssids) if probe_ssids else "",
        "capabilities": capabilities or "",
        "latitude": gps["lat"] if gps else None,
        "longitude": gps["lon"] if gps else None,
        "gps_altitude": gps.get("alt") if gps else None,
        "vendor_ies": json.dumps(vendor_ies) if vendor_ies else "",
        "ht_caps": ht_caps or "",
        "vht_caps": vht_caps or "",
        "seen_count": seen_count,
        "adv_changed": int(adv_changed) if adv_changed is not None else None,
        # non-CSV extras kept for in-memory use / console printing
        "est_distance": dist,
        "name": ssid or "",  # TUI compat alias
    }
    return record


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

def _sep(char="=", width=60):
    return char * width


def print_device(scanner: "WiFiScanner", record: Dict[str, Any], label: str):
    """Print a formatted detection to stdout."""
    if scanner.quiet or scanner.tui or scanner.gui:
        return

    addr = record.get("address", "")
    ssid = record.get("ssid", "")
    dtype = record.get("device_type", "")
    rssi = record.get("rssi")
    dist = record.get("est_distance")
    ch = record.get("channel")
    enc = record.get("encryption", "")
    vendor = record.get("vendor", "")
    ie_fp = record.get("ie_fingerprint", "")
    probes = record.get("probe_ssids", "")
    ht = record.get("ht_caps", "")
    vht = record.get("vht_caps", "")
    rand = record.get("is_randomized")
    vendor_ies = record.get("vendor_ies", "")
    gps_lat = record.get("latitude")
    gps_lon = record.get("longitude")
    ts = record.get("timestamp", "")

    print(f"\n{_sep()}")
    print(f"  {label}")
    print(f"{_sep()}")
    print(f"  {'Address':<14}: {addr}{' [randomized MAC]' if rand else ''}")
    if ssid:
        print(f"  {'SSID':<14}: {ssid}")
    print(f"  {'Type':<14}: {dtype}")
    if rssi is not None:
        print(f"  {'RSSI':<14}: {rssi} dBm")
    if dist is not None:
        print(f"  {'Est. Distance':<14}: ~{dist:.1f} m")
    if ch is not None:
        print(f"  {'Channel':<14}: {ch}")
    if enc and dtype == "AP":
        print(f"  {'Encryption':<14}: {enc}")
    if vendor:
        print(f"  {'Vendor':<14}: {vendor}")
    if ie_fp and dtype == "Station":
        print(f"  {'IE Fingerprint':<14}: {ie_fp}")
    if probes and dtype == "Station":
        print(f"  {'Probing':<14}: {probes}")
    if ht:
        print(f"  {'HT Caps':<14}: {ht}")
    if vht:
        print(f"  {'VHT Caps':<14}: {vht}")
    if vendor_ies and vendor_ies != "[]":
        try:
            ies = json.loads(vendor_ies) if isinstance(vendor_ies, str) else vendor_ies
            names = [v.get("name", v.get("oui", "?")) for v in ies]
            if names:
                print(f"  {'Vendor IEs':<14}: {', '.join(names)}")
        except Exception:
            pass
    if gps_lat is not None and gps_lon is not None:
        print(f"  {'Best GPS':<14}: {gps_lat:.6f}, {gps_lon:.6f}")
    ts_short = ts[11:19] if len(ts) >= 19 else ts
    print(f"  {'Timestamp':<14}: {ts_short}")
    print(f"{_sep()}")


# ---------------------------------------------------------------------------
# Record persistence
# ---------------------------------------------------------------------------

def record_device(scanner: "WiFiScanner", record: Dict[str, Any], label: str):
    """Persist a detection record and update scanner state."""
    addr = record.get("address", "")
    rssi = record.get("rssi")

    # Update TUI device table
    scanner.tui_devices[addr] = {
        **record,
        "times_seen": record.get("seen_count", 1),
        "last_seen": (record.get("timestamp", ""))[11:19],
    }

    # Update best GPS per device
    if record.get("latitude") is not None and rssi is not None:
        best = scanner.device_best_gps.get(addr)
        if best is None or rssi > best.get("rssi", -999):
            scanner.device_best_gps[addr] = {
                "lat": record["latitude"],
                "lon": record["longitude"],
                "rssi": rssi,
            }

    # Real-time CSV log
    if scanner._log_writer is not None:
        row = {k: record.get(k, "") for k in _FIELDNAMES}
        scanner._log_writer.writerow(row)
        if scanner._log_fh is not None:
            scanner._log_fh.flush()

    # SQLite recorder
    if scanner._db_recorder is not None:
        scanner._db_recorder.insert(record)

    # GUI event
    if scanner._gui_server is not None:
        scanner._gui_server.emit_device(record)

    # Proximity alert
    dist = record.get("est_distance")
    if (scanner.alert_within is not None
            and isinstance(dist, (int, float))
            and dist <= scanner.alert_within
            and not scanner.tui and not scanner.gui):
        print(f"\n  *** PROXIMITY ALERT: {addr} within {dist:.1f} m ***")

    # Accumulate for batch output
    if scanner._accumulate_records:
        scanner.records.append({k: record.get(k, "") for k in _FIELDNAMES})

    print_device(scanner, record, label)


def write_output(scanner: "WiFiScanner"):
    """Write accumulated records in the requested batch format."""
    if not scanner.records or scanner.output_format is None:
        return

    out = scanner.output_file or "-"
    fh = sys.stdout if out == "-" else open(out, "w", newline="")

    try:
        fmt = scanner.output_format
        if fmt == "csv":
            writer = csv.DictWriter(fh, fieldnames=_FIELDNAMES)
            writer.writeheader()
            writer.writerows(scanner.records)
        elif fmt == "json":
            json.dump(scanner.records, fh, indent=2)
            fh.write("\n")
        elif fmt == "jsonl":
            for rec in scanner.records:
                fh.write(json.dumps(rec) + "\n")
    finally:
        if fh is not sys.stdout:
            fh.close()


# ---------------------------------------------------------------------------
# SQLite recorder
# ---------------------------------------------------------------------------

class SqliteRecorder:
    """Persist detections to an SQLite database with session tracking."""

    _CREATE_SESSIONS = """
    CREATE TABLE IF NOT EXISTS sessions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at  TEXT,
        ended_at    TEXT,
        cli_args    TEXT
    );
    """
    _CREATE_DETECTIONS = """
    CREATE TABLE IF NOT EXISTS detections (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  INTEGER,
        timestamp   TEXT,
        address     TEXT,
        ssid        TEXT,
        device_type TEXT,
        rssi        INTEGER,
        avg_rssi    INTEGER,
        channel     INTEGER,
        encryption  TEXT,
        is_randomized INTEGER,
        vendor      TEXT,
        ie_fingerprint TEXT,
        probe_ssids TEXT,
        capabilities TEXT,
        latitude    REAL,
        longitude   REAL,
        gps_altitude REAL,
        vendor_ies  TEXT,
        ht_caps     TEXT,
        vht_caps    TEXT,
        seen_count  INTEGER,
        adv_changed INTEGER
    );
    """
    _CREATE_IDX_ADDR = "CREATE INDEX IF NOT EXISTS idx_det_addr ON detections (address);"
    _CREATE_IDX_SID = "CREATE INDEX IF NOT EXISTS idx_det_sid ON detections (session_id);"

    def __init__(self, path: str):
        self._path = path
        self._conn: Optional[sqlite3.Connection] = None
        self._session_id: Optional[int] = None

    def open(self, cli_args: str = ""):
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute(self._CREATE_SESSIONS)
        self._conn.execute(self._CREATE_DETECTIONS)
        self._conn.execute(self._CREATE_IDX_ADDR)
        self._conn.execute(self._CREATE_IDX_SID)
        self._conn.commit()
        cur = self._conn.execute(
            "INSERT INTO sessions (started_at, cli_args) VALUES (?, ?);",
            (_timestamp(), cli_args),
        )
        self._session_id = cur.lastrowid
        self._conn.commit()

    def insert(self, record: Dict[str, Any]):
        if self._conn is None or self._session_id is None:
            return
        cols = list(_FIELDNAMES)
        placeholders = ", ".join("?" for _ in cols)
        col_names = ", ".join(cols)
        values = [record.get(c, None) for c in cols]
        self._conn.execute(
            f"INSERT INTO detections (session_id, {col_names}) VALUES (?, {placeholders});",
            [self._session_id] + values,
        )
        self._conn.commit()

    def close(self):
        if self._conn is None:
            return
        try:
            self._conn.execute(
                "UPDATE sessions SET ended_at = ? WHERE id = ?;",
                (_timestamp(), self._session_id),
            )
            self._conn.commit()
        finally:
            self._conn.close()
            self._conn = None
