"""Tests for wifi_scan.output — record building and SQLite recorder."""

import os
import tempfile
import unittest
import unittest.mock
from collections import deque


def _make_scanner(**kwargs):
    """Return a minimal mock scanner suitable for build_record."""
    scanner = unittest.mock.MagicMock()
    scanner._gps = None
    scanner.ref_rssi = -37
    scanner.environment = "indoor"
    scanner.rssi_window = 1
    scanner.rssi_history = {}
    scanner.quiet = True
    scanner.tui = False
    scanner.gui = False
    scanner._gui_server = None
    scanner._log_writer = None
    scanner._log_fh = None
    scanner._db_recorder = None
    scanner._accumulate_records = False
    scanner.records = []
    scanner.tui_devices = {}
    scanner.device_best_gps = {}
    scanner.alert_within = None
    scanner.log_file = None
    scanner.db_path = None
    for k, v in kwargs.items():
        setattr(scanner, k, v)
    return scanner


class TestBuildRecord(unittest.TestCase):
    def test_basic_ap_record(self):
        from wifi_scan.output import build_record
        scanner = _make_scanner()
        rec = build_record(
            scanner, "AA:BB:CC:DD:EE:FF", "MyNetwork", "AP",
            -55, None, 6, "WPA2", False,
            "Apple Inc", None, None, None,
            None, "40MHz", None, 1, False,
        )
        self.assertEqual(rec["address"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(rec["ssid"], "MyNetwork")
        self.assertEqual(rec["device_type"], "AP")
        self.assertEqual(rec["rssi"], -55)
        self.assertEqual(rec["channel"], 6)
        self.assertEqual(rec["encryption"], "WPA2")
        self.assertEqual(rec["vendor"], "Apple Inc")
        self.assertEqual(rec["ht_caps"], "40MHz")

    def test_station_record_with_probe(self):
        from wifi_scan.output import build_record
        scanner = _make_scanner()
        rec = build_record(
            scanner, "DE:AD:BE:EF:00:01", "", "Station",
            -70, -68, None, "N/A", True,
            None, "a1b2c3d4e5f60708", ["HomeWifi", "CoffeeShop"],
            None, None, None, None, 3, None,
        )
        self.assertEqual(rec["device_type"], "Station")
        self.assertEqual(rec["is_randomized"], 1)
        self.assertEqual(rec["ie_fingerprint"], "a1b2c3d4e5f60708")
        self.assertIn("HomeWifi", rec["probe_ssids"])
        self.assertIn("CoffeeShop", rec["probe_ssids"])
        self.assertEqual(rec["avg_rssi"], -68)

    def test_distance_estimated(self):
        from wifi_scan.output import build_record
        scanner = _make_scanner(environment="indoor", ref_rssi=-37)
        rec = build_record(
            scanner, "00:11:22:33:44:55", "Net", "AP",
            -37, None, 1, "Open", False,
            None, None, None, None, None, None, None, 1, None,
        )
        # At ref_rssi the distance should be ~1 m
        self.assertIsNotNone(rec["est_distance"])
        self.assertAlmostEqual(rec["est_distance"], 1.0, places=1)

    def test_gps_stamped(self):
        from wifi_scan.output import build_record
        scanner = _make_scanner()
        gps_mock = unittest.mock.MagicMock()
        gps_mock.fix = {"lat": 37.12345, "lon": -122.54321, "alt": 50.0}
        scanner._gps = gps_mock
        rec = build_record(
            scanner, "00:11:22:33:44:55", "Net", "AP",
            -60, None, 6, "WPA2", False,
            None, None, None, None, None, None, None, 1, None,
        )
        self.assertAlmostEqual(rec["latitude"], 37.12345)
        self.assertAlmostEqual(rec["longitude"], -122.54321)
        self.assertAlmostEqual(rec["gps_altitude"], 50.0)

    def test_no_gps_is_none(self):
        from wifi_scan.output import build_record
        scanner = _make_scanner()
        scanner._gps = None
        rec = build_record(
            scanner, "00:11:22:33:44:55", "Net", "AP",
            -60, None, 6, "WPA2", False,
            None, None, None, None, None, None, None, 1, None,
        )
        self.assertIsNone(rec["latitude"])
        self.assertIsNone(rec["longitude"])


class TestSqliteRecorder(unittest.TestCase):
    def _make_record(self):
        return {
            "timestamp": "2024-02-18T14:23:45+0000",
            "address": "AA:BB:CC:DD:EE:FF",
            "ssid": "TestNet",
            "device_type": "AP",
            "rssi": -55,
            "avg_rssi": None,
            "channel": 6,
            "encryption": "WPA2",
            "is_randomized": 0,
            "vendor": "TestCorp",
            "ie_fingerprint": "",
            "probe_ssids": "",
            "capabilities": "",
            "latitude": None,
            "longitude": None,
            "gps_altitude": None,
            "vendor_ies": "",
            "ht_caps": "40MHz",
            "vht_caps": "",
            "seen_count": 1,
            "adv_changed": 0,
        }

    def test_open_creates_tables(self):
        from wifi_scan.output import SqliteRecorder
        import sqlite3
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name
        try:
            rec = SqliteRecorder(path)
            rec.open(cli_args="wifi-scan --all")
            rec.close()
            conn = sqlite3.connect(path)
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            self.assertIn("sessions", tables)
            self.assertIn("detections", tables)
            conn.close()
        finally:
            os.unlink(path)

    def test_insert_and_retrieve(self):
        from wifi_scan.output import SqliteRecorder
        import sqlite3
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name
        try:
            rec = SqliteRecorder(path)
            rec.open()
            rec.insert(self._make_record())
            rec.close()
            conn = sqlite3.connect(path)
            rows = conn.execute("SELECT address, ssid, channel FROM detections").fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], "AA:BB:CC:DD:EE:FF")
            self.assertEqual(rows[0][1], "TestNet")
            self.assertEqual(rows[0][2], 6)
            conn.close()
        finally:
            os.unlink(path)

    def test_session_recorded(self):
        from wifi_scan.output import SqliteRecorder
        import sqlite3
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name
        try:
            rec = SqliteRecorder(path)
            rec.open(cli_args="wifi-scan -i wlan0 --all")
            rec.close()
            conn = sqlite3.connect(path)
            row = conn.execute(
                "SELECT cli_args, ended_at FROM sessions").fetchone()
            self.assertEqual(row[0], "wifi-scan -i wlan0 --all")
            self.assertIsNotNone(row[1])   # ended_at should be set on close
            conn.close()
        finally:
            os.unlink(path)

    def test_proximity_alert_triggered(self):
        from wifi_scan.output import record_device
        scanner = _make_scanner(alert_within=5.0, quiet=False)
        scanner.tui = False
        scanner.gui = False
        rec = {
            "address": "AA:BB:CC:DD:EE:FF",
            "ssid": "Net",
            "device_type": "AP",
            "rssi": -30,
            "est_distance": 2.0,   # within 5 m
            "is_randomized": 0,
            "probe_ssids": "",
            "timestamp": "2024-02-18T14:23:45+0000",
            "latitude": None,
            "longitude": None,
        }
        # Should not raise; alert is just a print
        import io, sys
        captured = io.StringIO()
        with unittest.mock.patch("sys.stdout", captured):
            record_device(scanner, rec, "TEST")
        output = captured.getvalue()
        self.assertIn("PROXIMITY ALERT", output)

    def test_no_alert_when_outside_range(self):
        from wifi_scan.output import record_device
        scanner = _make_scanner(alert_within=5.0, quiet=False)
        scanner.tui = False
        scanner.gui = False
        rec = {
            "address": "AA:BB:CC:DD:EE:FF",
            "ssid": "Net",
            "device_type": "AP",
            "rssi": -90,
            "est_distance": 20.0,  # outside 5 m
            "is_randomized": 0,
            "probe_ssids": "",
            "timestamp": "2024-02-18T14:23:45+0000",
            "latitude": None,
            "longitude": None,
        }
        import io
        captured = io.StringIO()
        with unittest.mock.patch("sys.stdout", captured):
            record_device(scanner, rec, "TEST")
        self.assertNotIn("PROXIMITY ALERT", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
