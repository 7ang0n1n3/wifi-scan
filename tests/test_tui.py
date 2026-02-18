"""Tests for wifi_scan.tui — sparkline and TUI helpers."""

import unittest
from collections import deque


class TestMakeSparkline(unittest.TestCase):
    def test_length(self):
        from wifi_scan.tui import make_sparkline
        samples = deque([-80, -70, -60, -50, -40])
        result = make_sparkline(samples, width=8)
        self.assertEqual(len(result), 8)

    def test_padded_when_fewer_samples(self):
        from wifi_scan.tui import make_sparkline
        samples = deque([-60])
        result = make_sparkline(samples, width=8)
        self.assertEqual(len(result), 8)
        # Leading spaces for missing samples
        self.assertTrue(result.startswith(" "))

    def test_strong_signal_high_block(self):
        from wifi_scan.tui import make_sparkline
        BLOCKS = " ▁▂▃▄▅▆▇█"
        samples = deque([-30])  # max RSSI → highest block
        result = make_sparkline(samples, width=1)
        self.assertEqual(result, BLOCKS[-1])

    def test_weak_signal_low_block(self):
        from wifi_scan.tui import make_sparkline
        samples = deque([-100])  # min RSSI → lowest block (space)
        result = make_sparkline(samples, width=1)
        self.assertEqual(result, " ")

    def test_empty_samples(self):
        from wifi_scan.tui import make_sparkline
        result = make_sparkline(deque(), width=4)
        self.assertEqual(result, "    ")

    def test_clamps_above_max(self):
        from wifi_scan.tui import make_sparkline
        BLOCKS = " ▁▂▃▄▅▆▇█"
        samples = deque([0])   # above -30 dBm max → clamped to full block
        result = make_sparkline(samples, width=1)
        self.assertEqual(result, BLOCKS[-1])

    def test_clamps_below_min(self):
        from wifi_scan.tui import make_sparkline
        samples = deque([-200])  # below -100 dBm → clamped to space
        result = make_sparkline(samples, width=1)
        self.assertEqual(result, " ")

    def test_trend_ascending(self):
        from wifi_scan.tui import make_sparkline
        samples = deque([-90, -70, -50, -30])
        result = make_sparkline(samples, width=4)
        # Each char should be >= previous (ascending signal)
        BLOCKS = " ▁▂▃▄▅▆▇█"
        for i in range(len(result) - 1):
            self.assertLessEqual(BLOCKS.index(result[i]), BLOCKS.index(result[i + 1]))


class TestUtils(unittest.TestCase):
    def test_normalize_mac_colon(self):
        from wifi_scan.utils import _normalize_mac
        self.assertEqual(_normalize_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")

    def test_normalize_mac_dash(self):
        from wifi_scan.utils import _normalize_mac
        self.assertEqual(_normalize_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")

    def test_normalize_mac_plain(self):
        from wifi_scan.utils import _normalize_mac
        self.assertEqual(_normalize_mac("aabbccddeeff"), "AA:BB:CC:DD:EE:FF")

    def test_is_randomized_true(self):
        from wifi_scan.utils import _is_randomized_mac
        self.assertTrue(_is_randomized_mac("02:00:00:00:00:00"))
        self.assertTrue(_is_randomized_mac("AA:BB:CC:DD:EE:FF"))  # 0xAA has bit1 set

    def test_is_randomized_false(self):
        from wifi_scan.utils import _is_randomized_mac
        self.assertFalse(_is_randomized_mac("00:11:22:33:44:55"))
        self.assertFalse(_is_randomized_mac("04:00:00:00:00:00"))  # 0x04 bit1=0

    def test_mask_mac(self):
        from wifi_scan.utils import _mask_mac
        result = _mask_mac("AA:BB:CC:DD:EE:FF")
        self.assertEqual(result, "AA:BB:CC:??:??:??")

    def test_timestamp_format(self):
        from wifi_scan.utils import _timestamp
        ts = _timestamp()
        self.assertRegex(ts, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4}")


if __name__ == "__main__":
    unittest.main()
