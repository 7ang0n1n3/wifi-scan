"""Tests for wifi_scan.crypto — distance estimation and fingerprint correlation."""

import unittest


class TestIsRandomized(unittest.TestCase):
    def test_globally_unique_mac(self):
        from wifi_scan.crypto import is_randomized
        # Globally administered: locally administered bit (0x02) is clear
        self.assertFalse(is_randomized("00:11:22:33:44:55"))  # 0x00 → bit1=0 → not rand
        self.assertFalse(is_randomized("04:11:22:33:44:55"))  # 0x04 → bit1=0 → not rand
        self.assertFalse(is_randomized("01:11:22:33:44:55"))  # 0x01 → bit1=0 → not rand

    def test_randomized_mac(self):
        from wifi_scan.crypto import is_randomized
        # 0xAA = 0b10101010 — bit 1 (0x02) is set
        self.assertTrue(is_randomized("AA:BB:CC:DD:EE:FF"))

    def test_locally_administered(self):
        from wifi_scan.crypto import is_randomized
        # 0x02 = 0b00000010 — bit 1 set
        self.assertTrue(is_randomized("02:00:00:00:00:00"))

    def test_empty_mac(self):
        from wifi_scan.crypto import is_randomized
        self.assertFalse(is_randomized(""))


class TestEstimateDistance(unittest.TestCase):
    def test_at_reference_rssi(self):
        from wifi_scan.crypto import estimate_distance
        # At ref_rssi distance should be ~1m
        d = estimate_distance(-37, ref_rssi=-37, environment="free_space")
        self.assertAlmostEqual(d, 1.0, places=2)

    def test_stronger_signal_closer(self):
        from wifi_scan.crypto import estimate_distance
        d1 = estimate_distance(-50, environment="indoor")
        d2 = estimate_distance(-70, environment="indoor")
        self.assertLess(d1, d2)

    def test_indoor_closer_than_freespace(self):
        from wifi_scan.crypto import estimate_distance
        # Higher path loss exponent (indoor n=3) → for the same measured RSSI,
        # the device is estimated to be CLOSER (signal decays faster indoors,
        # so a -60 dBm reading implies a shorter actual distance).
        d_indoor = estimate_distance(-60, environment="indoor")
        d_free = estimate_distance(-60, environment="free_space")
        self.assertLess(d_indoor, d_free)

    def test_returns_float(self):
        from wifi_scan.crypto import estimate_distance
        d = estimate_distance(-65)
        self.assertIsInstance(d, float)
        self.assertGreater(d, 0)


class TestFingerprintCorrelator(unittest.TestCase):
    def test_single_mac_single_fp(self):
        from wifi_scan.crypto import FingerprintCorrelator
        c = FingerprintCorrelator()
        c.update("AA:BB:CC:DD:EE:FF", "fp1")
        self.assertEqual(c.get_fingerprint("AA:BB:CC:DD:EE:FF"), "fp1")

    def test_two_macs_same_fp(self):
        from wifi_scan.crypto import FingerprintCorrelator
        c = FingerprintCorrelator()
        c.update("AA:BB:CC:DD:EE:01", "fp_shared")
        c.update("AA:BB:CC:DD:EE:02", "fp_shared")
        macs = c.correlated_macs("fp_shared")
        self.assertIn("AA:BB:CC:DD:EE:01", macs)
        self.assertIn("AA:BB:CC:DD:EE:02", macs)

    def test_groups_only_when_multiple_macs(self):
        from wifi_scan.crypto import FingerprintCorrelator
        c = FingerprintCorrelator()
        c.update("MAC1", "fp_unique")
        c.update("MAC2", "fp_shared")
        c.update("MAC3", "fp_shared")
        groups = c.groups()
        self.assertEqual(len(groups), 1)
        fps = [fp for fp, _ in groups]
        self.assertIn("fp_shared", fps)
        self.assertNotIn("fp_unique", fps)

    def test_mac_rotates_fingerprint(self):
        from wifi_scan.crypto import FingerprintCorrelator
        c = FingerprintCorrelator()
        c.update("MAC1", "fp_old")
        c.update("MAC1", "fp_new")
        self.assertEqual(c.get_fingerprint("MAC1"), "fp_new")
        # Old fingerprint group should have MAC1 removed
        old_macs = c.correlated_macs("fp_old")
        self.assertNotIn("MAC1", old_macs)

    def test_empty_correlator(self):
        from wifi_scan.crypto import FingerprintCorrelator
        c = FingerprintCorrelator()
        self.assertEqual(c.groups(), [])
        self.assertIsNone(c.get_fingerprint("nonexistent"))
        self.assertEqual(c.correlated_macs("fp"), set())


if __name__ == "__main__":
    unittest.main()
