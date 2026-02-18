"""Tests for wifi_scan.detection — frame parsing and fingerprinting."""

import struct
import unittest


class TestFreqToChannel(unittest.TestCase):
    def test_24ghz_channel1(self):
        from wifi_scan.detection import _freq_to_channel
        self.assertEqual(_freq_to_channel(2412), 1)

    def test_24ghz_channel6(self):
        from wifi_scan.detection import _freq_to_channel
        self.assertEqual(_freq_to_channel(2437), 6)

    def test_24ghz_channel14(self):
        from wifi_scan.detection import _freq_to_channel
        self.assertEqual(_freq_to_channel(2484), 14)

    def test_5ghz_channel36(self):
        from wifi_scan.detection import _freq_to_channel
        self.assertEqual(_freq_to_channel(5180), 36)

    def test_5ghz_channel149(self):
        from wifi_scan.detection import _freq_to_channel
        self.assertEqual(_freq_to_channel(5745), 149)

    def test_unknown_freq(self):
        from wifi_scan.detection import _freq_to_channel
        self.assertIsNone(_freq_to_channel(1000))


class TestGetSSID(unittest.TestCase):
    def test_normal_ssid(self):
        from wifi_scan.detection import get_ssid
        ies = [(0, b"MyNetwork"), (1, b"\x82\x84")]
        self.assertEqual(get_ssid(ies), "MyNetwork")

    def test_hidden_ssid(self):
        from wifi_scan.detection import get_ssid
        ies = [(0, b""), (1, b"\x82\x84")]
        self.assertEqual(get_ssid(ies), "")

    def test_wildcard_probe(self):
        from wifi_scan.detection import get_ssid
        # Probe request with empty SSID = wildcard
        ies = [(0, b"\x00\x00"), (1, b"\x82\x84")]
        result = get_ssid(ies)
        self.assertIsInstance(result, str)

    def test_no_ssid_ie(self):
        from wifi_scan.detection import get_ssid
        ies = [(1, b"\x82\x84"), (3, b"\x06")]
        self.assertEqual(get_ssid(ies), "")


class TestParseRSN(unittest.TestCase):
    def _build_rsn_ie(self, akm_type: int) -> bytes:
        """Build a minimal RSN IE with a single AKM suite."""
        # version (2) + group_cipher (4) + pairwise_count (2) + pairwise (4)
        # + akm_count (2) + akm (4) + rsn_caps (2)
        data = struct.pack("<H", 1)                         # version
        data += b"\x00\x0f\xac\x04"                        # group: CCMP-128
        data += struct.pack("<H", 1)                        # pairwise count
        data += b"\x00\x0f\xac\x04"                        # pairwise: CCMP-128
        data += struct.pack("<H", 1)                        # akm count
        data += b"\x00\x0f\xac" + bytes([akm_type])        # akm suite
        data += struct.pack("<H", 0)                        # RSN caps
        return data

    def test_wpa2_psk(self):
        from wifi_scan.detection import parse_rsn
        ie = self._build_rsn_ie(0x02)  # PSK
        result = parse_rsn(ie)
        self.assertEqual(result["encryption"], "WPA2")
        self.assertIn("PSK", result["akm"])

    def test_wpa3_sae(self):
        from wifi_scan.detection import parse_rsn
        ie = self._build_rsn_ie(0x08)  # SAE
        result = parse_rsn(ie)
        self.assertEqual(result["encryption"], "WPA3")
        self.assertIn("SAE", result["akm"])

    def test_owe(self):
        from wifi_scan.detection import parse_rsn
        ie = self._build_rsn_ie(0x12)  # OWE
        result = parse_rsn(ie)
        self.assertEqual(result["encryption"], "WPA3-OWE")

    def test_too_short(self):
        from wifi_scan.detection import parse_rsn
        self.assertEqual(parse_rsn(b"\x01\x00"), {})


class TestParseHTCaps(unittest.TestCase):
    def test_40mhz_sgi(self):
        from wifi_scan.detection import parse_ht_caps
        # caps bits: 40MHz (0x0002) | SGI-20 (0x0020) | SGI-40 (0x0040)
        caps = 0x0002 | 0x0020 | 0x0040
        data = struct.pack("<H", caps) + b"\x00" * 24
        result = parse_ht_caps(data)
        self.assertIn("40MHz", result)
        self.assertIn("SGI-20", result)
        self.assertIn("SGI-40", result)

    def test_ldpc(self):
        from wifi_scan.detection import parse_ht_caps
        data = struct.pack("<H", 0x0001) + b"\x00" * 24
        result = parse_ht_caps(data)
        self.assertIn("LDPC", result)

    def test_too_short(self):
        from wifi_scan.detection import parse_ht_caps
        self.assertIsNone(parse_ht_caps(b"\x01"))


class TestParseVHTCaps(unittest.TestCase):
    def test_160mhz(self):
        from wifi_scan.detection import parse_vht_caps
        # bits 2-3: supported channel width = 1 → 160MHz
        caps = 0x00000004  # width bits = 01
        data = struct.pack("<I", caps) + b"\x00" * 8
        result = parse_vht_caps(data)
        self.assertIn("160MHz", result)

    def test_too_short(self):
        from wifi_scan.detection import parse_vht_caps
        self.assertIsNone(parse_vht_caps(b"\x01\x02\x03"))


class TestIEFingerprint(unittest.TestCase):
    def test_stable_fingerprint(self):
        """Same IE sequence should produce the same fingerprint."""
        from wifi_scan.detection import compute_ie_fingerprint
        ies = [
            (1, b"\x82\x84\x8b\x96"),   # Supported Rates
            (50, b"\x24\x30\x48\x6c"),   # Extended Rates
            (45, b"\xef\x01\x00\x00"),   # HT Caps
        ]
        fp1 = compute_ie_fingerprint(ies)
        fp2 = compute_ie_fingerprint(ies)
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 16)

    def test_different_ssid_same_fingerprint(self):
        """SSID (tag 0) must not affect the fingerprint."""
        from wifi_scan.detection import compute_ie_fingerprint
        ies_a = [(0, b"NetworkA"), (1, b"\x82\x84"), (50, b"\x24\x30")]
        ies_b = [(0, b"NetworkB"), (1, b"\x82\x84"), (50, b"\x24\x30")]
        self.assertEqual(
            compute_ie_fingerprint(ies_a),
            compute_ie_fingerprint(ies_b),
        )

    def test_different_rates_different_fingerprint(self):
        from wifi_scan.detection import compute_ie_fingerprint
        ies_a = [(1, b"\x82\x84")]
        ies_b = [(1, b"\x82\x84\x8b\x96")]
        self.assertNotEqual(
            compute_ie_fingerprint(ies_a),
            compute_ie_fingerprint(ies_b),
        )

    def test_empty_ies(self):
        from wifi_scan.detection import compute_ie_fingerprint
        fp = compute_ie_fingerprint([])
        self.assertEqual(len(fp), 16)

    def test_vendor_oui_only(self):
        """Vendor IE should only contribute its OUI (3 bytes), not full data."""
        from wifi_scan.detection import compute_ie_fingerprint
        ies_a = [(221, b"\x00\x50\xf2" + b"\x01" + b"\xff" * 20)]
        ies_b = [(221, b"\x00\x50\xf2" + b"\x01" + b"\xaa" * 5)]
        # Same OUI → same fingerprint
        self.assertEqual(
            compute_ie_fingerprint(ies_a),
            compute_ie_fingerprint(ies_b),
        )


class TestParseVendorIEs(unittest.TestCase):
    def test_microsoft_wpa(self):
        from wifi_scan.detection import parse_vendor_ies
        ies = [(221, b"\x00\x50\xf2\x01" + b"\x00" * 20)]
        result = parse_vendor_ies(ies)
        self.assertEqual(len(result), 1)
        self.assertIn("WPA", result[0]["name"])

    def test_wfa_p2p(self):
        from wifi_scan.detection import parse_vendor_ies
        ies = [(221, b"\x50\x6f\x9a\x09" + b"\x00" * 10)]
        result = parse_vendor_ies(ies)
        self.assertEqual(len(result), 1)
        self.assertIn("P2P", result[0]["name"])

    def test_unknown_oui(self):
        from wifi_scan.detection import parse_vendor_ies
        ies = [(221, b"\xab\xcd\xef\x00")]
        result = parse_vendor_ies(ies)
        self.assertEqual(len(result), 1)
        self.assertIn("abcdef", result[0]["name"].lower())

    def test_too_short_skipped(self):
        from wifi_scan.detection import parse_vendor_ies
        ies = [(221, b"\x00\x50")]   # < 3 bytes
        result = parse_vendor_ies(ies)
        self.assertEqual(result, [])

    def test_non_vendor_ie_skipped(self):
        from wifi_scan.detection import parse_vendor_ies
        ies = [(0, b"SSID"), (1, b"\x82\x84")]
        result = parse_vendor_ies(ies)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
