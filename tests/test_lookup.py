"""Tests for wifi_scan.lookup — OUI and vendor IE lookups."""

import json
import os
import tempfile
import unittest
import unittest.mock


class TestGetOuiVendor(unittest.TestCase):
    def setUp(self):
        # Patch the OUI cache with known data
        patcher = unittest.mock.patch(
            "wifi_scan.lookup._oui_cache",
            {"AABBCC": "TestCorp", "001A2B": "Apple Inc"},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_colon_format(self):
        from wifi_scan.lookup import get_oui_vendor
        self.assertEqual(get_oui_vendor("AA:BB:CC:DD:EE:FF"), "TestCorp")

    def test_dash_format(self):
        from wifi_scan.lookup import get_oui_vendor
        self.assertEqual(get_oui_vendor("AA-BB-CC-DD-EE-FF"), "TestCorp")

    def test_plain_format(self):
        from wifi_scan.lookup import get_oui_vendor
        self.assertEqual(get_oui_vendor("AABBCCDDEEFF"), "TestCorp")

    def test_lowercase(self):
        from wifi_scan.lookup import get_oui_vendor
        self.assertEqual(get_oui_vendor("aa:bb:cc:11:22:33"), "TestCorp")

    def test_apple(self):
        from wifi_scan.lookup import get_oui_vendor
        self.assertEqual(get_oui_vendor("00:1a:2b:00:00:00"), "Apple Inc")

    def test_unknown_mac(self):
        from wifi_scan.lookup import get_oui_vendor
        self.assertIsNone(get_oui_vendor("FF:FF:FF:FF:FF:FF"))

    def test_empty_mac(self):
        from wifi_scan.lookup import get_oui_vendor
        self.assertIsNone(get_oui_vendor(""))


class TestGetVendorIEName(unittest.TestCase):
    def setUp(self):
        patcher = unittest.mock.patch(
            "wifi_scan.lookup._vendor_ie_cache",
            {"0050f2": "Microsoft", "506f9a": "Wi-Fi Alliance"},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_microsoft(self):
        from wifi_scan.lookup import get_vendor_ie_name
        self.assertEqual(get_vendor_ie_name("0050f2"), "Microsoft")

    def test_wfa(self):
        from wifi_scan.lookup import get_vendor_ie_name
        self.assertEqual(get_vendor_ie_name("506f9a"), "Wi-Fi Alliance")

    def test_colon_separated(self):
        from wifi_scan.lookup import get_vendor_ie_name
        self.assertEqual(get_vendor_ie_name("00:50:f2"), "Microsoft")

    def test_unknown_oui(self):
        from wifi_scan.lookup import get_vendor_ie_name
        self.assertIsNone(get_vendor_ie_name("abcdef"))

    def test_empty(self):
        from wifi_scan.lookup import get_vendor_ie_name
        self.assertIsNone(get_vendor_ie_name(""))


class TestOUIDataFile(unittest.TestCase):
    """Verify the bundled OUI data file exists and has reasonable content."""

    def test_oui_file_exists(self):
        data_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "wifi_scan", "data",
        )
        self.assertTrue(os.path.exists(os.path.join(data_dir, "oui.json")))

    def test_oui_file_parseable(self):
        data_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "wifi_scan", "data",
        )
        path = os.path.join(data_dir, "oui.json")
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            self.assertIsInstance(data, dict)
            self.assertGreater(len(data), 0)

    def test_vendor_ie_file_exists(self):
        data_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "wifi_scan", "data",
        )
        self.assertTrue(os.path.exists(os.path.join(data_dir, "vendor_ies.json")))


if __name__ == "__main__":
    unittest.main()
