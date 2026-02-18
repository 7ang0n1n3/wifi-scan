"""Tests for wifi_scan.config — configuration loading and CLI merging."""

import json
import os
import tempfile
import unittest


class TestLoadConfig(unittest.TestCase):
    def test_missing_file_returns_empty(self):
        from wifi_scan.config import load_config
        result = load_config("/nonexistent/path/config.toml")
        self.assertEqual(result, {})

    def test_load_json_config(self):
        from wifi_scan.config import load_config
        cfg = {"environment": "outdoor", "min_rssi": -75, "timeout": 60}
        with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            path = f.name
        try:
            result = load_config(path)
            self.assertEqual(result["environment"], "outdoor")
            self.assertEqual(result["min_rssi"], -75)
            self.assertEqual(result["timeout"], 60)
        finally:
            os.unlink(path)

    def test_invalid_json_returns_empty(self):
        from wifi_scan.config import load_config
        with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json")
            path = f.name
        try:
            result = load_config(path)
            self.assertEqual(result, {})
        finally:
            os.unlink(path)

    def test_env_var_takes_precedence(self):
        from wifi_scan.config import load_config
        cfg = {"environment": "free_space"}
        with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            path = f.name
        try:
            import unittest.mock
            with unittest.mock.patch.dict(os.environ, {"WIFI_SCAN_CONFIG": path}):
                result = load_config()
            self.assertEqual(result["environment"], "free_space")
        finally:
            os.unlink(path)


class TestMergeWithCli(unittest.TestCase):
    def _make_args(self, **kwargs):
        import argparse
        args = argparse.Namespace(
            environment="indoor",
            min_rssi=None,
            rssi_window=1,
            timeout=None,
            verbose=False,
            quiet=False,
            tui=False,
            gui=False,
            gui_port=5000,
            no_gps=False,
            no_hop=False,
            two_ghz=False,
            five_ghz=False,
            interface=None,
            frame_types="all",
            db=None,
            channel=None,
        )
        for k, v in kwargs.items():
            setattr(args, k, v)
        return args

    def test_config_fills_default(self):
        from wifi_scan.config import merge_with_cli
        # Leave environment as None (unset) so the config value fills it in
        args = self._make_args(environment=None)
        config = {"environment": "outdoor"}
        merge_with_cli(args, config)
        self.assertEqual(args.environment, "outdoor")

    def test_cli_wins_when_explicit(self):
        from wifi_scan.config import merge_with_cli
        args = self._make_args(environment="free_space")
        config = {"environment": "outdoor"}
        # "free_space" is not the argparse default ("indoor") — should NOT be overridden
        # Actually since argparse default isn't set in our mock, let's use rssi_window
        args2 = self._make_args(rssi_window=10)   # explicitly set
        merge_with_cli(args2, {"rssi_window": 3})
        # rssi_window=10 != default(None or 1) so config should not override
        # The default from bare ArgumentParser is None, 10 != None → kept
        # (Implementation: only override if current == default or None)
        self.assertEqual(args2.rssi_window, 10)

    def test_gps_inverted_to_no_gps(self):
        from wifi_scan.config import merge_with_cli
        args = self._make_args(no_gps=False)
        merge_with_cli(args, {"gps": False})
        self.assertTrue(args.no_gps)

    def test_gps_true_keeps_no_gps_false(self):
        from wifi_scan.config import merge_with_cli
        args = self._make_args(no_gps=False)
        merge_with_cli(args, {"gps": True})
        self.assertFalse(args.no_gps)

    def test_unknown_keys_ignored(self):
        from wifi_scan.config import merge_with_cli
        args = self._make_args()
        merge_with_cli(args, {"unknown_key_xyz": 123})
        self.assertFalse(hasattr(args, "unknown_key_xyz"))


if __name__ == "__main__":
    unittest.main()
