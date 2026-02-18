"""Configuration loading for wifi-scan."""

import json
import os
import sys
from typing import Any, Dict, Optional

_CONFIG_ENV_VAR = "WIFI_SCAN_CONFIG"
_CONFIG_PATHS = [
    os.path.expanduser("~/.config/wifi-scan/config.toml"),
    os.path.expanduser("~/.config/wifi-scan/config.json"),
]
_CONFIG_KEYS = {
    "environment", "min_rssi", "rssi_window", "alert_within", "gps",
    "timeout", "verbose", "quiet", "tui", "gui", "gui_port", "db",
    "channel", "no_hop", "two_ghz", "five_ghz", "interface", "frame_types",
}


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from file (TOML preferred, JSON fallback).

    Search order:
    1. Explicit ``config_path`` argument
    2. ``$WIFI_SCAN_CONFIG`` environment variable
    3. ``~/.config/wifi-scan/config.toml``
    4. ``~/.config/wifi-scan/config.json``
    """
    if config_path:
        paths = [config_path]
    else:
        env = os.environ.get(_CONFIG_ENV_VAR)
        paths = [env] if env else _CONFIG_PATHS

    for path in paths:
        if not os.path.exists(path):
            continue
        try:
            if path.endswith(".toml"):
                if sys.version_info >= (3, 11):
                    import tomllib
                    with open(path, "rb") as f:
                        return tomllib.load(f)
                else:
                    try:
                        import tomli
                        with open(path, "rb") as f:
                            return tomli.load(f)
                    except ImportError:
                        pass  # fall through to JSON
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def merge_with_cli(args, config: Dict[str, Any]):
    """Merge config file values into the argparse namespace.

    CLI arguments take precedence when they differ from their argparse defaults.
    Config values only fill in attributes that are still at the default value.
    The ``gps`` config key is inverted to the ``no_gps`` flag.
    """
    import argparse
    _defaults = vars(argparse.ArgumentParser().parse_args([]))

    for key, value in config.items():
        if key not in _CONFIG_KEYS:
            continue
        if key == "gps":
            if not getattr(args, "no_gps", False):
                args.no_gps = not value
            continue
        if not hasattr(args, key):
            continue
        current = getattr(args, key)
        default = _defaults.get(key)
        if current is None or current == default:
            setattr(args, key, value)
