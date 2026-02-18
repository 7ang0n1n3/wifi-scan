"""wifi-scan: 802.11 WiFi scanner with monitor-mode packet capture,
MAC randomization detection, and IE fingerprint correlation."""

from .scanner import WiFiScanner
from .crypto import FingerprintCorrelator, is_randomized, estimate_distance
from .detection import (
    extract_ies, get_ssid, get_channel, get_rssi, get_encryption,
    compute_ie_fingerprint, parse_rsn, parse_ht_caps, parse_vht_caps,
    parse_vendor_ies,
)
from .lookup import get_oui_vendor, get_vendor_ie_name
from .utils import _is_randomized_mac, _normalize_mac, _timestamp
from .gps import GpsdReader
from .output import SqliteRecorder

__version__ = "1.0.0"
__all__ = [
    "WiFiScanner",
    "FingerprintCorrelator",
    "is_randomized",
    "estimate_distance",
    "extract_ies",
    "get_ssid",
    "get_channel",
    "get_rssi",
    "get_encryption",
    "compute_ie_fingerprint",
    "parse_rsn",
    "parse_ht_caps",
    "parse_vht_caps",
    "parse_vendor_ies",
    "get_oui_vendor",
    "get_vendor_ie_name",
    "GpsdReader",
    "SqliteRecorder",
]
