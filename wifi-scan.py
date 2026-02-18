"""Root-level shim entry point for wifi-scan.

Allows running directly as:  python wifi-scan.py [args]
while keeping all symbols importable from wifi_scan for test compatibility.
"""

# Re-export the public API so test code that imports `wifi-scan` directly works.
from wifi_scan.crypto import (
    FingerprintCorrelator,
    estimate_distance,
    is_randomized,
)
from wifi_scan.detection import (
    compute_ie_fingerprint,
    extract_ies,
    get_channel,
    get_encryption,
    get_rssi,
    get_ssid,
    parse_ht_caps,
    parse_rsn,
    parse_vendor_ies,
    parse_vht_caps,
)
from wifi_scan.gps import GpsdReader
from wifi_scan.lookup import get_oui_vendor, get_vendor_ie_name
from wifi_scan.output import SqliteRecorder
from wifi_scan.scanner import WiFiScanner
from wifi_scan.tui import make_sparkline
from wifi_scan.utils import _is_randomized_mac, _normalize_mac, _timestamp

if __name__ == "__main__":
    from wifi_scan.cli import main
    main()
