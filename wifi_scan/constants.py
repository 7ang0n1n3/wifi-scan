"""Global constants for wifi-scan."""

from typing import Dict, List

# Path-loss exponents for distance estimation
_ENV_PATH_LOSS: Dict[str, float] = {
    "free_space": 2.0,
    "outdoor": 2.2,
    "indoor": 3.0,
}

# Reference RSSI at 1 m (dBm) — typical WiFi transmit power
_REF_RSSI_DEFAULT = -37

# Timing (seconds)
_TUI_REFRESH_INTERVAL = 0.3
_SCAN_POLL_INTERVAL = 0.5
_TIMED_SCAN_POLL_INTERVAL = 0.1
_GPS_STARTUP_DELAY = 0.5
_GPS_RECONNECT_DELAY = 5.0
_GPS_SOCKET_TIMEOUT = 5.0
_CHANNEL_HOP_INTERVAL = 0.25  # seconds per channel

# 2.4 GHz channels (1–13 worldwide; 14 Japan only)
_CHANNELS_2GHZ: List[int] = list(range(1, 14))

# 5 GHz channels (common US/EU subset)
_CHANNELS_5GHZ: List[int] = [
    36, 40, 44, 48,         # UNII-1
    52, 56, 60, 64,         # UNII-2A
    100, 104, 108, 112,     # UNII-2C
    116, 120, 124, 128,
    132, 136, 140, 144,
    149, 153, 157, 161, 165,  # UNII-3
]

_CHANNELS_ALL: List[int] = _CHANNELS_2GHZ + _CHANNELS_5GHZ

# 802.11 management frame subtypes
_FRAME_SUBTYPES: Dict[int, str] = {
    0x00: "Assoc-Req",
    0x01: "Assoc-Resp",
    0x02: "Reassoc-Req",
    0x03: "Reassoc-Resp",
    0x04: "Probe-Req",
    0x05: "Probe-Resp",
    0x08: "Beacon",
    0x0A: "Disassoc",
    0x0B: "Auth",
    0x0C: "Deauth",
    0x0D: "Action",
}

# 802.11 Information Element tag IDs → human-readable names
_IE_TAGS: Dict[int, str] = {
    0:   "SSID",
    1:   "Supported-Rates",
    3:   "DS-Param",
    5:   "TIM",
    7:   "Country",
    11:  "QBSS-Load",
    32:  "Power-Constraint",
    35:  "TPC-Report",
    45:  "HT-Capabilities",
    48:  "RSN",
    50:  "Extended-Rates",
    54:  "Mobility-Domain",
    61:  "HT-Operation",
    74:  "Overlapping-BSS",
    107: "Interworking",
    127: "Extended-Caps",
    191: "VHT-Capabilities",
    192: "VHT-Operation",
    221: "Vendor-Specific",
    255: "Extended-Tag",
}

# CSV column names
_FIELDNAMES = [
    "timestamp",
    "address",
    "ssid",
    "device_type",
    "rssi",
    "avg_rssi",
    "channel",
    "encryption",
    "is_randomized",
    "vendor",
    "ie_fingerprint",
    "probe_ssids",
    "capabilities",
    "latitude",
    "longitude",
    "gps_altitude",
    "vendor_ies",
    "ht_caps",
    "vht_caps",
    "seen_count",
    "adv_changed",
]

_BANNER = r"""
 __        _  ___  _   ___   ___   _   _  _
 \ \      (_)/ __|| | / __| / __| /_\  | \| |
  \ \  _  | |\__ \| | \__ \| (__ / _ \ | .` |
   \_\(_) |_||___/|_| |___/ \___/_/ \_\|_|\_|
"""
