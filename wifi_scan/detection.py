"""802.11 frame parsing, IE extraction, encryption detection, and fingerprinting.

This module is the wifi-scan analog of btrpa-scan's detection.py, which parsed
BLE advertisement data.  Here we parse 802.11 management frames captured by
scapy in monitor mode.
"""

import hashlib
import struct
from typing import Any, Dict, List, Optional, Tuple

try:
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt, RadioTap
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


# ---------------------------------------------------------------------------
# RadioTap / header helpers
# ---------------------------------------------------------------------------

def get_rssi(pkt) -> Optional[int]:
    """Extract RSSI (dBm) from the RadioTap header."""
    if not _HAS_SCAPY or not pkt.haslayer(RadioTap):
        return None
    rt = pkt[RadioTap]
    for field in ("dBm_AntSignal", "antenna_signal"):
        val = getattr(rt, field, None)
        if val is not None:
            try:
                v = int(val)
                if -120 <= v <= 0:
                    return v
            except (TypeError, ValueError):
                pass
    return None


def _freq_to_channel(freq: int) -> Optional[int]:
    """Convert frequency (MHz) to 802.11 channel number."""
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2412) // 5 + 1
    if 5180 <= freq <= 5825:
        return (freq - 5000) // 5
    return None


# ---------------------------------------------------------------------------
# Information Element extraction
# ---------------------------------------------------------------------------

def extract_ies(pkt) -> List[Tuple[int, bytes]]:
    """Walk the IE chain and return a list of (tag_id, raw_bytes) tuples."""
    ies: List[Tuple[int, bytes]] = []
    if not _HAS_SCAPY:
        return ies
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if hasattr(elt, "ID") and hasattr(elt, "info"):
            ies.append((int(elt.ID), bytes(elt.info or b"")))
        inner = elt.payload
        if inner is None or not isinstance(inner, Dot11Elt):
            break
        elt = inner
    return ies


def get_ssid(ies: List[Tuple[int, bytes]]) -> str:
    """Extract SSID from IE list (tag 0).  Returns '' for hidden/wildcard."""
    for tag_id, data in ies:
        if tag_id == 0:
            try:
                return data.decode("utf-8", errors="replace").strip("\x00")
            except Exception:
                return ""
    return ""


def get_channel(pkt, ies: List[Tuple[int, bytes]]) -> Optional[int]:
    """Determine the operating channel from DS Parameter Set IE or RadioTap."""
    for tag_id, data in ies:
        if tag_id == 3 and data:
            return int(data[0])
    if _HAS_SCAPY and pkt.haslayer(RadioTap):
        try:
            freq = pkt[RadioTap].ChannelFrequency
            if freq:
                return _freq_to_channel(int(freq))
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Encryption detection
# ---------------------------------------------------------------------------

def _cipher_name(suite: bytes) -> str:
    _MAP = {
        b"\x00\x0f\xac\x00": "None",
        b"\x00\x0f\xac\x01": "WEP-40",
        b"\x00\x0f\xac\x02": "TKIP",
        b"\x00\x0f\xac\x04": "CCMP-128",
        b"\x00\x0f\xac\x05": "WEP-104",
        b"\x00\x0f\xac\x08": "GCMP-128",
        b"\x00\x0f\xac\x09": "GCMP-256",
        b"\x00\x0f\xac\x0a": "CCMP-256",
    }
    return _MAP.get(bytes(suite[:4]), f"0x{suite.hex()}")


def _akm_name(suite: bytes) -> str:
    _MAP = {
        b"\x00\x0f\xac\x01": "802.1X",
        b"\x00\x0f\xac\x02": "PSK",
        b"\x00\x0f\xac\x03": "FT-802.1X",
        b"\x00\x0f\xac\x04": "FT-PSK",
        b"\x00\x0f\xac\x05": "802.1X-SHA256",
        b"\x00\x0f\xac\x06": "PSK-SHA256",
        b"\x00\x0f\xac\x08": "SAE",
        b"\x00\x0f\xac\x09": "FT-SAE",
        b"\x00\x0f\xac\x12": "OWE",
        b"\x00\x50\xf2\x01": "WPA-PSK",
        b"\x00\x50\xf2\x02": "WPA-802.1X",
    }
    return _MAP.get(bytes(suite[:4]), f"0x{suite.hex()}")


def parse_rsn(data: bytes) -> Dict[str, Any]:
    """Parse an RSN Information Element (tag 48) for encryption details."""
    result: Dict[str, Any] = {}
    if len(data) < 8:
        return result
    try:
        pairwise_count = struct.unpack_from("<H", data, 6)[0]
        offset = 8
        pairwise = []
        for _ in range(pairwise_count):
            if offset + 4 > len(data):
                break
            pairwise.append(_cipher_name(data[offset:offset + 4]))
            offset += 4

        akms: List[str] = []
        if offset + 2 <= len(data):
            akm_count = struct.unpack_from("<H", data, offset)[0]
            offset += 2
            for _ in range(akm_count):
                if offset + 4 > len(data):
                    break
                akms.append(_akm_name(data[offset:offset + 4]))
                offset += 4

        rsn_caps = 0
        if offset + 2 <= len(data):
            rsn_caps = struct.unpack_from("<H", data, offset)[0]

        if "SAE" in akms or "FT-SAE" in akms:
            enc = "WPA2/WPA3" if any(a in akms for a in ("PSK", "FT-PSK", "PSK-SHA256")) else "WPA3"
        elif "OWE" in akms:
            enc = "WPA3-OWE"
        else:
            enc = "WPA2"

        result = {
            "encryption": enc,
            "pairwise": pairwise,
            "akm": akms,
            "mfp_required": bool(rsn_caps & 0x0040),
            "mfp_capable": bool(rsn_caps & 0x0080),
        }
    except Exception:
        result = {"encryption": "WPA2"}
    return result


def get_encryption(pkt, ies: List[Tuple[int, bytes]]) -> str:
    """Determine encryption type from management frame IEs and capability bits."""
    if not _HAS_SCAPY:
        return "Unknown"

    has_privacy = False
    for layer_name in ("Dot11Beacon", "Dot11ProbeResp"):
        layer = pkt.getlayer(layer_name)
        if layer is not None:
            try:
                has_privacy = bool(layer.cap & 0x0010)
            except Exception:
                pass
            break

    has_rsn = False
    has_wpa = False
    rsn_info: Dict[str, Any] = {}

    for tag_id, data in ies:
        if tag_id == 48:
            has_rsn = True
            rsn_info = parse_rsn(data)
        elif tag_id == 221 and len(data) >= 4:
            if data[:4] == b"\x00\x50\xf2\x01":
                has_wpa = True

    if has_rsn:
        return rsn_info.get("encryption", "WPA2")
    if has_wpa:
        return "WPA"
    if has_privacy:
        return "WEP"
    return "Open"


# ---------------------------------------------------------------------------
# Vendor IE parsing
# ---------------------------------------------------------------------------

def parse_vendor_ies(ies: List[Tuple[int, bytes]]) -> List[Dict[str, str]]:
    """Parse vendor-specific IEs (tag 221) into a list of human-readable dicts."""
    from .lookup import get_vendor_ie_name

    _MS_TYPES = {0x01: "WPA", 0x02: "WMM", 0x04: "WPS", 0x08: "TDLS"}
    _WFA_TYPES = {0x09: "P2P", 0x0A: "WFD", 0x1C: "NAN"}

    results = []
    for tag_id, data in ies:
        if tag_id != 221 or len(data) < 3:
            continue
        oui = data[:3].hex()
        vtype = data[3] if len(data) > 3 else None
        entry: Dict[str, str] = {"oui": oui}

        if oui == "0050f2":
            entry["name"] = _MS_TYPES.get(vtype, f"MS-{vtype:#04x}" if vtype is not None else "Microsoft")
        elif oui == "506f9a":
            entry["name"] = _WFA_TYPES.get(vtype, f"WFA-{vtype:#04x}" if vtype is not None else "Wi-Fi Alliance")
        else:
            name = get_vendor_ie_name(oui)
            entry["name"] = name if name else f"OUI-{oui}"

        results.append(entry)
    return results


# ---------------------------------------------------------------------------
# HT / VHT capability summaries
# ---------------------------------------------------------------------------

def parse_ht_caps(data: bytes) -> Optional[str]:
    """Summarize HT Capabilities IE (tag 45)."""
    if len(data) < 2:
        return None
    caps = struct.unpack_from("<H", data)[0]
    parts = []
    if caps & 0x0001:
        parts.append("LDPC")
    if caps & 0x0002:
        parts.append("40MHz")
    if caps & 0x0020:
        parts.append("SGI-20")
    if caps & 0x0040:
        parts.append("SGI-40")
    if caps & 0x0100:
        parts.append("TX-STBC")
    return ",".join(parts) or "HT"


def parse_vht_caps(data: bytes) -> Optional[str]:
    """Summarize VHT Capabilities IE (tag 191)."""
    if len(data) < 4:
        return None
    caps = struct.unpack_from("<I", data)[0]
    parts = []
    width = (caps >> 2) & 0x03
    if width == 1:
        parts.append("160MHz")
    elif width == 2:
        parts.append("80+80MHz")
    if caps & 0x0010:
        parts.append("SU-BF")
    if caps & 0x0800:
        parts.append("MU-BF")
    return ",".join(parts) or "VHT"


# ---------------------------------------------------------------------------
# IE fingerprinting — WiFi analog of BLE advertisement fingerprinting
# ---------------------------------------------------------------------------

def compute_ie_fingerprint(ies: List[Tuple[int, bytes]]) -> str:
    """Compute a stable fingerprint from the IE sequence in a probe request.

    Modern devices randomize their WiFi MAC addresses to prevent tracking.
    However, the precise sequence and values of Information Elements (IEs) in
    probe requests are determined by the device's driver and OS and remain
    stable across MAC rotations.  This fingerprint allows correlating detections
    that come from the same physical device even after it changes its MAC — the
    WiFi equivalent of Bluetooth IRK resolution for RPAs.

    We include: supported/extended rates, HT/VHT capability bits, extended
    capabilities, and vendor-specific IE OUIs.  We exclude SSIDs (vary per
    probe), DS Parameter (changes with channel), and TIM (timing-based).
    """
    parts = []
    for tag_id, data in ies:
        if tag_id in (0, 3, 5):    # SSID, DS-Param, TIM — unstable
            continue
        if tag_id in (1, 50):       # Supported / Extended Rates — verbatim
            parts.append(f"{tag_id}:{data.hex()}")
        elif tag_id == 45:          # HT Capabilities — first 2 bytes
            parts.append(f"45:{data[:2].hex()}" if len(data) >= 2 else "45:")
        elif tag_id == 191:         # VHT Capabilities — first 4 bytes
            parts.append(f"191:{data[:4].hex()}" if len(data) >= 4 else "191:")
        elif tag_id == 127:         # Extended Capabilities — verbatim
            parts.append(f"127:{data.hex()}")
        elif tag_id == 221:         # Vendor Specific — OUI only
            parts.append(f"221:{data[:3].hex()}" if len(data) >= 3 else "221:")
        elif tag_id == 255 and data:  # Extended Tag — tag number only
            parts.append(f"255:{data[0]:02x}")
        else:
            parts.append(str(tag_id))   # Presence only

    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def compute_frame_fingerprint(pkt) -> str:
    """Fingerprint a management frame payload for change detection."""
    try:
        return hashlib.sha256(bytes(pkt.payload)).hexdigest()[:8]
    except Exception:
        return ""
