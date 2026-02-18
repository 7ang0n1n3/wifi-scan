"""OUI and vendor IE lookup for wifi-scan."""

import json
import os
import re
from typing import Optional

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

_oui_cache: Optional[dict] = None
_vendor_ie_cache: Optional[dict] = None


def _load_oui() -> dict:
    global _oui_cache
    if _oui_cache is None:
        path = os.path.join(_DATA_DIR, "oui.json")
        try:
            with open(path) as f:
                _oui_cache = json.load(f)
        except Exception:
            _oui_cache = {}
    return _oui_cache


def _load_vendor_ies() -> dict:
    global _vendor_ie_cache
    if _vendor_ie_cache is None:
        path = os.path.join(_DATA_DIR, "vendor_ies.json")
        try:
            with open(path) as f:
                _vendor_ie_cache = json.load(f)
        except Exception:
            _vendor_ie_cache = {}
    return _vendor_ie_cache


def get_oui_vendor(mac: str) -> Optional[str]:
    """Look up vendor name from the OUI (first 6 hex chars) of a MAC address."""
    clean = re.sub(r"[:\-\.]", "", mac or "").upper()[:6]
    if not clean:
        return None
    return _load_oui().get(clean)


def get_vendor_ie_name(oui_hex: str) -> Optional[str]:
    """Look up a vendor IE OUI (3-byte hex string) in the known-OUI database."""
    key = re.sub(r"[:\-\.]", "", oui_hex or "").lower()[:6]
    return _load_vendor_ies().get(key)
