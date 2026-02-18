"""Utility helpers for wifi-scan."""

import re
from datetime import datetime, timezone


def _timestamp() -> str:
    """Return ISO 8601 timestamp with timezone offset."""
    now = datetime.now(timezone.utc).astimezone()
    return now.strftime("%Y-%m-%dT%H:%M:%S%z")


def _is_randomized_mac(mac: str) -> bool:
    """Return True if the MAC address is locally administered (randomized).

    Modern operating systems (Android 10+, iOS 14+, Windows 10 21H1+) set
    the locally administered bit (bit 1 of the first octet) when randomizing
    WiFi MAC addresses to prevent tracking.  This is the WiFi analog of a
    Bluetooth Resolvable Private Address (RPA).
    """
    if not mac:
        return False
    parts = mac.replace("-", ":").split(":")
    try:
        first = int(parts[0], 16)
        return bool(first & 0x02)
    except (ValueError, IndexError):
        return False


def _normalize_mac(mac: str) -> str:
    """Normalize MAC to upper-case colon-separated format."""
    clean = re.sub(r"[:\-\.]", "", mac or "").upper()
    if len(clean) == 12:
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return (mac or "").upper()


def _mac_oui(mac: str) -> str:
    """Return the OUI portion (first 6 hex chars, no separators, upper-case)."""
    clean = re.sub(r"[:\-\.]", "", mac or "").upper()
    return clean[:6] if len(clean) >= 6 else clean


def _mask_mac(mac: str) -> str:
    """Partially mask a MAC for display: AA:BB:CC:??:??:??"""
    parts = (mac or "").upper().split(":")
    if len(parts) == 6:
        return ":".join(parts[:3] + ["??", "??", "??"])
    return mac
