"""MAC randomization detection and IE fingerprint correlation for wifi-scan.

In Bluetooth, devices using Resolvable Private Addresses (RPAs) can be tracked
by resolving the address cryptographically with an Identity Resolving Key (IRK).
btrpa-scan implements that flow in crypto.py.

WiFi's equivalent mechanism is MAC address randomization: modern devices set
the locally administered (L/A) bit in their WiFi MAC address to signal that
the address is ephemeral and will rotate periodically.

Rather than cryptographic resolution, wifi-scan uses Information Element (IE)
fingerprinting: the precise sequence and values of IEs in probe requests is
remarkably stable per device model / OS combination, even as MAC addresses
rotate.  The FingerprintCorrelator groups detections that share an IE
fingerprint — likely representing the same physical device under different
randomized MACs.
"""

from typing import Dict, List, Optional, Set, Tuple

from .utils import _is_randomized_mac


def is_randomized(mac: str) -> bool:
    """Return True if the MAC address uses a locally administered (randomized) value."""
    return _is_randomized_mac(mac)


def estimate_distance(rssi: int, ref_rssi: int = -37,
                      environment: str = "indoor") -> Optional[float]:
    """Estimate distance in metres using the log-distance path-loss model.

    Parameters
    ----------
    rssi:
        Measured signal strength in dBm (negative integer).
    ref_rssi:
        Reference RSSI at 1 m.  Default ``-37`` dBm is typical for a WiFi
        device with ~15–20 dBm TX power at one metre.
    environment:
        Path-loss exponent preset — ``'free_space'`` (n=2.0), ``'outdoor'``
        (n=2.2), or ``'indoor'`` (n=3.0).
    """
    from .constants import _ENV_PATH_LOSS
    n = _ENV_PATH_LOSS.get(environment, 3.0)
    try:
        d = 10 ** ((ref_rssi - rssi) / (10.0 * n))
        return round(d, 2)
    except (ZeroDivisionError, OverflowError, ValueError):
        return None


class FingerprintCorrelator:
    """Correlate devices across MAC address rotations using IE fingerprints.

    This is the WiFi analog of IRK resolution in btrpa-scan: instead of
    cryptographic RPA resolution, we group detections by their stable IE
    fingerprint.  When a new MAC is observed with an already-known fingerprint,
    it is flagged as a correlated device (likely the same hardware).
    """

    def __init__(self):
        self._fp_to_macs: Dict[str, Set[str]] = {}
        self._mac_to_fp: Dict[str, str] = {}

    def update(self, mac: str, fingerprint: str) -> bool:
        """Record a MAC ↔ fingerprint association.

        Returns True if this MAC has a *new* fingerprint association, i.e. a
        previously unseen MAC sharing a fingerprint with an existing one.
        """
        old_fp = self._mac_to_fp.get(mac)
        if old_fp and old_fp != fingerprint:
            self._fp_to_macs.get(old_fp, set()).discard(mac)

        self._mac_to_fp[mac] = fingerprint
        if fingerprint not in self._fp_to_macs:
            self._fp_to_macs[fingerprint] = set()

        already_known = fingerprint in self._fp_to_macs and len(self._fp_to_macs[fingerprint]) > 0
        self._fp_to_macs[fingerprint].add(mac)
        return already_known and mac not in (self._fp_to_macs[fingerprint] - {mac})

    def correlated_macs(self, fingerprint: str) -> Set[str]:
        """Return all MACs seen with the given fingerprint."""
        return set(self._fp_to_macs.get(fingerprint, set()))

    def get_fingerprint(self, mac: str) -> Optional[str]:
        """Return the most recently seen IE fingerprint for a MAC."""
        return self._mac_to_fp.get(mac)

    def groups(self) -> List[Tuple[str, Set[str]]]:
        """Return (fingerprint, set_of_macs) for groups with more than one MAC.

        Each group represents a set of randomized MACs that are likely the same
        physical device tracked across MAC address rotations.
        """
        return [
            (fp, macs)
            for fp, macs in self._fp_to_macs.items()
            if len(macs) > 1
        ]
