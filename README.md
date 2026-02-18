# wifi-scan

A 802.11 WiFi scanner with monitor-mode packet capture, MAC randomization detection, IE fingerprint correlation, and SQLite/CSV/JSON output.

Directly inspired by [btrpa-scan](../btrpa-scan/) — the BLE scanner with RPA resolution — and mirrors its architecture for WiFi:

| BLE (btrpa-scan) | WiFi (wifi-scan) |
|---|---|
| BLE advertisement | 802.11 management frame (Beacon / Probe Request) |
| Resolvable Private Address (RPA) | Randomized MAC (locally administered bit) |
| IRK (Identity Resolving Key) | IE fingerprint (stable probe request sequence) |
| `--irk` resolution | `--correlate` correlation |
| bleak `BleakScanner` | scapy `AsyncSniffer` |
| iBeacon / Eddystone parsing | IE parsing (HT/VHT caps, RSN, vendor IEs) |

## Features

- **Monitor-mode sniffing** via scapy — captures Beacon, Probe Request, Probe Response, and Association frames
- **AP discovery** — BSSID, SSID, channel, encryption (Open/WEP/WPA/WPA2/WPA3), vendor, HT/VHT capabilities
- **Station discovery** — detects client devices probing for networks, tracks probe SSID history
- **MAC randomization detection** — flags devices using locally administered (randomized) MACs
- **IE fingerprint correlation** (`--correlate`) — groups detections sharing the same probe request IE fingerprint, tracking the same physical device across MAC rotations (the WiFi analog of BLE IRK resolution)
- **Channel hopping** — automatically cycles through 2.4 GHz + 5 GHz channels
- **OUI vendor lookup** — identifies device manufacturer from MAC prefix
- **RSSI averaging** — sliding-window averaging for stable distance estimates
- **Distance estimation** — log-distance path-loss model (free_space / outdoor / indoor)
- **GPS stamping** — integrates with gpsd for location tagging
- **Live TUI** — curses-based real-time device table with RSSI sparklines
- **Web GUI** — Flask + SocketIO radar visualization, auto-opens in browser
- **Persistent output** — SQLite database, real-time CSV log, batch JSON/JSONL/CSV

## Requirements

- Linux (monitor mode)
- **Root** / `CAP_NET_RAW` + `CAP_NET_ADMIN` (required for monitor mode)
- `iw` — wireless interface management
- `scapy>=2.5.0`

## Installation

**Option A — run directly (no install):**

```bash
git clone https://github.com/7ang0n1n3/wifi-scan.git
cd wifi-scan
pip install scapy            # core dependency
pip install flask flask-socketio  # optional: web GUI
sudo python3 wifi-scan.py --all -i wlan0
```

**Option B — install as a command:**

```bash
pip install -e .
# or with web GUI support:
pip install -e ".[gui]"
sudo wifi-scan --all -i wlan0
```

> Throughout this README, `wifi-scan` refers to the installed command.
> If running directly, replace it with `python3 wifi-scan.py`.

## Monitor mode

wifi-scan configures monitor mode automatically — no manual setup needed.
Pass your wireless interface with `-i` and the app handles the rest:

```bash
sudo python3 wifi-scan.py --all -i wlan0
```

On startup it tries two strategies in order:

1. **Virtual monitor interface** (preferred) — adds `wlan0mon` on top of the
   managed `wlan0`, leaving your WiFi connection active.  Supported by most
   Intel, Atheros, and Broadcom drivers.
2. **Full monitor mode** — if the driver does not support virtual interfaces,
   `wlan0` itself is switched to monitor mode for the duration of the scan and
   restored to managed mode automatically on exit (Ctrl+C or timeout).

The startup message tells you which strategy was used:

```
[*] Virtual monitor interface created: wlan0mon (WiFi connection on wlan0 preserved)
```
or
```
[*] wlan0 switched to monitor mode
```

## Usage

```
sudo python3 wifi-scan.py [bssid] [options]
# or if installed:
sudo wifi-scan [bssid] [options]
```

### Live TUI

The TUI shows a real-time scrolling device table with RSSI sparklines, sorted
by signal strength.  Bold rows are correlated devices (shared IE fingerprint).

```bash
sudo wifi-scan --all -i wlan0 --tui
```

Useful TUI combinations:

```bash
# 2.4 GHz only with 5-sample RSSI averaging
sudo wifi-scan --all -i wlan0 --tui --2ghz --rssi-window 5

# Track stations probing for networks, group by IE fingerprint
sudo wifi-scan --correlate -i wlan0 --tui --frame-types probe

# Log everything to SQLite while watching the TUI
sudo wifi-scan --all -i wlan0 --tui --db scan.db
```

### Web GUI

The web GUI opens a browser tab with a live radar canvas, device sidebar, and
detail panel.  Devices update in real time via WebSocket.

```bash
sudo wifi-scan --all -i wlan0 --gui
```

> **Note:** When running as root, Chrome/Chromium may block the auto-open
> due to sandbox restrictions.  If the browser does not appear, open
> `http://localhost:5000` manually.

Useful GUI combinations:

```bash
# Custom port
sudo wifi-scan --all -i wlan0 --gui --gui-port 8080

# Save to SQLite while the GUI runs
sudo wifi-scan --all -i wlan0 --gui --db scan.db

# 5 GHz only with signal averaging
sudo wifi-scan --all -i wlan0 --gui --5ghz --rssi-window 3
```

### Scan modes

```bash
# Discover all APs and stations (default)
sudo wifi-scan --all -i wlan0

# Target a specific BSSID
sudo wifi-scan AA:BB:CC:DD:EE:FF -i wlan0

# Search for a specific SSID (partial match, case-insensitive)
sudo wifi-scan --ssid "MyNetwork" -i wlan0

# Correlate devices across MAC randomization (WiFi analog of IRK resolution)
sudo wifi-scan --correlate -i wlan0
```

### Channel selection

```bash
# All channels, hopping (default)
sudo wifi-scan --all -i wlan0

# 2.4 GHz only (channels 1–13)
sudo wifi-scan --all -i wlan0 --2ghz

# 5 GHz only
sudo wifi-scan --all -i wlan0 --5ghz

# Stay on channel 6
sudo wifi-scan --all -i wlan0 --channel 6

# Disable hopping (dwell on first channel of selected band)
sudo wifi-scan --all -i wlan0 --2ghz --no-hop
```

### Frame capture

```bash
# Beacons only — discover APs
sudo wifi-scan --all -i wlan0 --frame-types beacon

# Probe requests only — discover client devices
sudo wifi-scan --all -i wlan0 --frame-types probe
```

### Signal filtering

```bash
# Ignore devices below -75 dBm
sudo wifi-scan --all -i wlan0 --min-rssi -75

# RSSI averaging over 5 samples
sudo wifi-scan --all -i wlan0 --rssi-window 5

# Proximity alert within 5 m
sudo wifi-scan --all -i wlan0 --alert-within 5
```

### Output

```bash
# Real-time CSV log
sudo wifi-scan --all -i wlan0 --log scan.csv

# SQLite database
sudo wifi-scan --all -i wlan0 --db wifi.db

# Batch JSON at end of scan
sudo wifi-scan --all -i wlan0 -t 30 --output json -o results.json
```

### GPS

```bash
# GPS stamping via gpsd (enabled automatically if gpsd is running)
sudo wifi-scan --all -i wlan0

# Disable GPS
sudo wifi-scan --all -i wlan0 --no-gps
```

## Configuration file

Create `~/.config/wifi-scan/config.toml`:

```toml
environment = "indoor"
min_rssi = -80
rssi_window = 5
alert_within = 10.0
timeout = 60
tui = false
gui = false
gui_port = 5000
gps = true
db = "/var/lib/wifi-scan/scans.db"
```

Or JSON: `~/.config/wifi-scan/config.json`

Override path with `$WIFI_SCAN_CONFIG=/path/to/config.toml`.

## Output fields

| Field | Description |
|---|---|
| `address` | MAC address (BSSID for APs, station MAC for clients) |
| `ssid` | Network name (APs) or probed SSID (stations) |
| `device_type` | `AP` or `Station` |
| `rssi` | Signal strength (dBm) |
| `avg_rssi` | Averaged RSSI (with `--rssi-window`) |
| `channel` | 802.11 channel number |
| `encryption` | Open / WEP / WPA / WPA2 / WPA3 / WPA2/WPA3 / WPA3-OWE |
| `is_randomized` | 1 if locally administered (randomized) MAC |
| `vendor` | OUI vendor name |
| `ie_fingerprint` | SHA-256 prefix of IE sequence (stations only) |
| `probe_ssids` | Comma-separated list of probed SSIDs (stations only) |
| `ht_caps` | HT (WiFi 4) capability summary |
| `vht_caps` | VHT (WiFi 5) capability summary |
| `latitude`, `longitude`, `gps_altitude` | GPS fix (if gpsd available) |
| `vendor_ies` | JSON list of parsed vendor-specific IEs |

## IE fingerprint correlation (`--correlate`)

Modern devices rotate their WiFi MAC addresses periodically (Android 10+,
iOS 14+, Windows 10 21H1+) to prevent cross-network tracking.

`--correlate` uses the Information Element (IE) sequence in probe requests as a
behavioral fingerprint.  This sequence — the precise order and values of
supported rates, HT/VHT capability bits, extended capabilities, and vendor IE
OUIs — is determined by the device's driver and OS, and remains stable across
MAC rotations.

When two different MACs share an IE fingerprint they are flagged as likely the
same physical device:

```
FP CORRELATED  —  addr #3  [FP match: DE:AD:BE:EF:00:01]
  Address       : DE:AD:BE:EF:00:02 [randomized MAC]
  IE Fingerprint: a1b2c3d4e5f60708
```

This is the direct WiFi analog of btrpa-scan's BLE IRK resolution.

## Running tests

```bash
pip install pytest
pytest tests/ -v
```

## Architecture

```
wifi_scan/
├── cli.py          # CLI argument parser & main entry
├── scanner.py      # WiFiScanner class (scapy AsyncSniffer + channel hopper)
├── detection.py    # 802.11 frame parsing, IE extraction, fingerprinting
├── crypto.py       # MAC randomization, distance estimation, FingerprintCorrelator
├── lookup.py       # OUI vendor lookup, vendor IE name lookup
├── output.py       # Record building, CSV/JSON/SQLite output
├── tui.py          # Curses live TUI with RSSI sparklines
├── gui_server.py   # Flask + SocketIO web radar GUI
├── gps.py          # Lightweight gpsd TCP client
├── config.py       # TOML/JSON config loading
├── utils.py        # MAC normalization, timestamp, randomization check
├── constants.py    # Channels, IE tags, CSV fields, timing
└── data/
    ├── oui.json        # IEEE OUI vendor database
    └── vendor_ies.json # Known vendor-specific IE OUI names
```
