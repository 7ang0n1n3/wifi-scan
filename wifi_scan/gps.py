"""Lightweight gpsd client for wifi-scan."""

import json
import socket
import threading
import time
from typing import Optional

from .constants import _GPS_RECONNECT_DELAY, _GPS_SOCKET_TIMEOUT


class GpsdReader:
    """Lightweight gpsd client that reads GPS fixes over a TCP socket."""

    def __init__(self, host: str = "localhost", port: int = 2947):
        self._host = host
        self._port = port
        self._lock = threading.Lock()
        self._fix: Optional[dict] = None
        self._connected = False
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    @property
    def fix(self) -> Optional[dict]:
        with self._lock:
            return dict(self._fix) if self._fix else None

    @property
    def connected(self) -> bool:
        with self._lock:
            return self._connected

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run(self):
        while self._running:
            try:
                self._connect_and_read()
            except (OSError, ConnectionRefusedError, ConnectionResetError):
                pass
            with self._lock:
                self._connected = False
            if self._running:
                time.sleep(_GPS_RECONNECT_DELAY)

    def _connect_and_read(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_GPS_SOCKET_TIMEOUT)
        with self._lock:
            self._sock = sock
        try:
            sock.connect((self._host, self._port))
            with self._lock:
                self._connected = True
            sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
            buf = ""
            while self._running:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                buf += data.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if msg.get("class") == "TPV":
                        lat = msg.get("lat")
                        lon = msg.get("lon")
                        if lat is not None and lon is not None:
                            with self._lock:
                                self._fix = {
                                    "lat": lat,
                                    "lon": lon,
                                    "alt": msg.get("alt"),
                                }
        finally:
            with self._lock:
                self._sock = None
            sock.close()
