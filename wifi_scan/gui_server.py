"""Flask + SocketIO web GUI for wifi-scan."""

import threading
from typing import Optional

_HAS_FLASK = False
try:
    from flask import Flask
    from flask_socketio import SocketIO
    _HAS_FLASK = True
except ImportError:
    pass

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>wifi-scan</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a0a;color:#00ff41;font-family:'Courier New',monospace;font-size:13px;overflow:hidden;height:100vh;display:flex;flex-direction:column}
#header{background:#111;border-bottom:1px solid #00ff4133;padding:8px 16px;display:flex;align-items:center;gap:24px;flex-shrink:0}
#header h1{color:#00ff41;font-size:15px;letter-spacing:2px}
.stat{color:#aaa;font-size:12px}
.stat span{color:#00ff41;font-weight:bold}
#main{display:flex;flex:1;overflow:hidden}
#sidebar{width:280px;flex-shrink:0;border-right:1px solid #00ff4133;display:flex;flex-direction:column;overflow:hidden}
#sidebar h2{padding:8px 12px;font-size:12px;color:#888;border-bottom:1px solid #1a1a1a;letter-spacing:1px}
#device-list{flex:1;overflow-y:auto;padding:4px 0}
.dev-entry{padding:6px 12px;cursor:pointer;border-bottom:1px solid #111}
.dev-entry:hover{background:#111}
.dev-entry.ap{border-left:3px solid #00aaff}
.dev-entry.station{border-left:3px solid #00ff41}
.dev-entry.correlated{border-left:3px solid #ff9900}
.dev-mac{font-size:12px;color:#fff}
.dev-ssid{font-size:11px;color:#888;margin-top:2px}
.dev-meta{font-size:11px;color:#555;margin-top:2px}
.dev-rssi{font-size:11px}
.rssi-strong{color:#00ff41}
.rssi-med{color:#ffcc00}
.rssi-weak{color:#ff4400}
#content{flex:1;display:flex;flex-direction:column;overflow:hidden}
#radar-wrap{flex:1;position:relative;display:flex;align-items:center;justify-content:center;background:#050505}
canvas#radar{display:block}
#detail{height:160px;flex-shrink:0;background:#0d0d0d;border-top:1px solid #00ff4133;padding:10px 16px;overflow-y:auto;font-size:12px}
#detail table{border-collapse:collapse;width:100%}
#detail td{padding:2px 8px;vertical-align:top}
#detail td:first-child{color:#888;white-space:nowrap;width:140px}
#detail td:last-child{color:#00ff41}
#status-bar{padding:4px 16px;background:#0a0a0a;border-top:1px solid #1a1a1a;font-size:11px;color:#444;flex-shrink:0}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:#0a0a0a}::-webkit-scrollbar-thumb{background:#1a3a1a}
</style>
</head>
<body>
<div id="header">
  <h1>wifi-scan</h1>
  <div class="stat">APs: <span id="s-aps">0</span></div>
  <div class="stat">Stations: <span id="s-sta">0</span></div>
  <div class="stat">Detections: <span id="s-det">0</span></div>
  <div class="stat">Elapsed: <span id="s-el">0</span>s</div>
  <div class="stat" id="s-gps" style="display:none">GPS: <span id="s-gps-val">-</span></div>
</div>
<div id="main">
  <div id="sidebar">
    <h2>DEVICES</h2>
    <div id="device-list"></div>
  </div>
  <div id="content">
    <div id="radar-wrap"><canvas id="radar"></canvas></div>
    <div id="detail"><em style="color:#333">Click a device to see details</em></div>
  </div>
</div>
<div id="status-bar" id="status">Connecting...</div>

<script src="https://cdn.socket.io/4.6.1/socket.io.min.js"></script>
<script>
const socket = io();
const devices = {};
let selectedMac = null;
let radarAngle = 0;
let animId = null;

const canvas = document.getElementById('radar');
const ctx = canvas.getContext('2d');

function resizeCanvas(){
  const wrap = document.getElementById('radar-wrap');
  const sz = Math.min(wrap.clientWidth, wrap.clientHeight) - 20;
  canvas.width = sz; canvas.height = sz;
}
resizeCanvas();
window.addEventListener('resize', resizeCanvas);

function rssiClass(rssi){
  if(rssi >= -60) return 'rssi-strong';
  if(rssi >= -75) return 'rssi-med';
  return 'rssi-weak';
}

function drawRadar(){
  const sz = canvas.width, cx = sz/2, cy = sz/2, r = sz/2 - 10;
  ctx.clearRect(0, 0, sz, sz);

  // Grid rings
  ctx.strokeStyle = '#0a2a0a';
  ctx.lineWidth = 1;
  for(let i=1;i<=4;i++){
    ctx.beginPath();
    ctx.arc(cx, cy, r*i/4, 0, Math.PI*2);
    ctx.stroke();
  }
  // Cross-hairs
  ctx.beginPath();ctx.moveTo(cx,cy-r);ctx.lineTo(cx,cy+r);ctx.stroke();
  ctx.beginPath();ctx.moveTo(cx-r,cy);ctx.lineTo(cx+r,cy);ctx.stroke();

  // Sweep
  radarAngle = (radarAngle + 0.03) % (Math.PI * 2);
  const grad = ctx.createConicalGradient ? null : null;
  ctx.save();
  ctx.translate(cx, cy);
  ctx.rotate(radarAngle);
  const sweep = ctx.createLinearGradient(0, 0, r, 0);
  sweep.addColorStop(0, 'rgba(0,255,65,0.3)');
  sweep.addColorStop(1, 'rgba(0,255,65,0)');
  ctx.fillStyle = sweep;
  ctx.beginPath();
  ctx.moveTo(0, 0);
  ctx.arc(0, 0, r, -0.3, 0.3);
  ctx.fill();
  ctx.restore();

  // Devices as blips
  const devArr = Object.values(devices);
  devArr.forEach((d, i) => {
    const rssi = d.rssi || -90;
    // Map RSSI to distance ring (stronger = closer = inner)
    const normDist = Math.max(0, Math.min(1, (rssi + 30) / -70));
    const blipR = r * normDist;
    // Spread devices evenly by index
    const angle = (i / Math.max(devArr.length, 1)) * Math.PI * 2;
    const bx = cx + blipR * Math.cos(angle);
    const by = cy + blipR * Math.sin(angle);

    const isAP = d.device_type === 'AP';
    const color = isAP ? '#00aaff' : (d.is_correlated ? '#ff9900' : '#00ff41');
    const size = d.mac === selectedMac ? 5 : 3;

    ctx.beginPath();
    ctx.arc(bx, by, size, 0, Math.PI*2);
    ctx.fillStyle = color;
    ctx.fill();

    if(Math.abs(bx - cx) > 8 || Math.abs(by - cy) > 8){
      const label = (d.ssid || d.address || '').substring(0, 12);
      ctx.fillStyle = '#00ff4188';
      ctx.font = '9px monospace';
      ctx.fillText(label, bx + 5, by - 3);
    }
  });

  animId = requestAnimationFrame(drawRadar);
}
drawRadar();

function buildDeviceList(){
  const list = document.getElementById('device-list');
  const sorted = Object.values(devices).sort((a,b)=>(b.rssi||0)-(a.rssi||0));
  list.innerHTML = sorted.map(d => {
    const cls = d.device_type === 'AP' ? 'ap' : (d.is_correlated ? 'correlated' : 'station');
    const rssiStr = d.rssi != null ? d.rssi + ' dBm' : '';
    const rClass = d.rssi != null ? rssiClass(d.rssi) : '';
    const sub = d.device_type === 'AP'
      ? (d.ssid || '[hidden]')
      : (d.probe_ssids ? 'probing: ' + d.probe_ssids.split(',')[0] : '[scanning]');
    const rand = d.is_randomized ? ' <span style="color:#555;font-size:10px">[rand]</span>' : '';
    return `<div class="dev-entry ${cls}" onclick="selectDevice('${d.address}')">
      <div class="dev-mac">${d.address}${rand}</div>
      <div class="dev-ssid">${sub}</div>
      <div class="dev-meta"><span class="${rClass}">${rssiStr}</span> &nbsp; ${d.vendor||''}</div>
    </div>`;
  }).join('');
}

function selectDevice(mac){
  selectedMac = mac;
  const d = devices[mac];
  if(!d) return;
  const rows = [
    ['Address', d.address + (d.is_randomized ? ' [randomized]' : '')],
    ['Type', d.device_type],
    ['SSID', d.ssid || (d.device_type === 'AP' ? '[hidden]' : '')],
    ['RSSI', d.rssi != null ? d.rssi + ' dBm' : ''],
    ['Est. Distance', d.est_distance != null ? '~' + d.est_distance.toFixed(1) + ' m' : ''],
    ['Channel', d.channel || ''],
    ['Encryption', d.encryption || ''],
    ['Vendor', d.vendor || ''],
    ['Probing', d.probe_ssids || ''],
    ['IE Fingerprint', d.ie_fingerprint || ''],
    ['HT Caps', d.ht_caps || ''],
    ['VHT Caps', d.vht_caps || ''],
    ['Seen', (d.seen_count || 1) + 'x'],
    ['Last Seen', d.timestamp ? d.timestamp.substring(11,19) : ''],
  ].filter(r => r[1]);

  document.getElementById('detail').innerHTML =
    '<table>' + rows.map(r=>`<tr><td>${r[0]}</td><td>${r[1]}</td></tr>`).join('') + '</table>';
}

socket.on('device', data => {
  devices[data.address] = {...(devices[data.address]||{}), ...data};
  buildDeviceList();
  if(selectedMac === data.address) selectDevice(data.address);
});

socket.on('status', data => {
  const aps = Object.values(devices).filter(d=>d.device_type==='AP').length;
  const sta = Object.values(devices).filter(d=>d.device_type==='Station').length;
  document.getElementById('s-aps').textContent = aps;
  document.getElementById('s-sta').textContent = sta;
  document.getElementById('s-det').textContent = data.total_detections || 0;
  document.getElementById('s-el').textContent = data.elapsed || 0;
  document.getElementById('status-bar').textContent =
    data.scanning ? 'Scanning...' : 'Scan complete';
});

socket.on('gps', data => {
  const gpsEl = document.getElementById('s-gps');
  gpsEl.style.display = 'block';
  document.getElementById('s-gps-val').textContent =
    data.lat.toFixed(5) + ', ' + data.lon.toFixed(5);
});

socket.on('connect', () => {
  document.getElementById('status-bar').textContent = 'Connected';
});
socket.on('disconnect', () => {
  document.getElementById('status-bar').textContent = 'Disconnected';
});
</script>
</body>
</html>
"""


class GuiServer:
    """Flask + SocketIO web GUI server for wifi-scan."""

    def __init__(self, port: int = 5000):
        self._port = port
        self._thread: Optional[threading.Thread] = None
        self._sio: Optional["SocketIO"] = None
        self._app: Optional["Flask"] = None

    def start(self):
        if not _HAS_FLASK:
            return
        self._app = Flask(__name__)
        self._app.config["SECRET_KEY"] = "wifi-scan"
        self._sio = SocketIO(self._app, cors_allowed_origins="*",
                             async_mode="threading", logger=False,
                             engineio_logger=False)

        @self._app.route("/")
        def index():
            from flask import Response
            return Response(_HTML, mimetype="text/html")

        self._thread = threading.Thread(
            target=self._sio.run,
            kwargs={"app": self._app, "port": self._port,
                    "host": "0.0.0.0", "allow_unsafe_werkzeug": True},
            daemon=True,
        )
        self._thread.start()

        import webbrowser, time
        time.sleep(0.8)
        webbrowser.open(f"http://localhost:{self._port}")

    def emit_device(self, record: dict):
        if self._sio is None:
            return
        payload = {
            "address": record.get("address", ""),
            "ssid": record.get("ssid", ""),
            "device_type": record.get("device_type", ""),
            "rssi": record.get("rssi"),
            "est_distance": record.get("est_distance"),
            "channel": record.get("channel"),
            "encryption": record.get("encryption", ""),
            "is_randomized": bool(record.get("is_randomized")),
            "vendor": record.get("vendor", ""),
            "ie_fingerprint": record.get("ie_fingerprint", ""),
            "probe_ssids": record.get("probe_ssids", ""),
            "ht_caps": record.get("ht_caps", ""),
            "vht_caps": record.get("vht_caps", ""),
            "seen_count": record.get("seen_count", 1),
            "timestamp": record.get("timestamp", ""),
        }
        try:
            self._sio.emit("device", payload)
        except Exception:
            pass

    def emit_status(self, data: dict):
        if self._sio is None:
            return
        try:
            self._sio.emit("status", data)
        except Exception:
            pass

    def emit_gps(self, fix: dict):
        if self._sio is None:
            return
        try:
            self._sio.emit("gps", fix)
        except Exception:
            pass

    def stop(self):
        if self._sio is not None:
            try:
                self._sio.stop()
            except Exception:
                pass
