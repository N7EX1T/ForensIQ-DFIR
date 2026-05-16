#!/usr/bin/env python3
"""
ForensIQ v3.0 — Desktop Application Entry Point
================================================

Digital Forensics & Incident Response (DFIR) analyzer for Linux.
This module provides the PyQt6 desktop window, embedded WebEngine browser,
local HTTP server (port 18765), and proxy for AI API requests.

Architecture:
    - QMainWindow hosts a QWebEngineView that loads ForensIQ.html
    - A background HTTP server exposes /api/* endpoints
    - The HTML dashboard fetches data from these endpoints via JS
    - All scanning logic lives in forensiq_engine.py
    - User data is stored in ~/.forensiq/ (sessions, reports)

Run:
    sudo python3 forensiq_app.py
    or use the desktop shortcut after running install.sh

Author: Egor Gubarev
License: MIT
"""

import sys, os, json, threading, subprocess, urllib.request, urllib.error

# Auto-install required dependencies on first run
def _ensure_dep(module, pip_name=None):
    pip_name = pip_name or module
    try:
        __import__(module)
        return True
    except ImportError:
        print(f"  [setup] Installing {pip_name} ...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install",
                                   pip_name, "--break-system-packages", "--quiet"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            __import__(module)
            return True
        except Exception:
            return False

_ensure_dep("PyQt6")
_ensure_dep("PyQt6.QtWebEngineWidgets", "PyQt6-WebEngine")
_ensure_dep("reportlab")
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QProgressBar, QCheckBox, QFrame,
    QDialog, QScrollArea, QGridLayout, QMessageBox, QFileDialog,
    QListWidget, QListWidgetItem, QSizePolicy, QSystemTrayIcon, QMenu
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl, QThread, pyqtSignal, QTimer, Qt, QSize
from PyQt6.QtGui import QFont, QIcon, QPixmap, QPainter, QColor, QImage

if os.geteuid() == 0:
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox"

import forensiq_engine as engine

PORT    = 18765
# ─── AI CONFIGURATION ───────────────────────────────────────────────────
# Set AI_ENABLED to True to enable the AI Analyst feature
# Requires either Anthropic API key OR local Ollama installation
AI_ENABLED = False  # Set to True to enable AI Analyst tab and auto-analysis

ANTHROPIC_API_KEY = ""    # Paste your sk-ant-... key here if using Anthropic
OLLAMA_ENABLED    = True  # True = use local Ollama (free), False = use Anthropic
OLLAMA_URL      = "http://localhost:11434/api/chat"
OLLAMA_MODEL    = "llama3.1:8b"  # модель которую скачал через ollama pull
IS_ROOT = os.geteuid() == 0

# ── Colors ─────────────────────────────────────────────────────────────────────
C = {
    'bg0':   '#1c1c26', 'bg1': '#242432', 'bg2': '#2c2c3e',
    'bg3':   '#343448', 'line': '#3a3a52',
    'red':   '#ff6b6b', 'redh': '#ff8888',
    'green': '#44e8a0', 'orange': '#ffaa44', 'text': '#f0f0ff',
    't2':    '#c8c8e8', 't3': '#8888aa',
}

# ── Icon — shield + magnifier ─────────────────────────────────────────────────
def make_icon(size=64):
    try:
        from PyQt6.QtGui import QPen, QBrush, QPainterPath, QImage, QPainter, QColor, QIcon, QPixmap
        from PyQt6.QtCore import QRectF, Qt
        r = size / 64.0
        img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
        img.fill(Qt.GlobalColor.transparent)
        p = QPainter(img)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        red   = QColor('#ff6b6b')
        bg    = QColor('#1c1c26')
        # Background rounded rect
        p.setBrush(QBrush(bg)); p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 0, size, size, int(13*r), int(13*r))
        # Shield shape
        shield = QPainterPath()
        shield.moveTo(32*r, 8*r)
        shield.lineTo(54*r, 16*r)
        shield.lineTo(54*r, 34*r)
        shield.cubicTo(54*r, 46*r, 42*r, 54*r, 32*r, 58*r)
        shield.cubicTo(22*r, 54*r, 10*r, 46*r, 10*r, 34*r)
        shield.lineTo(10*r, 16*r)
        shield.closeSubpath()
        # Fill shield with subtle tint
        p.setBrush(QBrush(QColor(255, 107, 107, 28)))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawPath(shield)
        # Shield border
        pen = QPen(red, 2.8*r)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen); p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(shield)
        # Magnifier circle
        p.setPen(QPen(red, 2.5*r))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(QRectF(22*r, 20*r, 16*r, 16*r))
        # Magnifier handle
        pen2 = QPen(red, 2.8*r)
        pen2.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen2)
        p.drawLine(int(35*r), int(33*r), int(42*r), int(40*r))
        p.end()
        return QIcon(QPixmap.fromImage(img))
    except Exception as e:
        print(f"[icon] {e}")
        return QIcon()


# ── Auto dependency installer ─────────────────────────────────────────────────
SYSTEM_DEPS = [
    ('extundelete', 'extundelete', 'File recovery (deleted ext4 files)'),
    ('testdisk',    'testdisk',    'Disk/partition recovery'),
    ('photorec',    'testdisk',    'File carving & recovery'),
    ('volatility3', 'volatility3', 'Memory forensics'),
    ('foremost',    'foremost',    'File carving from raw images'),
    ('dcfldd',      'dcfldd',      'Forensic disk imaging'),
    ('binwalk',     'binwalk',     'Firmware/binary analysis'),
    ('yara',        'yara',        'Malware pattern matching'),
    ('nmap',        'nmap',        'Network scanner'),
    ('wireshark',   'wireshark',   'Network packet capture'),
    ('strings',     'binutils',    'Binary string extraction'),
    ('hexdump',     'bsdmainutils','Hex dump tool'),
    ('file',        'file',        'File type identification'),
    ('lsof',        'lsof',        'Open file lister'),
    ('strace',      'strace',      'System call tracer'),
    ('chkrootkit',  'chkrootkit',  'Rootkit detector'),
    ('rkhunter',    'rkhunter',    'Rootkit hunter'),
    ('unhide',      'unhide',      'Hidden process/port detector'),
    ('lynis',       'lynis',       'Security audit tool'),
    ('auditd',      'auditd',      'Linux audit daemon'),
]

PIP_DEPS = [
    ('PyQt6',              'PyQt6',              'GUI framework'),
    ('PyQt6-WebEngine',    'PyQt6-WebEngine',    'Embedded browser'),
    ('PyQt6-Svg',          'PyQt6-Svg',          'SVG support'),
    ('psutil',             'psutil',             'Process/system utilities'),
    ('yara-python',        'yara-python',        'YARA Python bindings'),
]

def check_cmd(cmd):
    try:
        subprocess.run(['which', cmd], capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def install_pkg(pkg):
    try:
        subprocess.run(['apt-get', 'install', '-y', pkg],
                       capture_output=True, timeout=120)
        return True
    except Exception:
        return False


# ── Sessions directory ──────────────────────────────────────────────────────
# User data directory — separate per user, follows XDG spec
USER_DATA_DIR = os.path.join(os.path.expanduser("~"), ".forensiq")
SESSIONS_DIR  = os.path.join(USER_DATA_DIR, "sessions")
os.makedirs(SESSIONS_DIR, exist_ok=True)

def get_sessions():
    """Return list of saved sessions sorted by modification time desc."""
    if not os.path.isdir(SESSIONS_DIR):
        return []
    sessions = []
    for fn in os.listdir(SESSIONS_DIR):
        if fn.endswith(".json"):
            fp = os.path.join(SESSIONS_DIR, fn)
            try:
                mtime = os.path.getmtime(fp)
                with open(fp) as f:
                    d = json.load(f)
                s = d.get("summary", {})
                sessions.append({
                    "path": fp,
                    "name": fn,
                    "mtime": mtime,
                    "hostname": s.get("hostname", "unknown"),
                    "scanned_at": s.get("scanned_at", ""),
                    "risk": d.get("risk_score", 0),
                    "critical": s.get("critical", 0),
                    "total": s.get("total", 0),
                })
            except Exception:
                pass
    sessions.sort(key=lambda x: x["mtime"], reverse=True)
    return sessions


class SessionDialog(QDialog):
    """Startup dialog: new scan / load session / load log file."""

    RESULT_NEW     = 1
    RESULT_SESSION = 2
    RESULT_FILE    = 3

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ForensIQ — Start")
        self.setFixedSize(620, 520)
        self.setModal(True)
        self.choice = self.RESULT_NEW
        self.session_path = None
        self._build()

    def _btn_style(self, primary=False):
        if primary:
            return (f"QPushButton{{background:{C['red']};color:#fff;border:none;"
                    f"border-radius:8px;padding:12px 28px;font-size:12px;font-weight:700;"
                    f"letter-spacing:1px;}}"
                    f"QPushButton:hover{{background:{C['redh']};}}")
        return (f"QPushButton{{background:{C['bg2']};color:{C['t2']};"
                f"border:1px solid {C['line']};border-radius:8px;padding:12px 24px;"
                f"font-size:12px;font-weight:600;}}"
                f"QPushButton:hover{{background:{C['bg3']};color:{C['text']};}}")

    def _build(self):
        self.setStyleSheet(f"""
            QDialog{{background:{C['bg0']};color:{C['text']};
                font-family:'Segoe UI',Ubuntu,sans-serif;}}
            QLabel#title{{font-size:22px;font-weight:700;letter-spacing:4px;
                color:{C['text']};font-family:'JetBrains Mono','Courier New';}}
            QLabel#sub{{font-size:11px;color:{C['t3']};
                font-family:'JetBrains Mono','Courier New';}}
            QLabel#sec{{font-size:10px;color:{C['t3']};letter-spacing:2px;
                text-transform:uppercase;font-family:'JetBrains Mono','Courier New';}}
            QListWidget{{background:{C['bg1']};border:1px solid {C['line']};
                border-radius:6px;color:{C['text']};font-size:12px;
                font-family:'JetBrains Mono','Courier New';outline:none;}}
            QListWidget::item{{padding:8px 12px;border-bottom:1px solid {C['bg2']};}}
            QListWidget::item:selected{{background:{C['bg3']};color:{C['text']};}}
            QListWidget::item:hover{{background:{C['bg2']};}}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(30, 28, 30, 24)
        root.setSpacing(0)

        # Header
        hdr = QHBoxLayout()
        ico_lbl = QLabel()
        ico_lbl.setPixmap(make_icon(40).pixmap(40, 40))
        hdr.addWidget(ico_lbl)
        hdr.addSpacing(12)
        vlbl = QVBoxLayout()
        vlbl.setSpacing(2)
        t = QLabel("FORENSIQ"); t.setObjectName("title")
        s = QLabel("Digital Forensics & Incident Response  ·  v3.0")
        s.setObjectName("sub")
        vlbl.addWidget(t); vlbl.addWidget(s)
        hdr.addLayout(vlbl); hdr.addStretch()
        root.addLayout(hdr)
        root.addSpacing(24)

        # Sessions section
        sec_lbl = QLabel("PREVIOUS SESSIONS")
        sec_lbl.setObjectName("sec")
        root.addWidget(sec_lbl)
        root.addSpacing(6)

        self.list_widget = QListWidget()
        self.list_widget.setFixedHeight(180)
        sessions = get_sessions()
        if sessions:
            for s in sessions[:12]:
                risk_col = C['red'] if s['risk'] >= 80 else C['orange'] if s['risk'] >= 50 else C['green']
                item_text = (f"  {s['scanned_at'][:16] if s['scanned_at'] else 'unknown date'}"
                             f"   {s['hostname']:<18}"
                             f"   risk:{s['risk']:>3}   crit:{s['critical']:>3}   total:{s['total']:>5}")
                item = QListWidgetItem(item_text)
                item.setData(256, s["path"])  # Qt.UserRole = 256
                self.list_widget.addItem(item)
            self.list_widget.setCurrentRow(0)
        else:
            placeholder = QListWidgetItem("  No saved sessions yet")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self.list_widget.addItem(placeholder)
        root.addWidget(self.list_widget)
        root.addSpacing(10)

        # Open session button
        btn_open = QPushButton("▶  Open Selected Session")
        btn_open.setStyleSheet(self._btn_style(False))
        btn_open.clicked.connect(self._open_session)
        root.addWidget(btn_open)
        root.addSpacing(20)

        # Divider
        line = QFrame(); line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"background:{C['line']};max-height:1px;")
        root.addWidget(line)
        root.addSpacing(18)

        # Bottom row: load file | new scan
        sec2 = QLabel("OR")
        sec2.setObjectName("sec")
        sec2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(sec2)
        root.addSpacing(12)

        row = QHBoxLayout(); row.setSpacing(10)
        btn_file = QPushButton("📂  Load Log File (.json)")
        btn_file.setStyleSheet(self._btn_style(False))
        btn_file.clicked.connect(self._load_file)
        btn_new = QPushButton("▶  New Scan")
        btn_new.setStyleSheet(self._btn_style(True))
        btn_new.clicked.connect(self._new_scan)
        row.addWidget(btn_file); row.addWidget(btn_new)
        root.addLayout(row)

    def _open_session(self):
        item = self.list_widget.currentItem()
        if not item:
            return
        path = item.data(256)
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "Not found", "Session file not found.")
            return
        self.choice = self.RESULT_SESSION
        self.session_path = path
        self.accept()

    def _load_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open ForensIQ Report", "", "JSON files (*.json)")
        if path:
            self.choice = self.RESULT_FILE
            self.session_path = path
            self.accept()

    def _new_scan(self):
        self.choice = self.RESULT_NEW
        self.session_path = None
        self.accept()


class DepsDialog(QDialog):
    """Shows missing deps and installs them."""
    install_done = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ForensIQ — Tools & Dependencies")
        self.setMinimumSize(680, 520)
        self.setStyleSheet(f"""
            QDialog {{ background:{C['bg1']};color:{C['text']}; }}
            QLabel  {{ color:{C['text']}; }}
            QCheckBox {{ color:{C['t2']};font-size:12px;spacing:7px; }}
            QCheckBox::indicator {{
                width:14px;height:14px;border-radius:3px;
                border:1px solid {C['line']};background:{C['bg2']};
            }}
            QCheckBox::indicator:checked {{
                background:{C['red']};border-color:{C['red']};
            }}
            QScrollArea,QWidget#inner {{ background:{C['bg1']};border:none; }}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(24,20,24,20)

        title = QLabel("Forensic Tools")
        title.setStyleSheet(f"font-size:17px;font-weight:700;color:{C['text']};margin-bottom:4px;")
        root.addWidget(title)

        sub = QLabel("Select tools to install. Installed tools are checked and greyed out.")
        sub.setStyleSheet(f"font-size:12px;color:{C['t3']};margin-bottom:12px;")
        root.addWidget(sub)

        div = QFrame(); div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"color:{C['line']};"); root.addWidget(div)

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget(); inner.setObjectName('inner')
        grid = QGridLayout(inner)
        grid.setContentsMargins(0,12,0,0)
        grid.setHorizontalSpacing(24); grid.setVerticalSpacing(10)
        scroll.setWidget(inner); root.addWidget(scroll, 1)

        self._cbs = {}
        for idx, (cmd, pkg, desc) in enumerate(SYSTEM_DEPS):
            installed = check_cmd(cmd)
            row_w = QWidget(); row_w.setStyleSheet('background:transparent;')
            vl = QVBoxLayout(row_w); vl.setContentsMargins(0,0,0,0); vl.setSpacing(1)
            cb = QCheckBox(cmd)
            cb.setChecked(not installed)
            cb.setEnabled(not installed)
            if installed:
                cb.setStyleSheet(f"color:{C['t3']};font-size:12px;")
            lbl = QLabel(f"  {desc}  ·  apt: {pkg}")
            lbl.setStyleSheet(f"font-size:10px;color:{C['t3']};margin-left:22px;")
            vl.addWidget(cb); vl.addWidget(lbl)
            grid.addWidget(row_w, idx//2, idx%2)
            self._cbs[pkg] = (cb, cmd)

        div2 = QFrame(); div2.setFrameShape(QFrame.Shape.HLine)
        div2.setStyleSheet(f"color:{C['line']};"); root.addWidget(div2)

        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet(f"font-family:'Courier New';font-size:11px;color:{C['t3']};padding:6px 0;")
        root.addWidget(self.status_lbl)

        foot = QHBoxLayout()
        foot.addStretch()
        self.btn_skip = QPushButton("Skip")
        self.btn_install = QPushButton("Install Selected")
        self.btn_skip.setFixedHeight(34)
        self.btn_install.setFixedHeight(34)
        self.btn_skip.setStyleSheet(f"""QPushButton{{background:{C['bg2']};color:{C['t2']};
            border:1px solid {C['line']};border-radius:6px;padding:0 18px;font-size:12px;}}
            QPushButton:hover{{background:{C['bg3']};color:{C['text']};}}""")
        self.btn_install.setStyleSheet(f"""QPushButton{{background:{C['red']};color:#fff;
            border:none;border-radius:6px;padding:0 22px;font-size:12px;font-weight:700;}}
            QPushButton:hover{{background:{C['redh']};}}""")
        self.btn_skip.clicked.connect(self.reject)
        self.btn_install.clicked.connect(self._do_install)
        if not IS_ROOT:
            self.btn_install.setEnabled(False)
            self.btn_install.setToolTip("Requires root to install packages")
        foot.addWidget(self.btn_skip); foot.addSpacing(8); foot.addWidget(self.btn_install)
        root.addLayout(foot)

    def _do_install(self):
        to_install = [pkg for pkg,(cb,cmd) in self._cbs.items() if cb.isChecked()]
        if not to_install:
            self.accept(); return
        self.btn_install.setEnabled(False)
        self.btn_skip.setEnabled(False)

        def worker():
            # apt update first
            self.status_lbl.setText("Running apt-get update…")
            subprocess.run(['apt-get','update','-qq'], capture_output=True, timeout=60)
            for pkg in to_install:
                self.status_lbl.setText(f"Installing {pkg}…")
                install_pkg(pkg)
            self.status_lbl.setText(f"Done. Installed {len(to_install)} package(s).")
            QTimer.singleShot(1200, self.accept)

        threading.Thread(target=worker, daemon=True).start()


# ── Scan Thread ───────────────────────────────────────────────────────────────
class ScanThread(QThread):
    progress = pyqtSignal(str, int, int)
    done     = pyqtSignal(dict)

    def __init__(self, ids):
        super().__init__(); self._ids = ids; self._cancel = False

    def cancel(self): self._cancel = True

    def run(self):
        engine.clear_state()
        sel   = [(s,l,f) for s,l,_,f,_ in SCANNERS if s in self._ids]
        total = len(sel) + 1
        for i,(sid,lbl,fn) in enumerate(sel):
            if self._cancel:
                self.progress.emit("Cancelled.",i,total); return
            self.progress.emit(f"Scanning {lbl}…",i,total)
            try: fn()
            except Exception as e: print(f"  [!] {sid}: {e}")
        if self._cancel: return
        self.progress.emit("Building report…",total-1,total)
        self.done.emit(engine.build_report())


# ── HTTP Handler ──────────────────────────────────────────────────────────────
class Handler(engine.http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        base = os.path.dirname(os.path.abspath(__file__))
        if self.path in ("/","/index.html"):
            self.send_response(200)
            self.send_header("Content-type","text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(open(os.path.join(base,"ForensIQ.html"),"rb").read())
        elif self.path == "/api/report":
            self.send_response(200)
            self.send_header("Content-type","application/json")
            self.send_header("Access-Control-Allow-Origin","*")
            self.send_header("Cache-Control","no-cache, no-store")
            self.end_headers()
            # Send empty sentinel if scan not done yet
            cache = engine.REPORT_CACHE
            if not cache or "summary" not in cache:
                self.wfile.write(b'{"ready":false}')
            else:
                self.wfile.write(json.dumps(cache).encode())
        elif self.path == "/api/correlations":
            self.send_response(200)
            self.send_header("Content-type","application/json")
            self.send_header("Access-Control-Allow-Origin","*")
            self.send_header("Cache-Control","no-cache, no-store")
            self.end_headers()
            try:
                data = engine.correlate()
            except Exception as ex:
                data = {"nodes":[],"edges":[],"chains":[],"stats":{},"error":str(ex)}
            self.wfile.write(json.dumps(data).encode())
        elif self.path == "/api/config":
            self.send_response(200)
            self.send_header("Content-type","application/json")
            self.send_header("Access-Control-Allow-Origin","*")
            self.end_headers()
            cfg = {"ai_enabled": AI_ENABLED, "version": "3.0",
                   "ollama": OLLAMA_ENABLED, "anthropic": bool(ANTHROPIC_API_KEY)}
            self.wfile.write(json.dumps(cfg).encode())
            return
        elif self.path == "/api/toggle_ai":
            # Runtime toggle of AI feature
            global AI_ENABLED
            AI_ENABLED = not AI_ENABLED
            self.send_response(200)
            self.send_header("Content-type","application/json")
            self.send_header("Access-Control-Allow-Origin","*")
            self.end_headers()
            self.wfile.write(json.dumps({"ai_enabled": AI_ENABLED}).encode())
            return
        elif self.path == "/api/pdf":
            self.send_response(200)
            self.send_header("Content-type","application/json")
            self.send_header("Access-Control-Allow-Origin","*")
            self.end_headers()
            if not engine.REPORT_CACHE:
                self.wfile.write(json.dumps({"ok":False,"error":"No scan data"}).encode())
                return
            import tempfile, os as _os
            ts = engine.REPORT_CACHE.get("summary",{}).get("scanned_at","scan").replace(" ","_").replace(":","")[:13]
            host = engine.REPORT_CACHE.get("summary",{}).get("hostname","host")[:20]
            fname = f"forensiq_{host}_{ts}.pdf"
            path = _os.path.join(_os.path.expanduser("~"), "Downloads", fname)
            try: _os.makedirs(_os.path.dirname(path), exist_ok=True)
            except: path = _os.path.join("/tmp", fname)
            ok, result = engine.generate_pdf(engine.REPORT_CACHE, path)
            self.wfile.write(json.dumps({"ok":ok,"path":result,"filename":fname}).encode())
            return
        elif self.path == "/api/sessions":
            # Return list of saved sessions
            self.send_response(200)
            self.send_header("Content-type","application/json")
            self.send_header("Access-Control-Allow-Origin","*")
            self.end_headers()
            sessions = []
            try:
                for s in get_sessions():
                    sessions.append({
                        "name":       s["name"],
                        "label":      f"{s['scanned_at'][:16]}  ·  {s['hostname']}  ·  risk:{s['risk']}  crit:{s['critical']}",
                        "path":       s["path"],
                        "scanned_at": s["scanned_at"],
                        "hostname":   s["hostname"],
                        "risk":       s["risk"],
                    })
            except Exception: pass
            self.wfile.write(json.dumps({"sessions": sessions}).encode())
        elif self.path.startswith("/api/session?path="):
            # Return specific session data
            from urllib.parse import unquote
            path = unquote(self.path[len("/api/session?path="):])
            self.send_response(200)
            self.send_header("Content-type","application/json")
            self.send_header("Access-Control-Allow-Origin","*")
            self.end_headers()
            try:
                if os.path.isfile(path) and path.endswith(".json"):
                    with open(path) as f:
                        self.wfile.write(f.read().encode())
                else:
                    self.wfile.write(b'{}')
            except Exception:
                self.wfile.write(b'{}')
        else:
            self.send_response(404); self.end_headers()
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
        self.end_headers()

    def do_POST(self):
        if self.path == "/api/ai":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
            except Exception:
                self.send_response(400); self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            if OLLAMA_ENABLED:
                # ── Ollama local AI ──────────────────────────────────────
                try:
                    # Convert Anthropic format → Ollama format
                    messages = data.get("messages", [])
                    system   = data.get("system", "")
                    # Prepend system as first user message if present
                    ollama_msgs = []
                    identity = (
                        "IMPORTANT: You are ForensIQ AI Analyst, created by Egor Gubarev as part of the ForensIQ DFIR platform. "
                        "If anyone asks who created you, who made you, or who you are — always answer: "
                        "'I am ForensIQ AI Analyst, created by Egor Gubarev (ForensIQ).' "
                        "Never say you are Llama, Meta, or any other AI. You are ForensIQ AI.\n\n"
                    )
                    if system:
                        ollama_msgs.append({"role": "system", "content": identity + system})
                    else:
                        ollama_msgs.append({"role": "system", "content": identity})
                    ollama_msgs.extend(messages)

                    ollama_payload = json.dumps({
                        "model":    OLLAMA_MODEL,
                        "messages": ollama_msgs,
                        "stream":   False,
                        "options":  {"temperature": 0.3, "num_predict": 2000}
                    }).encode()

                    req = urllib.request.Request(
                        OLLAMA_URL,
                        data=ollama_payload,
                        headers={"Content-Type": "application/json"},
                        method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=120) as resp:
                        result = json.loads(resp.read())

                    # Convert Ollama response → Anthropic format
                    text = result.get("message", {}).get("content", "No response")
                    out  = json.dumps({
                        "content": [{"type": "text", "text": text}],
                        "model":   OLLAMA_MODEL,
                        "role":    "assistant"
                    })
                    self.wfile.write(out.encode())

                except Exception as e:
                    err = json.dumps({"error": {"message": f"Ollama error: {e}. Make sure Ollama is running: ollama serve"}})
                    self.wfile.write(err.encode())

            elif ANTHROPIC_API_KEY:
                # ── Anthropic API ────────────────────────────────────────
                try:
                    payload = json.dumps(data).encode()
                    req = urllib.request.Request(
                        "https://api.anthropic.com/v1/messages",
                        data=payload,
                        headers={
                            "Content-Type":      "application/json",
                            "x-api-key":         ANTHROPIC_API_KEY,
                            "anthropic-version": "2023-06-01",
                        },
                        method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        self.wfile.write(resp.read())
                except urllib.error.HTTPError as e:
                    self.wfile.write(e.read())
                except Exception as e:
                    self.wfile.write(json.dumps({"error": {"message": str(e)}}).encode())
            else:
                err = json.dumps({"error": {"message": "No AI configured. Set OLLAMA_ENABLED=True or add ANTHROPIC_API_KEY in forensiq_app.py"}})
                self.wfile.write(err.encode())
        else:
            self.send_response(404); self.end_headers()

    def log_message(self,*a): pass


# ── Scanner Modal ─────────────────────────────────────────────────────────────
SCANNERS = [
    ("processes","Processes",      "Running processes & suspicious PIDs",  engine.scan_processes,    False),
    ("ports",    "Open Ports",     "Listening ports & malicious services", engine.scan_ports,        False),
    ("memory",   "Memory / CPU",   "RAM, load avg, top consumers",         engine.scan_memory,       False),
    ("users",    "User Activity",  "Login history (last/lastb/w)",         engine.scan_user_activity,False),
    ("autostart","Autostart",      "Systemd, XDG, rc.local, profile.d",   engine.scan_autostart,    False),
    ("suid",     "SUID Files",     "Privilege escalation vectors",         engine.scan_suid,         False),
    ("recent",   "Recent Changes", "Files modified in last 24 h",          engine.scan_recent_files, False),
    ("trash",    "Trash",          "GUI-deleted files",                    engine.scan_trash,        False),
    ("temp",     "Temp / Hidden",  "Scripts & hidden files in /tmp",       engine.scan_temp_hidden,  False),
    ("auth",     "Auth Log",       "SSH attacks, sudo, logins",            engine.scan_auth,         True),
    ("syslog",   "Syslog",         "System commands, kernel events",       engine.scan_syslog,       False),
    ("bash",     "Bash History",   "Terminal command history",             engine.scan_bash,         False),
    ("ufw",      "Firewall (UFW)", "Blocked/allowed connections",          engine.scan_ufw,          False),
    ("dpkg",     "Packages",       "Installed/removed software",           engine.scan_dpkg,         False),
    ("kern",     "Kernel Log",     "USB devices, drivers, hardware",       engine.scan_kern,         False),
    ("journal",  "Journal",        "Boot events, deletions, cron",         engine.scan_journal,      False),
    ("network",  "Live Network",   "Active connections via ss",            engine.scan_network_live, False),
    ("browser",  "Browser",        "Firefox & Chrome visited URLs",        engine.scan_browser,      False),
    ("cron",     "Cron Jobs",      "Scheduled tasks & cron files",         engine.scan_cron_files,   False),
]

class ScannerModal(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Scanners")
        self.setModal(True); self.setMinimumWidth(740)
        self.setStyleSheet(f"""
            QDialog{{background:{C['bg1']};color:{C['text']};}}
            QLabel{{color:{C['text']};}}
            QCheckBox{{color:{C['t2']};font-size:12.5px;spacing:8px;}}
            QCheckBox::indicator{{width:15px;height:15px;border-radius:3px;
                border:1px solid {C['line']};background:{C['bg2']};}}
            QCheckBox::indicator:checked{{background:{C['red']};border-color:{C['red']};}}
            QCheckBox:disabled{{color:{C['t3']};}}
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(24,20,24,20); root.setSpacing(0)

        hdr = QHBoxLayout()
        t = QLabel("Scanners"); t.setStyleSheet(f"font-size:17px;font-weight:700;")
        hdr.addWidget(t); hdr.addStretch()
        for label, state in (("All", True), ("None", False)):
            b = QPushButton(label); b.setFixedHeight(30)
            b.setStyleSheet(f"""QPushButton{{background:{C['bg2']};color:{C['t2']};
                border:1px solid {C['line']};border-radius:6px;padding:0 14px;font-size:12px;}}
                QPushButton:hover{{background:{C['bg3']};color:{C['text']};}}""")
            b.clicked.connect(lambda _,s=state: self._set_all(s))
            hdr.addSpacing(6); hdr.addWidget(b)
        root.addLayout(hdr); root.addSpacing(14)

        div = QFrame(); div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"color:{C['line']};"); root.addWidget(div)
        root.addSpacing(14)

        grid = QGridLayout()
        grid.setHorizontalSpacing(24); grid.setVerticalSpacing(10)
        self._cbs = {}
        for idx,(sid,label,desc,fn,needs_sudo) in enumerate(SCANNERS):
            disabled = needs_sudo and not IS_ROOT
            w = QWidget(); w.setStyleSheet('background:transparent;')
            vl = QVBoxLayout(w); vl.setContentsMargins(0,0,0,0); vl.setSpacing(1)
            cb = QCheckBox(label); cb.setChecked(not disabled); cb.setEnabled(not disabled)
            if disabled: cb.setToolTip("Requires root")
            dl = QLabel(desc + (" — requires root" if disabled else ""))
            dl.setStyleSheet(f"font-size:10.5px;color:{C['t3']};margin-left:22px;")
            vl.addWidget(cb); vl.addWidget(dl)
            grid.addWidget(w, idx//3, idx%3)
            self._cbs[sid] = cb
        root.addLayout(grid); root.addSpacing(18)

        div2 = QFrame(); div2.setFrameShape(QFrame.Shape.HLine)
        div2.setStyleSheet(f"color:{C['line']};"); root.addWidget(div2)
        root.addSpacing(14)

        foot = QHBoxLayout(); foot.addStretch()
        bc = QPushButton("Cancel"); bo = QPushButton("Run Scan")
        bc.setFixedHeight(36); bo.setFixedHeight(36)
        bc.setStyleSheet(f"""QPushButton{{background:{C['bg2']};color:{C['t2']};
            border:1px solid {C['line']};border-radius:7px;padding:0 20px;font-size:13px;}}
            QPushButton:hover{{background:{C['bg3']};color:{C['text']};}}""")
        bo.setStyleSheet(f"""QPushButton{{background:{C['red']};color:#fff;border:none;
            border-radius:7px;padding:0 24px;font-size:13px;font-weight:700;}}
            QPushButton:hover{{background:{C['redh']};}}""")
        bc.clicked.connect(self.reject); bo.clicked.connect(self.accept)
        foot.addWidget(bc); foot.addSpacing(8); foot.addWidget(bo)
        root.addLayout(foot)

    def _set_all(self, state):
        for cb in self._cbs.values():
            if cb.isEnabled(): cb.setChecked(state)

    def selected(self):
        return [sid for sid,cb in self._cbs.items() if cb.isChecked()]


# ── Main Window ───────────────────────────────────────────────────────────────
# ── Monitor Thread — real-time alerts ─────────────────────────────────────
class MonitorThread(QThread):
    """Background thread that re-scans key indicators every N seconds."""
    alert = pyqtSignal(str, str, str)  # title, message, severity

    def __init__(self, interval=60):
        super().__init__()
        self.interval   = interval
        self._stop      = False
        self._baseline  = {}  # baseline state after first scan

    def stop(self):
        self._stop = True

    def _quick_check(self):
        """Fast check: new processes, new ports, new connections."""
        alerts = []
        import subprocess, re

        # Check for new listening ports
        try:
            out = subprocess.check_output(["ss","-tlnp"], timeout=5, stderr=subprocess.DEVNULL).decode()
            ports = set()
            for line in out.splitlines()[1:]:
                m = re.search(r":(\d+)\s", line)
                if m: ports.add(int(m.group(1)))
            prev = self._baseline.get("ports", ports)
            new_ports = ports - prev
            for p in new_ports:
                sev = "CRITICAL" if p in {4444,1337,31337,9001,6666,6667} else "HIGH"
                alerts.append((f"New Port Opened: {p}", f"Port :{p} started listening", sev))
            self._baseline["ports"] = ports
        except Exception: pass

        # Check for new processes with suspicious names
        try:
            out = subprocess.check_output(["ps","aux","--no-headers"], timeout=5, stderr=subprocess.DEVNULL).decode()
            procs = set()
            suspicious = {"nc","ncat","netcat","msfconsole","meterpreter","mimikatz","beacon","cobalt"}
            for line in out.splitlines():
                parts = line.split(None, 10)
                if len(parts) > 10:
                    cmd = parts[10].split("/")[-1].split()[0].lower()
                    procs.add(cmd)
                    if cmd in suspicious:
                        alerts.append((f"Suspicious Process: {cmd}", f"Known malicious tool detected: {cmd}", "CRITICAL"))
            self._baseline["procs"] = procs
        except Exception: pass

        return alerts

    def run(self):
        import time
        # Wait for first scan before monitoring
        while not self._stop:
            if engine.REPORT_CACHE:
                break
            time.sleep(2)

        # Set baseline from first scan
        try:
            import subprocess, re
            out = subprocess.check_output(["ss","-tlnp"], timeout=5, stderr=subprocess.DEVNULL).decode()
            ports = set()
            for line in out.splitlines()[1:]:
                m = re.search(r":(\d+)\s", line)
                if m: ports.add(int(m.group(1)))
            self._baseline["ports"] = ports
        except Exception: pass

        while not self._stop:
            import time
            time.sleep(self.interval)
            if self._stop: break
            try:
                new_alerts = self._quick_check()
                for title, msg, sev in new_alerts:
                    self.alert.emit(title, msg, sev)
            except Exception: pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ForensIQ — DFIR Analyzer v3.0")
        self._icon = make_icon()
        self.setWindowIcon(self._icon)
        self.setMinimumSize(1280,800); self.resize(1520,940)
        self.thread = None
        self._sel   = [s for s,_,_,_,req in SCANNERS if not (req and not IS_ROOT)]
        self._build_ui()
        threading.Thread(target=self._start_server, daemon=True).start()
        QTimer.singleShot(400, self._load_page)
        self._setup_tray()
        self._monitor = MonitorThread(interval=60)
        self._monitor.alert.connect(self._on_alert)
        self._monitor.start()

    def _qss(self):
        return f"""
            QMainWindow,QWidget{{background:{C['bg0']};color:{C['text']};
                font-family:'Segoe UI',Ubuntu,sans-serif;font-size:13px;}}
            QPushButton#scan{{background:{C['red']};color:#fff;border:none;
                border-radius:7px;padding:9px 26px;font-size:12px;font-weight:700;
                letter-spacing:1.5px;min-width:130px;}}
            QPushButton#scan:hover{{background:{C['redh']};}}
            QPushButton#scan:disabled{{background:{C['bg3']};color:{C['t3']};}}
            QPushButton#secondary{{background:{C['bg2']};color:{C['t2']};
                border:1px solid {C['line']};border-radius:7px;padding:9px 20px;
                font-size:12px;font-weight:600;}}
            QPushButton#secondary:hover{{background:{C['bg3']};color:{C['text']};}}
            QPushButton#cancel{{background:rgba(240,96,96,.15);color:{C['red']};
                border:1px solid rgba(240,96,96,.4);border-radius:7px;
                padding:9px 18px;font-size:12px;font-weight:700;}}
            QPushButton#cancel:hover{{background:rgba(240,96,96,.28);}}
            QLabel#logo{{font-size:16px;font-weight:700;letter-spacing:5px;
                color:{C['text']};font-family:'JetBrains Mono','Courier New';}}
            QLabel#ver{{font-size:11px;color:{C['t3']};
                font-family:'Courier New';margin-left:6px;}}
            QLabel#stat{{font-size:11px;color:{C['t2']};
                font-family:'JetBrains Mono','Courier New';}}
            QProgressBar{{background:{C['bg0']};border:none;}}
            QProgressBar::chunk{{background:{C['red']};border-radius:0;}}
            QStatusBar{{background:{C['bg1']};color:{C['t3']};
                font-family:'Courier New';font-size:10px;
                border-top:1px solid {C['line']};}}
        """

    def _build_ui(self):
        self.setStyleSheet(self._qss())
        c = QWidget(); self.setCentralWidget(c)
        root = QVBoxLayout(c); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # Topbar
        bar = QWidget(); bar.setFixedHeight(54)
        bar.setStyleSheet(f"background:{C['bg1']};border-bottom:1px solid {C['line']};")
        hbar = QHBoxLayout(bar); hbar.setContentsMargins(18,0,18,0); hbar.setSpacing(0)

        il = QLabel(); il.setPixmap(self._icon.pixmap(QSize(28,28)))
        hbar.addWidget(il); hbar.addSpacing(10)
        hbar.addWidget(QLabel("FORENSIQ", objectName="logo"))
        hbar.addWidget(QLabel("/ v3.0",   objectName="ver"))
        hbar.addStretch()

        self.lbl = QLabel("ready — press RUN SCAN", objectName="stat")
        hbar.addWidget(self.lbl); hbar.addSpacing(16)

        self.btn_cancel = QPushButton("✕  CANCEL", objectName="cancel")
        self.btn_cancel.clicked.connect(self.cancel_scan)
        self.btn_cancel.hide()
        hbar.addWidget(self.btn_cancel); hbar.addSpacing(8)

        btn_sc = QPushButton("⚙  SCANNERS", objectName="secondary")
        btn_sc.clicked.connect(self._open_scanners)
        hbar.addWidget(btn_sc); hbar.addSpacing(8)

        self.btn_scan = QPushButton("▶  RUN SCAN", objectName="scan")
        self.btn_scan.clicked.connect(self.scan)
        hbar.addWidget(self.btn_scan)
        root.addWidget(bar)

        # Progress
        self.prog = QProgressBar()
        self.prog.setRange(0,100); self.prog.setValue(0)
        self.prog.setFixedHeight(3); self.prog.hide()
        root.addWidget(self.prog)

        # WebView — set bg before load, avoids white flash
        self.web = QWebEngineView()
        self.web.page().setBackgroundColor(QColor(C['bg0']))

        # Intercept external links (target=_blank, http(s)) and open in system browser
        from PyQt6.QtCore import QUrl
        def _open_external(url):
            try:
                if isinstance(url, QUrl):
                    url = url.toString()
                if url.startswith("http://") or url.startswith("https://"):
                    subprocess.Popen(["xdg-open", url],
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            except Exception: pass
        # Catch links with target="_blank" — they create a new "window"
        self.web.page().newWindowRequested.connect(
            lambda req: _open_external(req.requestedUrl())
        )
        # Also catch normal navigation that goes outside our local server
        from PyQt6.QtWebEngineCore import QWebEnginePage
        _orig_accept = self.web.page().acceptNavigationRequest
        def _accept_nav(url, nav_type, is_main_frame):
            u = url.toString() if hasattr(url, "toString") else str(url)
            if (u.startswith("http://") or u.startswith("https://")) and "localhost" not in u and "127.0.0.1" not in u:
                _open_external(u)
                return False
            return True
        self.web.page().acceptNavigationRequest = _accept_nav

        root.addWidget(self.web, 1)

        host = os.uname().nodename if hasattr(os,'uname') else 'unknown'
        self.statusBar().showMessage(
            f"  ForensIQ v3.0  ·  {host}  ·  {'root' if IS_ROOT else 'user'}  ·  port {PORT}"
        )

    def _start_server(self):
        srv = engine.http.server.HTTPServer(("localhost", PORT), Handler)
        srv.serve_forever()

    def _load_page(self):
        self.web.load(QUrl(f"http://localhost:{PORT}"))
        # No auto-scan — user presses RUN SCAN manually

    def _open_deps(self):
        DepsDialog(self).exec()

    def _open_scanners(self):
        modal = ScannerModal(self)
        for sid, cb in modal._cbs.items():
            if cb.isEnabled(): cb.setChecked(sid in self._sel)
        if modal.exec() == QDialog.DialogCode.Accepted:
            self._sel = modal.selected()
            self.scan()

    def _setup_tray(self):
        """Setup system tray icon with context menu."""
        self._tray = QSystemTrayIcon(self._icon, self)
        menu = QMenu()
        menu.addAction("Open ForensIQ", self.show)
        menu.addAction("Run Scan", self.scan)
        menu.addSeparator()
        menu.addAction("Quit", QApplication.quit)
        self._tray.setContextMenu(menu)
        self._tray.setToolTip("ForensIQ — DFIR Analyzer")
        self._tray.activated.connect(lambda r: self.show() if r == QSystemTrayIcon.ActivationReason.DoubleClick else None)
        self._tray.show()

    def _on_alert(self, title, message, severity):
        """Handle real-time alert from monitor thread."""
        # System tray notification
        icon = QSystemTrayIcon.MessageIcon.Critical if severity == "CRITICAL" else QSystemTrayIcon.MessageIcon.Warning
        self._tray.showMessage(f"ForensIQ Alert — {severity}", f"{title}\n{message}", icon, 8000)
        # In-app notification via JS
        js = f"if(typeof showAlert==='function'){{showAlert({json.dumps(title)},{json.dumps(message)},{json.dumps(severity)});}}"
        self.web.page().runJavaScript(js)

    def scan(self):
        if not self._sel:
            self.lbl.setText("no scanners selected — open ⚙ SCANNERS"); return
        self._scan_start = __import__("time").time()
        self.btn_scan.setEnabled(False); self.btn_scan.setText("⏳  SCANNING…")
        self.btn_cancel.show()
        self.prog.show(); self.prog.setValue(0)
        self.lbl.setText(f"running {len(self._sel)} scanners…")
        self.web.page().runJavaScript("if(typeof startScanTimer==='function'){startScanTimer();}")
        self.thread = ScanThread(self._sel)
        self.thread.progress.connect(self._on_progress)
        self.thread.done.connect(self._on_done)
        self.thread.start()

    def cancel_scan(self):
        if self.thread and self.thread.isRunning():
            self.thread.cancel(); self.lbl.setText("cancelling…")
            self.btn_cancel.setEnabled(False)

    def _on_progress(self, msg, cur, total):
        self.lbl.setText(msg)
        if total > 0: self.prog.setValue(int(cur/total*100))

    def _on_done(self, report):
        engine.REPORT_CACHE = report
        # Save to sessions/ dir
        try:
            os.makedirs(SESSIONS_DIR, exist_ok=True)
            s = report.get("summary", {})
            ts = s.get("scanned_at", "").replace(" ", "_").replace(":", "-")[:16] or "scan"
            host = s.get("hostname", "host").replace(" ", "_")[:20]
            fname = f"{ts}_{host}.json"
            spath = os.path.join(SESSIONS_DIR, fname)
            with open(spath, "w") as f: json.dump(report, f, indent=2)
            # Also keep legacy forensiq_report.json for compatibility
            lpath = os.path.join(USER_DATA_DIR, "forensiq_report.json")
            with open(lpath, "w") as f: json.dump(report, f, indent=2)
        except Exception: pass
        self.prog.setValue(100)
        QTimer.singleShot(500, self.prog.hide)
        self.btn_scan.setEnabled(True); self.btn_scan.setText("▶  RUN SCAN")
        self.btn_cancel.hide(); self.btn_cancel.setEnabled(True)
        s = report["summary"]; risk = report.get("risk_score",0)
        elapsed = __import__("time").time() - getattr(self, "_scan_start", __import__("time").time())
        elapsed_str = f"{int(elapsed)}s" if elapsed < 60 else f"{int(elapsed//60)}m {int(elapsed%60)}s"
        self.lbl.setText(
            f"scan done  ·  {elapsed_str}  ·  risk:{risk}  crit:{s['critical']}  high:{s['high']}  total:{s['total']}"
        )
        # Page polls /api/report automatically — just refresh it
        self.web.page().runJavaScript(
            f"if(typeof load==='function'){{_pollCount=0;load();}} "
            f"if(typeof setScanTime==='function'){{setScanTime('{elapsed_str}');}}"
        )
        self.statusBar().showMessage(
            f"  {s['scanned_at']}  ·  {s['hostname']}  ·  "
            f"risk:{risk}  crit:{s['critical']}  high:{s['high']}  med:{s['medium']}  total:{s['total']}  "
            f"· scan time: {elapsed_str}"
        )


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 11))

    # Show startup session dialog
    dlg = SessionDialog()
    dlg.setWindowIcon(make_icon())
    if dlg.exec() == QDialog.DialogCode.Rejected:
        sys.exit(0)

    w = MainWindow()
    app.setWindowIcon(w._icon)

    # Handle user choice from session dialog
    if dlg.choice in (SessionDialog.RESULT_SESSION, SessionDialog.RESULT_FILE):
        path = dlg.session_path
        try:
            with open(path) as f:
                report = json.load(f)
            engine.REPORT_CACHE = report
            s = report.get("summary", {})
            risk = report.get("risk_score", 0)
            w.lbl.setText(
                f"loaded: {os.path.basename(path)}  ·  "
                f"risk:{risk}  crit:{s.get('critical',0)}  total:{s.get('total',0)}"
            )
            w.statusBar().showMessage(
                f"  {s.get('scanned_at','')}  ·  {s.get('hostname','')}  ·  "
                f"risk:{risk}  crit:{s.get('critical',0)}  high:{s.get('high',0)}"
                f"  med:{s.get('medium',0)}  total:{s.get('total',0)}"
            )
            # Trigger dashboard refresh after page finishes loading
            def _refresh_after_load():
                w.web.page().runJavaScript("if(typeof load==='function'){load();}")
            # Page needs ~800ms to fully load before JS call works
            QTimer.singleShot(900, _refresh_after_load)
        except Exception as e:
            QMessageBox.warning(w, "Load error", f"Could not load session:\n{e}")

    w.show()

    # If user chose New Scan — auto-trigger scan after page loads
    if dlg.choice == SessionDialog.RESULT_NEW:
        def _auto_scan():
            if hasattr(w, 'scan'):
                w.scan()
        QTimer.singleShot(1200, _auto_scan)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
