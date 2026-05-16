"""
ForensIQ v3.0 — Scanning Engine
================================

Core forensic data collection and analysis engine. This module contains:

  - 19 platform-specific scanners (processes, ports, autostart, SUID,
    logins, browser history, cron, services, etc.)
  - Risk scoring algorithm
  - Correlation engine (correlate()) — builds a graph of related events
  - PDF report generator (generate_pdf())
  - Windows compatibility layer (auto-detected)

The engine populates REPORT_CACHE which is served via the HTTP API
in forensiq_app.py. All scanners are pure-Python and use only the
standard library plus optional ReportLab for PDF generation.

Author: Egor Gubarev
License: MIT
"""

#!/usr/bin/env python3
"""
ForensIQ Engine v1.0 — Full DFIR Scanner
Covers: auth, syslog, bash, ufw, dpkg, trash, journal,
        browser, USB, network, cron, services, drivers, temp/hidden files
"""

import re, os, json, gzip, glob, subprocess, http.server
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

MAX_LINES = 100000

LOG_SOURCES = {
    "auth":   ["/var/log/auth.log", "/var/log/auth.log.1"],
    "syslog": ["/var/log/syslog",   "/var/log/syslog.1"],
    "kern":   ["/var/log/kern.log"],
    "bash":   [os.path.expanduser("~/.bash_history")],
    "ufw":    ["/var/log/ufw.log",  "/var/log/ufw.log.1"],
    "dpkg":   ["/var/log/dpkg.log"],
    "apt":    ["/var/log/apt/history.log"],
    "boot":   ["/var/log/boot.log"],
    "dmesg":  ["/var/log/dmesg"],
}

MALICIOUS_PORTS = {4444,1337,31337,9001,6666,6667,4545,5555,7777,8888,9999,2222}

# ── Global state ──────────────────────────────────────────────
findings       = []
ip_fail        = defaultdict(int)
hourly         = defaultdict(int)
cats           = defaultdict(int)
deleted_files  = []
network_events = []
usb_events     = []
browser_events = []
cron_events    = []
service_events = []
driver_events  = []
boot_events    = []
login_events   = []
REPORT_CACHE   = {}

# ── Detection rules ───────────────────────────────────────────

AUTH_RULES = [
    # Failed logins from network = HIGH, but lowered automatically if single attempt by calibration
    (r"Failed password for(?: invalid user)? (\S+) from ([\d\.]+)", "HIGH",   "Failed SSH login",                           "failed_login"),
    (r"Invalid user (\S+) from ([\d\.]+)",                          "HIGH",   "SSH attempt — unknown username",             "failed_login"),
    (r"Accepted (password|publickey) for (\S+) from ([\d\.]+)",     "INFO",   "Successful SSH login",                       "login"),
    # Local sessions / sudo — INFO, normal activity
    (r"session opened for user (\S+)",                              "INFO",   "User session opened",                        "login"),
    (r"session closed for user (\S+)",                              "INFO",   "User session closed",                        "logout"),
    (r"sudo:.*authentication failure",                              "MEDIUM", "Failed sudo authentication",                 "failed_login"),
    (r"sudo:.*COMMAND=(.*)",                                        "INFO",   "Sudo command executed",                      "privilege"),
    # User account changes — MEDIUM not CRITICAL (apt installs trigger usermod)
    (r"\buseradd\b",                                                "MEDIUM", "User account added",                         "persistence"),
    (r"\busermod\b",                                                "LOW",    "User account modified",                      "persistence"),
    (r"\buserdel\b",                                                "MEDIUM", "User account deleted",                       "persistence"),
    # Direct root login (NOT sudo) — actually serious
    (r"ROOT LOGIN",                                                 "HIGH",   "Direct root login",                          "privilege"),
    (r"session opened for user root by \(uid=0\)",                  "INFO",   "Root session (sudo)",                        "privilege"),
    (r"pam_unix.*password.*changed",                                "MEDIUM", "Password changed",                           "persistence"),
    (r"new group.*name=(\S+)",                                      "LOW",    "New group created",                          "persistence"),
]

SYSLOG_RULES = [
    # Real reverse shell patterns
    (r"nc\s+.*-e\s+|\bncat\s+.*--exec",                           "CRITICAL", "NetCat reverse shell signature",             "backdoor"),
    (r"/dev/tcp/|/dev/udp/",                                        "CRITICAL", "Bash reverse shell signature",               "backdoor"),
    # Downloads — only flag if going to /tmp or executing inline
    (r"(curl|wget).*\|\s*(sh|bash)",                                "CRITICAL", "Remote code via pipe to shell",              "execution"),
    (r"(curl|wget).*-o\s*/tmp/|(curl|wget).*-O\s*/tmp/",            "HIGH",     "Download to /tmp/",                          "download"),
    # SUID bit — only flag explicit setuid root, not regular chmod
    (r"chmod\s+[47]7[57]\s|chmod\s+u\+s",                          "HIGH",     "SUID bit set",                               "privilege"),
    # Cron — only modification
    (r"crontab\s+-e\s",                                             "LOW",      "Crontab edited",                             "cron"),
    # /etc/passwd or /etc/shadow write attempts
    (r"audit.*name=\"/etc/(passwd|shadow)\".*succ=yes",              "HIGH",     "Credentials file modified",                  "credential"),
    (r"base64\s+-d|base64\s+--decode",                             "HIGH",     "Base64 decode — encoded payload",            "execution"),
    (r"iptables\s+-F|ufw\s+disable|ufw\s+reset",                   "CRITICAL", "Firewall disabled/flushed",                  "defense_evasion"),
    (r"systemctl\s+(stop|disable)\s+(ufw|apparmor|auditd|fail2ban)","CRITICAL", "Security service disabled",                 "defense_evasion"),
    (r"systemctl\s+(enable|start)\s+(\S+)",                        "MEDIUM",   "Service enabled/started",                   "service"),
    (r"systemctl\s+(disable|stop)\s+(\S+)",                        "MEDIUM",   "Service disabled/stopped",                  "service"),
    (r"insmod|modprobe\s+",                                        "HIGH",     "Kernel module loaded",                       "driver"),
    (r"rmmod\s+",                                                   "HIGH",     "Kernel module removed",                      "driver"),
    (r"python.*-c.*exec|python.*eval|perl.*-e",                    "MEDIUM",   "Inline code execution",                      "execution"),
    (r"shred\s+|wipe\s+|srm\s+",                                   "HIGH",     "Secure file deletion tool",                  "deleted_files"),
    (r"rm\s+.*-[rf]{1,2}|rm\s+-[rf]{1,2}",                        "MEDIUM",   "File deletion command in syslog",            "deleted_files"),
]

# BASH_HISTORY is HISTORICAL data — we don't know WHEN these commands ran.
# A 5-year-old `curl ... | sh` is not an active threat. Severity capped at MEDIUM/LOW.
BASH_RULES = [
    # Reverse shells in history — MEDIUM (could be old training, could be incident)
    (r"\bnc\s+.*-e\s",                                            "MEDIUM",  "NetCat reverse shell in history",          "backdoor"),
    (r"/dev/tcp/|/dev/udp/",                                        "MEDIUM",  "Bash reverse shell in history",            "backdoor"),
    (r"bash\s+-i.*>&|bash\s+-i.*>.*2>&",                           "MEDIUM",  "Bash reverse shell one-liner in history",  "backdoor"),
    # Pipe-to-shell installs (curl ... | sh) — LOW. Common for legit installers (Ollama, rustup, etc.)
    (r"curl.*\|\s*bash|wget.*\|\s*bash|curl.*\|\s*sh",             "LOW",     "Pipe-to-shell install in history",         "execution"),
    # Defense evasion — MEDIUM
    (r"history\s+-c\b|unset\s+HISTFILE\b|export\s+HISTSIZE=0\b",  "MEDIUM",  "Shell history cleared command",            "defense_evasion"),
    # Reading shadow / private keys — MEDIUM
    (r"cat\s+/etc/shadow\b|cat\s+.*id_rsa\b",                     "MEDIUM",  "Sensitive credential file accessed",       "credential"),
    # Cracking tools — LOW, often used in CTFs / training
    (r"\bhydra\b|\bmedusa\b|\bhashcat\b",                         "LOW",     "Password cracking tool in history",        "credential"),
    # Direct disk write — MEDIUM
    (r"\bdd\s+if=.*of=/dev/(sd|nvme|hd)",                          "MEDIUM",  "Direct disk write in history",             "impact"),
]

UFW_RULES = [
    # Only flag attempts on known-malicious backdoor ports
    (r"\[UFW BLOCK\].*DPT=4444",   "MEDIUM",   "Blocked Metasploit port 4444",    "network"),
    (r"\[UFW BLOCK\].*DPT=1337",   "MEDIUM",   "Blocked backdoor port 1337",      "network"),
    (r"\[UFW BLOCK\].*DPT=31337",  "MEDIUM",   "Blocked elite backdoor 31337",    "network"),
    # Normal UFW BLOCK on SSH/RDP from internet = noise, not flagged
    # Allowed traffic = not flagged at all
]

DPKG_RULES = [
    # Security tools removed — actual threat
    (r"\bremove\s+(ufw|apparmor|auditd|fail2ban|clamav)\b", "HIGH", "Security tool removed",          "defense_evasion"),
    # Offensive tools installed — worth noting but not HIGH
    (r"\binstall\s+(metasploit|cobaltstrike|empire|mimikatz)\b", "MEDIUM", "Known offensive tool installed", "execution"),
    # Normal package management = not flagged
    (r"install\s+(\S+)",           "INFO",     "Package installed",               "software"),
    (r"upgrade\s+(\S+)",           "INFO",     "Package upgraded",                "software"),
]

KERN_RULES = [
    (r"usb.*connect|usb.*new.*device|usb.*attached|New USB device found",          "INFO",   "USB device connected",           "usb"),
    (r"usb.*disconnect|usb.*removed",                                               "INFO",   "USB device disconnected",        "usb"),
    # Disk errors — keep MEDIUM, real concern but not critical
    (r"sd[a-z]\d*:.*sector|I/O error",                                             "MEDIUM", "Disk I/O error",                 "hardware"),
    # OOM is common on dev machines — LOW
    (r"Out of memory|OOM killer",                                                   "LOW",    "Out of memory event",            "system"),
    # Segfault — informational
    (r"kernel: \[\s*\d+\.\d+\] (\S+)\s+\[(\d+)\].*segfault",                      "LOW",    "Process segfault",               "system"),
    (r"ACPI|firmware|microcode",                                                    "INFO",   "Firmware/microcode event",       "driver"),
    (r"nouveau|radeon|i915|amdgpu|nvidia",                                         "INFO",   "GPU driver event",               "driver"),
    # Module loading at boot is normal — INFO not MEDIUM
    (r"loaded module|module.*loaded|modprobe",                                      "INFO",   "Kernel module loaded",           "driver"),
]

# ── Helpers ───────────────────────────────────────────────────

def read_log(filepath):
    p = Path(filepath)
    try:
        if not p.exists() or not p.is_file():
            return []
    except (PermissionError, OSError):
        return []
    try:
        op = gzip.open if str(filepath).endswith(".gz") else open
        with op(str(filepath), "rt", errors="ignore") as f:
            return f.readlines()[-MAX_LINES:]
    except (PermissionError, OSError):
        return []
    except Exception:
        return []

def tstamp(line):
    m = re.match(r"(\w{3}\s+\d+\s+\d+:\d+:\d+)", line)
    return m.group(1) if m else ""

def run_cmd(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""

# ── Severity calibration ─────────────────────────────────────
# Patterns that match common system noise — auto-downgrade severity
# to reduce false positives that inflate the risk score
KNOWN_BENIGN_PATTERNS = [
    # System users/services
    (r"\b(systemd|systemd-\w+|dbus-daemon|pulseaudio|gnome-shell|gdm|NetworkManager)\b", "INFO"),
    # System package managers
    (r"\b(apt|dpkg|snap|flatpak|unattended-upgrade)\b", "INFO"),
    # System cron jobs
    (r"/etc/cron\.(daily|weekly|monthly|hourly)/", "LOW"),
    # Logrotate / backup
    (r"logrotate|anacron", "INFO"),
    # Normal SUID system binaries
    (r"/usr/bin/(sudo|su|passwd|chsh|chfn|gpasswd|newgrp|mount|umount|ping|fusermount)\b", "INFO"),
    (r"/usr/bin/(pkexec|polkit-agent-helper)", "INFO"),
    # Sessions ending normally
    (r"session opened|session closed", "INFO"),
    # Just a tab/typo on password prompt
    (r"authentication failure.*tty=tty\d", "LOW"),
]

# Known malicious indicators — always escalate
KNOWN_MALICIOUS_PATTERNS = [
    (r"\b(meterpreter|metasploit|empire|cobaltstrike|beacon|mimikatz)\b", "CRITICAL"),
    (r"\b(nc|ncat|netcat)\s+.*-e\b", "CRITICAL"),
    (r"reverse[\s_-]?shell|bind[\s_-]?shell", "CRITICAL"),
    (r"/dev/tcp/", "CRITICAL"),
    (r"chmod\s+\+s|setuid\(0\)", "HIGH"),
]


def _calibrate_severity(sev, desc, detail, src, time_str=""):
    """Auto-adjust severity based on context. Returns new severity."""
    text = (desc + " " + detail + " " + str(src)).lower()
    # Check malicious first (escalate)
    for pat, esc_sev in KNOWN_MALICIOUS_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            ord_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "LOW": 4}
            if ord_map.get(esc_sev, 4) < ord_map.get(sev, 4):
                return esc_sev
            return sev
    # Then check benign (downgrade)
    for pat, new_sev in KNOWN_BENIGN_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            ord_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "LOW": 4}
            if ord_map.get(new_sev, 4) > ord_map.get(sev, 4):
                return new_sev

    # Time-based downgrade: events older than 7 days are mostly historical, not active threats
    if time_str:
        try:
            # Parse "Mon Day HH:MM:SS" format from syslog
            m = re.match(r"(\w{3})\s+(\d+)\s+(\d+):(\d+):", time_str)
            if m:
                from datetime import datetime as _dt
                now = _dt.now()
                month_map = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}
                event_month = month_map.get(m.group(1), now.month)
                event_day   = int(m.group(2))
                # Approximate year (syslog usually has no year — use current year)
                event_year = now.year
                # If month is in the future, assume previous year
                if event_month > now.month:
                    event_year -= 1
                try:
                    event_dt = _dt(event_year, event_month, event_day, int(m.group(3)), int(m.group(4)))
                    age_days = (now - event_dt).days
                    # Downgrade old events
                    if age_days > 7:
                        ord_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "LOW": 4}
                        # Old CRITICAL → MEDIUM, old HIGH → LOW, etc.
                        if sev == "CRITICAL": return "MEDIUM"
                        if sev == "HIGH":     return "LOW"
                        if sev == "MEDIUM":   return "INFO"
                except: pass
        except: pass
    return sev


def rec(sev, cat, t, desc, detail, src, extra=None):
    """Record a finding with optional extra fields for detail panel."""
    # Auto-calibrate severity based on context and time
    sev = _calibrate_severity(sev, desc, detail, src, t)
    entry = {
        "severity":    sev,
        "category":    cat,
        "time":        t,
        "description": desc,
        "detail":      detail.strip()[:300],
        "source":      os.path.basename(str(src)),
        "raw":         detail.strip()[:500],
    }
    if extra:
        entry.update(extra)
    findings.append(entry)
    cats[cat] += 1
    m = re.search(r"(\d+):\d+:\d+", t)
    if m:
        hourly[int(m.group(1))] += 1

# ── Scanners ──────────────────────────────────────────────────

def scan_auth():
    print("  [*] auth.log ...", end=" ", flush=True); n = 0
    for filepath in LOG_SOURCES["auth"]:
        for line in read_log(filepath):
            for pat, sev, desc, cat in AUTH_RULES:
                m = re.search(pat, line, re.IGNORECASE)
                if m:
                    extra = {}
                    ip_m = re.search(r"from ([\d\.]+)", line)
                    user_m = re.search(r"for (?:invalid user )?(\S+) from", line)
                    if ip_m:
                        extra["src_ip"] = ip_m.group(1)
                        if "Failed" in line or "Invalid" in line:
                            ip_fail[ip_m.group(1)] += 1
                    if user_m:
                        extra["username"] = user_m.group(1)
                    rec(sev, cat, tstamp(line), desc, line, filepath, extra)
                    n += 1
                    # Track login/logout for dedicated section
                    if cat in ("login", "logout"):
                        login_events.append({
                            "time": tstamp(line),
                            "type": cat,
                            "user": extra.get("username", "—"),
                            "ip":   extra.get("src_ip", "local"),
                            "raw":  line.strip()[:150],
                        })
                    break
    # Brute force escalation
    for ip, c in ip_fail.items():
        if c >= 5:
            sev = "CRITICAL" if c >= 10 else "HIGH"
            rec(sev, "brute_force",
                datetime.now().strftime("%b %d %H:%M:%S"),
                f"Brute force attack — {c} failed attempts",
                f"Source IP: {ip} | {c} failed logins", "auth.log",
                {"src_ip": ip, "attempts": c})
            n += 1
    print(f"{n} findings")

def scan_syslog():
    print("  [*] syslog ...", end=" ", flush=True); n = 0
    for filepath in LOG_SOURCES["syslog"]:
        for line in read_log(filepath):
            for pat, sev, desc, cat in SYSLOG_RULES:
                if re.search(pat, line, re.IGNORECASE):
                    rec(sev, cat, tstamp(line), desc, line, filepath)
                    n += 1
                    if cat == "service":
                        svc_m = re.search(r"systemctl\s+\S+\s+(\S+)", line, re.IGNORECASE)
                        service_events.append({
                            "time":    tstamp(line),
                            "action":  "enable/start" if "enable" in line or "start" in line else "stop/disable",
                            "service": svc_m.group(1) if svc_m else "unknown",
                            "raw":     line.strip()[:150],
                        })
                    if cat == "driver":
                        driver_events.append({"time": tstamp(line), "raw": line.strip()[:150]})
                    break
    print(f"{n} findings")

def scan_bash():
    print("  [*] bash_history ...", end=" ", flush=True); n = 0
    for filepath in LOG_SOURCES["bash"]:
        for i, line in enumerate(read_log(filepath)):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for pat, sev, desc, cat in BASH_RULES:
                if re.search(pat, line, re.IGNORECASE):
                    rec(sev, cat, f"line {i+1}", desc, line, filepath)
                    n += 1
                    if cat == "deleted_files":
                        deleted_files.append({
                            "time":        f"history line {i+1}",
                            "method":      "terminal (rm/shred)",
                            "command":     line[:200],
                            "source":      "bash_history",
                            "recoverable": "possible" if "shred" not in line else "unlikely",
                        })
                    if cat == "cron":
                        cron_events.append({"time": f"line {i+1}", "raw": line[:150], "source": "bash_history"})
                    break
    print(f"{n} findings")

def scan_ufw():
    print("  [*] ufw.log ...", end=" ", flush=True); n = 0
    for filepath in LOG_SOURCES["ufw"]:
        for line in read_log(filepath):
            for pat, sev, desc, cat in UFW_RULES:
                if re.search(pat, line, re.IGNORECASE):
                    src_m = re.search(r"SRC=([\d\.]+)", line)
                    dst_m = re.search(r"DST=([\d\.]+)", line)
                    dpt_m = re.search(r"DPT=(\d+)", line)
                    spt_m = re.search(r"SPT=(\d+)", line)
                    proto_m = re.search(r"PROTO=(\S+)", line)
                    port = int(dpt_m.group(1)) if dpt_m else 0
                    extra = {
                        "src_ip":   src_m.group(1) if src_m else "—",
                        "dst_ip":   dst_m.group(1) if dst_m else "—",
                        "dst_port": port,
                        "src_port": int(spt_m.group(1)) if spt_m else 0,
                        "proto":    proto_m.group(1) if proto_m else "—",
                        "action":   "BLOCK" if "BLOCK" in line else "ALLOW",
                        "suspicious": port in MALICIOUS_PORTS,
                    }
                    rec(sev, cat, tstamp(line), desc, line, filepath, extra)
                    n += 1
                    network_events.append({"time": tstamp(line), **extra, "raw": line.strip()[:200]})
                    break
    print(f"{n} findings")

def scan_dpkg():
    print("  [*] dpkg.log ...", end=" ", flush=True); n = 0
    for filepath in [*LOG_SOURCES["dpkg"], *LOG_SOURCES["apt"]]:
        for line in read_log(filepath):
            for pat, sev, desc, cat in DPKG_RULES:
                if re.search(pat, line, re.IGNORECASE):
                    pkg_m = re.search(r"(?:remove|purge|install|upgrade)\s+(\S+)", line, re.IGNORECASE)
                    pkg = pkg_m.group(1) if pkg_m else "unknown"
                    action = "remove" if "remove" in line.lower() else "purge" if "purge" in line.lower() else "install"
                    rec(sev, cat, tstamp(line), desc, line, filepath, {"package": pkg, "action": action})
                    n += 1
                    if action in ("remove", "purge"):
                        deleted_files.append({
                            "time":        tstamp(line),
                            "method":      f"package {action}",
                            "command":     line.strip()[:150],
                            "package":     pkg,
                            "source":      "dpkg.log",
                            "recoverable": "yes",
                            "recover_cmd": f"sudo apt install {pkg}",
                        })
                    break
    print(f"{n} findings")

def scan_kern():
    print("  [*] kern.log ...", end=" ", flush=True); n = 0
    for filepath in LOG_SOURCES["kern"]:
        for line in read_log(filepath):
            for pat, sev, desc, cat in KERN_RULES:
                if re.search(pat, line, re.IGNORECASE):
                    rec(sev, cat, tstamp(line), desc, line, filepath)
                    n += 1
                    if cat == "usb":
                        dev_m = re.search(r"Product:\s*(.+)|Manufacturer:\s*(.+)|idProduct=(\w+)", line)
                        usb_events.append({
                            "time":   tstamp(line),
                            "action": "connected" if any(w in line.lower() for w in ["connect", "new", "attach", "found"]) else "disconnected",
                            "device": dev_m.group(0) if dev_m else "unknown device",
                            "raw":    line.strip()[:150],
                        })
                    if cat == "driver":
                        driver_events.append({"time": tstamp(line), "raw": line.strip()[:150]})
                    break
    print(f"{n} findings")

def scan_trash():
    """
    Scan Trash directories for GUI-deleted files.
    Linux Trash: ~/.local/share/Trash/
    Each deleted file has a .trashinfo with original path + date.
    """
    print("  [*] Trash (GUI deleted) ...", end=" ", flush=True); n = 0

    trash_dirs = [
        os.path.expanduser("~/.local/share/Trash/info"),
        "/root/.local/share/Trash/info",
    ]
    # Also check other users
    for user_home in glob.glob("/home/*"):
        trash_dirs.append(os.path.join(user_home, ".local/share/Trash/info"))

    for trash_info_dir in trash_dirs:
        try:
            p = Path(trash_info_dir)
            if not p.exists():
                continue
            info_files = list(p.glob("*.trashinfo"))
        except PermissionError:
            continue
        except Exception:
            continue
        for info_file in info_files:
            try:
                content = info_file.read_text(errors="ignore")
                path_m = re.search(r"Path=(.+)", content)
                date_m = re.search(r"DeletionDate=(.+)", content)
                orig_path = path_m.group(1).strip() if path_m else "unknown"
                del_date  = date_m.group(1).strip() if date_m else "unknown"

                # File is in trash = recoverable (not permanent delete)
                deleted_files.append({
                    "time":        del_date,
                    "method":      "GUI delete (moved to Trash)",
                    "command":     f"Deleted: {orig_path}",
                    "source":      "Trash",
                    "original_path": orig_path,
                    "recoverable": "yes — still in Trash",
                    "recover_cmd": f"restore-trash  OR  mv ~/.local/share/Trash/files/{info_file.stem} {orig_path}",
                })
                rec("INFO", "deleted_files", del_date,
                    f"File moved to Trash: {os.path.basename(orig_path)}",
                    f"Original path: {orig_path}", "Trash",
                    {"original_path": orig_path, "del_date": del_date})
                n += 1
            except Exception:
                continue

    print(f"{n} files in trash")

def scan_journal():
    """Use journalctl to find file deletions, boot events, service changes."""
    print("  [*] journalctl ...", end=" ", flush=True); n = 0
    try:
        out = run_cmd(["journalctl", "-n", "10000", "--no-pager", "-q"], timeout=15)
        for line in out.splitlines():
            # Boot events
            if re.search(r"Started.*Graphical|Reached target.*network|kernel:.*Booting", line, re.IGNORECASE):
                boot_events.append({"time": tstamp(line), "event": line.strip()[:120]})
                rec("INFO", "boot", tstamp(line), "System boot event", line, "journal")
                n += 1
            # New devices
            elif re.search(r"New device found|device added|driver loaded", line, re.IGNORECASE):
                driver_events.append({"time": tstamp(line), "raw": line.strip()[:150]})
                rec("INFO", "driver", tstamp(line), "New device/driver loaded", line, "journal")
                n += 1
            # Cron jobs
            elif re.search(r"CRON\[|crond\[|cron.*CMD", line, re.IGNORECASE):
                cron_events.append({"time": tstamp(line), "raw": line.strip()[:150], "source": "journal"})
                rec("INFO", "cron", tstamp(line), "Cron job executed", line, "journal")
                n += 1
            # File deletion via audit
            elif re.search(r"SYSCALL.*unlink|type=PATH.*inode.*DELETE", line, re.IGNORECASE):
                deleted_files.append({
                    "time":        tstamp(line),
                    "method":      "kernel audit (unlink syscall)",
                    "command":     line.strip()[:200],
                    "source":      "journalctl",
                    "recoverable": "possible with extundelete",
                    "recover_cmd": "sudo extundelete /dev/sda1 --restore-all",
                })
                rec("MEDIUM", "deleted_files", tstamp(line), "File deleted (kernel audit)", line, "journal")
                n += 1
    except Exception:
        pass
    print(f"{n} findings")

def scan_temp_hidden():
    """Scan for suspicious temp files, hidden files, archives in odd places."""
    print("  [*] temp/hidden/archives ...", end=" ", flush=True); n = 0

    suspicious_locations = [
        "/tmp", "/var/tmp", "/dev/shm",
        os.path.expanduser("~"),
        os.path.expanduser("~/Downloads"),
    ]

    suspicious_extensions = {".sh", ".py", ".pl", ".rb", ".elf", ".out", ".bin"}
    archive_extensions    = {".zip", ".tar", ".gz", ".7z", ".rar", ".tgz"}

    for base_dir in suspicious_locations:
        base = Path(base_dir)
        if not base.exists():
            continue
        try:
            for item in base.iterdir():
                name = item.name
                suf  = item.suffix.lower()

                # Hidden files (start with .) in /tmp or /dev/shm = suspicious
                if name.startswith(".") and base_dir in ("/tmp", "/var/tmp", "/dev/shm"):
                    rec("HIGH", "temp_artifacts",
                        datetime.fromtimestamp(item.stat().st_mtime).strftime("%b %d %H:%M:%S"),
                        f"Hidden file in suspicious location: {base_dir}/{name}",
                        f"Path: {item}", "filesystem",
                        {"file_path": str(item), "size": item.stat().st_size})
                    n += 1

                # Executable scripts in /tmp
                elif suf in suspicious_extensions and base_dir in ("/tmp", "/var/tmp", "/dev/shm"):
                    rec("CRITICAL", "temp_artifacts",
                        datetime.fromtimestamp(item.stat().st_mtime).strftime("%b %d %H:%M:%S"),
                        f"Executable script in temp: {name}",
                        f"Path: {item}", "filesystem",
                        {"file_path": str(item), "size": item.stat().st_size})
                    n += 1

                # Archives are NORMAL in Downloads — no longer flagged
        except PermissionError:
            pass
        except Exception:
            pass

    print(f"{n} findings")

def scan_browser():
    """Scan browser history for suspicious downloads and activity."""
    print("  [*] browser history ...", end=" ", flush=True); n = 0

    # Firefox history
    ff_profiles = glob.glob(os.path.expanduser("~/.mozilla/firefox/*.default*/places.sqlite"))
    ff_profiles += glob.glob("/root/.mozilla/firefox/*.default*/places.sqlite")

    for db in ff_profiles:
        try:
            import shutil, tempfile, sqlite3
            tmp = tempfile.mktemp(suffix=".sqlite")
            shutil.copy2(db, tmp)
            conn = sqlite3.connect(tmp)
            rows = conn.execute(
                "SELECT url, title, visit_date/1000000 as ts FROM moz_places "
                "JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id "
                "ORDER BY visit_date DESC LIMIT 500"
            ).fetchall()
            conn.close()
            os.unlink(tmp)
            for url, title, ts in rows:
                if not url:
                    continue
                t = datetime.fromtimestamp(ts).strftime("%b %d %H:%M:%S") if ts else "—"
                browser_events.append({"time": t, "browser": "Firefox", "url": url[:200], "title": title or "—"})
                # Flag suspicious URLs
                # Only flag truly suspicious patterns — raw pastebin, ngrok tunnels, known malware hosts
                if re.search(r"pastebin\.com/raw/|"
                             r"ngrok\.io|ngrok-free|"
                             r"discord\.com/api/webhooks|"
                             r"transfer\.sh|"
                             r"anonfiles\.com|file\.io|"
                             r"\.onion\b",
                             url, re.IGNORECASE):
                    rec("HIGH", "download", t,
                        f"Suspicious URL in Firefox history",
                        url, "firefox_history",
                        {"url": url, "browser": "Firefox"})
                    n += 1
        except Exception:
            pass

    # Chromium/Chrome history
    chrome_dbs = glob.glob(os.path.expanduser("~/.config/chromium/*/History"))
    chrome_dbs += glob.glob(os.path.expanduser("~/.config/google-chrome/*/History"))
    chrome_dbs += glob.glob("/root/.config/chromium/*/History")

    for db in chrome_dbs:
        try:
            import shutil, tempfile, sqlite3
            tmp = tempfile.mktemp(suffix=".sqlite")
            shutil.copy2(db, tmp)
            conn = sqlite3.connect(tmp)
            rows = conn.execute(
                "SELECT url, title, last_visit_time/1000000 as ts FROM urls "
                "ORDER BY last_visit_time DESC LIMIT 500"
            ).fetchall()
            conn.close()
            os.unlink(tmp)
            for url, title, ts in rows:
                if not url:
                    continue
                t = datetime.fromtimestamp(max(0, ts - 11644473600)).strftime("%b %d %H:%M:%S") if ts else "—"
                browser_events.append({"time": t, "browser": "Chrome/Chromium", "url": url[:200], "title": title or "—"})
                if re.search(r"pastebin\.com/raw/|"
                             r"ngrok\.io|ngrok-free|"
                             r"discord\.com/api/webhooks|"
                             r"transfer\.sh|"
                             r"anonfiles\.com|file\.io|"
                             r"\.onion\b",
                             url, re.IGNORECASE):
                    rec("HIGH", "download", t,
                        "Suspicious URL in Chrome history",
                        url, "chrome_history",
                        {"url": url, "browser": "Chrome"})
                    n += 1
        except Exception:
            pass

    print(f"{n} suspicious URLs found ({len(browser_events)} total visits)")

def scan_network_live():
    """Live network scan — active connections via ss."""
    print("  [*] live network (ss) ...", end=" ", flush=True); n = 0
    out = run_cmd(["ss", "-tnp"])
    for line in out.splitlines()[1:]:   # Skip header
        parts = line.split()
        if len(parts) < 5:
            continue
        # Extract remote address:port
        remote = parts[4] if len(parts) > 4 else ""
        port_m = re.search(r":(\d+)$", remote)
        if port_m:
            port = int(port_m.group(1))
            ip_m = re.match(r"([\d\.]+):\d+$", remote)
            ip = ip_m.group(1) if ip_m else remote
            if port in MALICIOUS_PORTS:
                rec("CRITICAL", "network",
                    datetime.now().strftime("%b %d %H:%M:%S"),
                    f"LIVE connection to malicious port {port}",
                    line.strip(), "ss",
                    {"dst_ip": ip, "dst_port": port, "action": "ACTIVE", "suspicious": True})
                n += 1
            network_events.append({
                "time":       datetime.now().strftime("%H:%M:%S"),
                "src_ip":     "localhost",
                "dst_ip":     ip,
                "dst_port":   port,
                "action":     "ACTIVE",
                "suspicious": port in MALICIOUS_PORTS,
                "raw":        line.strip()[:150],
            })
    print(f"{n} suspicious live connections")

def scan_cron_files():
    """Directly check cron files for scheduled tasks."""
    print("  [*] cron files ...", end=" ", flush=True); n = 0
    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
    ]
    for cp in cron_paths:
        try:
            p = Path(cp)
            if p.is_file():
                for line in read_log(str(p)):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        cron_events.append({"time": "static", "raw": line[:150], "source": cp})
                        # Only flag truly malicious patterns
                        if re.search(r"(bash|sh)\s+-i\s*[<>]&|/dev/tcp/|nc\s+.*-e|"
                                     r"/tmp/\.[a-z]|/dev/shm/\.|"
                                     r"base64\s+-d.*\|.*sh|"
                                     r"python.*socket.*connect.*exec",
                                     line, re.I):
                            rec("CRITICAL", "cron", "static", "Malicious cron entry", line, cp)
                            n += 1
                        # Normal cron entries are NOT flagged anymore — just stored
            elif p.is_dir():
                try:
                    files = list(p.iterdir())
                except (PermissionError, OSError):
                    continue
                for f in files:
                    try:
                        for line in read_log(str(f)):
                            line = line.strip()
                            if line and not line.startswith("#"):
                                cron_events.append({"time": "static", "raw": line[:150], "source": str(f)})
                                if re.search(r"(bash|sh)\s+-i\s*[<>]&|/dev/tcp/|nc\s+.*-e|"
                                             r"/tmp/\.[a-z]|/dev/shm/\.|"
                                             r"base64\s+-d.*\|.*sh",
                                             line, re.I):
                                    rec("CRITICAL", "cron", "static", "Malicious cron entry", line, f)
                                    n += 1
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError):
            continue
    print(f"{n} cron findings")

# ── Report builder ────────────────────────────────────────────

def build_report():
    so = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "LOW": 4}

    # Deduplicate network events
    seen = set()
    unique_net = []
    for e in network_events:
        key = f"{e.get('src_ip')}:{e.get('dst_ip')}:{e.get('dst_port')}:{e.get('action')}"
        if key not in seen:
            seen.add(key)
            unique_net.append(e)

    return {
        "summary": {
            "critical":   sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high":       sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium":     sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "info":       sum(1 for f in findings if f["severity"] == "INFO"),
            "total":      len(findings),
            "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname":   os.uname().nodename,
        },
        # NO CAP — send all findings so filter works correctly
        "findings":        sorted(findings, key=lambda x: so.get(x["severity"], 4)),
        "chart_hourly":    [hourly.get(h, 0) for h in range(24)],
        "chart_categories": dict(cats),
        "top_ips":         [{"ip": ip, "count": c} for ip, c in
                            sorted(ip_fail.items(), key=lambda x: x[1], reverse=True)[:10]],
        "network_events":  unique_net[:200],
        "deleted_files":   deleted_files[:200],
        "usb_events":      usb_events[:50],
        "browser_events":  browser_events[:200],
        "cron_events":     cron_events[:100],
        "service_events":  service_events[:100],
        "driver_events":   driver_events[:100],
        "boot_events":     boot_events[:50],
        "login_events":    login_events[:200],
    }

def clear_state():
    """Reset all global state before a new scan."""
    global findings, ip_fail, hourly, cats, deleted_files, network_events
    global usb_events, browser_events, cron_events, service_events, driver_events
    global boot_events, login_events
    findings.clear(); ip_fail.clear(); hourly.clear(); cats.clear()
    deleted_files.clear(); network_events.clear(); usb_events.clear()
    browser_events.clear(); cron_events.clear(); service_events.clear()
    driver_events.clear(); boot_events.clear(); login_events.clear()

def run_all():
    if IS_WINDOWS:
        return run_windows_scan()
    clear_state()
    scan_auth()
    scan_syslog()
    scan_bash()
    scan_ufw()
    scan_dpkg()
    scan_kern()
    scan_trash()
    scan_journal()
    scan_temp_hidden()
    scan_browser()
    scan_network_live()
    scan_cron_files()
    return build_report()

# ═══════════════════════════════════════════════════════════════
# NEW SCANNERS v1.0
# ═══════════════════════════════════════════════════════════════

# New global state
processes    = []
open_ports   = []
autostart    = []
suid_files   = []
recent_files = []
memory_info  = {}
top_procs    = []
user_activity= []

def scan_processes():
    """Snapshot processes. Flag ONLY real threats — no false positives."""
    print("  [*] processes ...", end=" ", flush=True); n = 0
    global processes, top_procs
    processes.clear(); top_procs.clear()

    out = run_cmd(["ps", "aux", "--no-headers", "--sort=-%cpu"])

    # ── REAL malicious tool names — full word match ──────────
    MALICIOUS_TOOLS = re.compile(
        r"(?:^|/|\s)(meterpreter|msfconsole|mimikatz|cobaltstrike|"
        r"empire|powersploit|sliver|havoc)(?:\s|$)",
        re.I
    )
    # ── Active reverse shell signatures ──────────────────────
    RSHELL = re.compile(
        r"bash\s+-i\s*[<>]&\s*/dev/tcp|"        # bash -i >& /dev/tcp/...
        r"/dev/tcp/\d|"                            # /dev/tcp/IP
        r"\bnc\s+[^|]*\s-e\s|"                  # nc -e (only with the -e flag)
        r"ncat\s+[^|]*--exec\s|"
        r"python[\d]?\s+-c\s+.*socket.*exec",
        re.I
    )
    # ── ACTUAL suspicious execution locations ────────────────
    # /tmp/, /dev/shm/, /var/tmp/ — yes
    # /run/user/X/ — NO, this is normal systemd runtime
    SUS_EXEC = re.compile(
        r"(?:^|\s)(/tmp/[^/\s][^\s]*|/dev/shm/[^/\s][^\s]*|/var/tmp/[^/\s][^\s]*)"
        r"(?:\s|$)",
        re.I
    )
    # Whitelist for common /tmp usage that is fine
    SUS_EXEC_OK = re.compile(
        r"/tmp/\.X11-unix|/tmp/\.ICE-unix|/tmp/snap|"
        r"/tmp/systemd-private|/tmp/\.font-unix|/tmp/ssh-",
        re.I
    )

    for line in out.splitlines():
        parts = line.split(None, 10)
        if len(parts) < 11: continue
        user, pid, cpu, mem = parts[0], parts[1], parts[2], parts[3]
        cmd = parts[10]
        proc = {"pid": pid, "user": user, "cpu": cpu, "mem": mem, "cmd": cmd[:150]}
        processes.append(proc)

        if MALICIOUS_TOOLS.search(cmd):
            rec("CRITICAL", "process", datetime.now().strftime("%b %d %H:%M:%S"),
                f"Known malicious tool: {cmd[:60]}",
                f"PID:{pid} USER:{user} CPU:{cpu}% MEM:{mem}%",
                "ps", {"pid": pid, "user": user, "cpu": cpu, "mem": mem, "cmd": cmd})
            n += 1
        elif RSHELL.search(cmd):
            rec("CRITICAL", "process", datetime.now().strftime("%b %d %H:%M:%S"),
                f"Reverse shell: {cmd[:60]}",
                f"PID:{pid} USER:{user} CMD:{cmd[:120]}",
                "ps", {"pid": pid, "user": user, "cpu": cpu, "mem": mem, "cmd": cmd})
            n += 1
        elif SUS_EXEC.search(cmd) and not SUS_EXEC_OK.search(cmd):
            rec("HIGH", "process", datetime.now().strftime("%b %d %H:%M:%S"),
                f"Process from temp dir: {cmd[:60]}",
                f"PID:{pid} USER:{user} PATH:{cmd[:100]}",
                "ps", {"pid": pid, "user": user, "cpu": cpu, "mem": mem, "cmd": cmd})
            n += 1

    top_procs = processes[:20]
    print(f"{len(processes)} total, {n} suspicious")


def scan_ports():
    """Snapshot all listening ports and flag suspicious ones."""
    print("  [*] open ports ...", end=" ", flush=True); n = 0
    global open_ports
    open_ports.clear()

    out = run_cmd(["ss", "-tlnp"])
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5: continue
        state   = parts[0]
        local   = parts[3]
        proc_m  = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        pname   = proc_m.group(1) if proc_m else "—"
        pid     = proc_m.group(2) if proc_m else "—"
        port_m  = re.search(r':(\d+)$', local)
        port    = int(port_m.group(1)) if port_m else 0
        addr    = re.sub(r':\d+$', '', local)

        entry = {"port": port, "addr": addr, "process": pname, "pid": pid, "state": state}
        open_ports.append(entry)

        if port in MALICIOUS_PORTS:
            rec("CRITICAL", "network", datetime.now().strftime("%b %d %H:%M:%S"),
                f"Malicious port {port} open — process: {pname}",
                f"Port:{port} PID:{pid} Process:{pname}", "ss", entry)
            n += 1
        elif port < 1024 and pname not in ("sshd","nginx","apache2","systemd","cups","avahi-daemon","—"):
            rec("MEDIUM", "network", datetime.now().strftime("%b %d %H:%M:%S"),
                f"Unusual privileged port {port} — {pname}",
                f"Port:{port} Process:{pname} PID:{pid}", "ss", entry)
            n += 1

    print(f"{len(open_ports)} ports, {n} suspicious")


def scan_autostart():
    """Check all persistence/autostart locations."""
    print("  [*] autostart/persistence ...", end=" ", flush=True); n = 0
    global autostart
    autostart.clear()

    locations = {
        "systemd_system":  list(Path("/etc/systemd/system").glob("*.service")) if Path("/etc/systemd/system").exists() else [],
        "systemd_user":    list(Path(os.path.expanduser("~/.config/systemd/user")).glob("*.service"))
                           if Path(os.path.expanduser("~/.config/systemd/user")).exists() else [],
        "xdg_autostart":   list(Path("/etc/xdg/autostart").glob("*.desktop")) if Path("/etc/xdg/autostart").exists() else [],
        "user_autostart":  list(Path(os.path.expanduser("~/.config/autostart")).glob("*.desktop"))
                           if Path(os.path.expanduser("~/.config/autostart")).exists() else [],
        "init_d":          [f for f in Path("/etc/init.d").iterdir() if f.is_file()] if Path("/etc/init.d").exists() else [],
        "rc_local":        [Path("/etc/rc.local")] if Path("/etc/rc.local").exists() else [],
        "profile_d":       list(Path("/etc/profile.d").glob("*.sh")) if Path("/etc/profile.d").exists() else [],
    }

    suspicious_in_service = re.compile(r"ExecStart=.*(wget|curl|nc\s|bash\s+-i|python.*-c|/tmp/|/dev/shm)", re.I)

    for location, files in locations.items():
        for f in files:
            try:
                content = Path(f).read_text(errors="ignore")[:500]
                is_sus = bool(suspicious_in_service.search(content))
                entry = {
                    "location": location,
                    "file":     str(f),
                    "name":     f.name,
                    "preview":  content[:150].replace('\n', ' '),
                    "suspicious": is_sus,
                    "mtime":    datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
                }
                autostart.append(entry)
                if is_sus:
                    rec("CRITICAL", "persistence", entry["mtime"],
                        f"Suspicious autostart entry: {f.name}",
                        content[:150], str(f), entry)
                    n += 1
                else:
                    rec("INFO", "persistence", entry["mtime"],
                        f"Autostart entry: {f.name}",
                        f"Location: {location}", str(f), entry)
            except (PermissionError, OSError):
                continue

    print(f"{len(autostart)} entries, {n} suspicious")


def scan_suid():
    """Find SUID/SGID files — common privilege escalation vectors."""
    print("  [*] SUID/SGID files ...", end=" ", flush=True); n = 0
    global suid_files
    suid_files.clear()

    # Known legitimate SUID binaries — don't flag these
    known_suid = {
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/gpasswd",
        "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/pkexec",
        "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/fusermount",
        "/usr/bin/fusermount3", "/usr/bin/ping", "/usr/bin/traceroute6",
        "/usr/sbin/pppd", "/sbin/unix_chkpwd", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/lib/openssh/ssh-keysign", "/usr/lib/policykit-1/polkit-agent-helper-1",
    }

    out = run_cmd(["find", "/", "-perm", "/6000", "-type", "f",
                   "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"], timeout=30)

    for line in out.splitlines():
        line = line.strip()
        if not line: continue
        is_known = line in known_suid
        entry = {"path": line, "known": is_known}
        suid_files.append(entry)
        if not is_known:
            rec("HIGH", "privilege", datetime.now().strftime("%b %d %H:%M:%S"),
                f"Unknown SUID/SGID file: {os.path.basename(line)}",
                f"Path: {line}", "filesystem", entry)
            n += 1

    print(f"{len(suid_files)} SUID files, {n} unknown")


def scan_recent_files():
    """Files modified in last 24h in sensitive locations."""
    print("  [*] recently modified files ...", end=" ", flush=True); n = 0
    global recent_files
    recent_files.clear()

    sensitive_dirs = [
        "/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
        "/lib", "/lib64", os.path.expanduser("~"),
        "/var/www", "/opt",
    ]
    cutoff = datetime.now().timestamp() - 86400  # 24 hours

    for d in sensitive_dirs:
        p = Path(d)
        if not p.exists(): continue
        try:
            for item in p.iterdir():
                try:
                    if not item.is_file(): continue
                    mtime = item.stat().st_mtime
                    if mtime < cutoff: continue
                    t = datetime.fromtimestamp(mtime).strftime("%b %d %H:%M:%S")
                    entry = {
                        "path":  str(item),
                        "name":  item.name,
                        "dir":   d,
                        "mtime": t,
                        "size":  item.stat().st_size,
                    }
                    recent_files.append(entry)
                    # Flag modified system binaries as HIGH
                    if d in ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/lib", "/lib64"):
                        rec("HIGH", "temp_artifacts", t,
                            f"System binary modified in last 24h: {item.name}",
                            f"Path: {item}", "filesystem", entry)
                        n += 1
                    elif d == "/etc":
                        rec("MEDIUM", "temp_artifacts", t,
                            f"Config file modified: {item.name}",
                            f"Path: {item}", "filesystem", entry)
                        n += 1
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            continue

    print(f"{len(recent_files)} recent files, {n} flagged")


def scan_memory():
    """RAM usage, CPU load, and top resource consumers."""
    print("  [*] memory/resources ...", end=" ", flush=True)
    global memory_info, top_procs

    # /proc/meminfo
    mem = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            num_m = re.search(r"(\d+)", v)
            if num_m: mem[k.strip()] = int(num_m.group(1))
    except Exception:
        pass

    total_kb  = mem.get("MemTotal", 0)
    avail_kb  = mem.get("MemAvailable", 0)
    used_kb   = total_kb - avail_kb
    swap_total= mem.get("SwapTotal", 0)
    swap_free = mem.get("SwapFree", 0)

    def kb_to_gb(kb): return round(kb / 1024 / 1024, 2)

    memory_info.update({
        "total_gb":    kb_to_gb(total_kb),
        "used_gb":     kb_to_gb(used_kb),
        "avail_gb":    kb_to_gb(avail_kb),
        "used_pct":    round(used_kb / total_kb * 100, 1) if total_kb else 0,
        "swap_total_gb": kb_to_gb(swap_total),
        "swap_used_gb":  kb_to_gb(swap_total - swap_free),
    })

    # CPU load
    try:
        load = os.getloadavg()
        memory_info["load_1m"]  = round(load[0], 2)
        memory_info["load_5m"]  = round(load[1], 2)
        memory_info["load_15m"] = round(load[2], 2)
    except Exception:
        pass

    # CPU count
    try:
        memory_info["cpu_count"] = os.cpu_count() or 1
    except Exception:
        memory_info["cpu_count"] = 1

    # Top processes by memory
    out = run_cmd(["ps", "aux", "--no-headers", "--sort=-%mem"])
    top_by_mem = []
    for line in out.splitlines()[:15]:
        parts = line.split(None, 10)
        if len(parts) < 11: continue
        top_by_mem.append({
            "user": parts[0], "pid": parts[1],
            "cpu":  parts[2], "mem": parts[3],
            "cmd":  parts[10][:80]
        })
    memory_info["top_by_mem"] = top_by_mem

    # Flag high memory usage
    if memory_info.get("used_pct", 0) > 90:
        rec("HIGH", "system", datetime.now().strftime("%b %d %H:%M:%S"),
            f"Critical memory usage: {memory_info['used_pct']}%",
            f"Used: {memory_info['used_gb']}GB / {memory_info['total_gb']}GB", "proc")

    print(f"RAM {memory_info.get('used_pct',0)}% used")


def scan_user_activity():
    """Login history via last, lastb (failed), who, w."""
    print("  [*] user activity (last/who) ...", end=" ", flush=True); n = 0
    global user_activity
    user_activity.clear()

    # last — successful logins
    out = run_cmd(["last", "-n", "200", "-F"])
    for line in out.splitlines():
        if not line or line.startswith("wtmp") or line.startswith("reboot"): continue
        parts = line.split()
        if len(parts) < 4: continue
        entry = {
            "type":    "login",
            "user":    parts[0],
            "terminal": parts[1] if len(parts) > 1 else "—",
            "from":    parts[2] if len(parts) > 2 else "local",
            "raw":     line.strip()[:150],
        }
        # Extract date from last output
        date_m = re.search(r"(\w{3} \w{3}\s+\d+ \d+:\d+:\d+ \d{4})", line)
        entry["time"] = date_m.group(1) if date_m else "—"
        user_activity.append(entry)
        n += 1

    # lastb — failed logins
    out_b = run_cmd(["lastb", "-n", "100"])
    for line in out_b.splitlines():
        if not line or line.startswith("btmp"): continue
        parts = line.split()
        if len(parts) < 3: continue
        entry = {
            "type":    "failed_login",
            "user":    parts[0],
            "terminal": parts[1] if len(parts) > 1 else "—",
            "from":    parts[2] if len(parts) > 2 else "—",
            "raw":     line.strip()[:150],
        }
        date_m = re.search(r"(\w{3} \w{3}\s+\d+ \d+:\d+:\d+)", line)
        entry["time"] = date_m.group(1) if date_m else "—"
        user_activity.append(entry)
        if parts[0] not in ("btmp",):
            rec("HIGH", "failed_login", entry["time"],
                f"Failed login attempt: user '{parts[0]}'",
                line.strip(), "lastb", entry)
            n += 1

    # w — currently logged in
    out_w = run_cmd(["w", "-h"])
    for line in out_w.splitlines():
        if not line: continue
        parts = line.split()
        if len(parts) < 4: continue
        entry = {
            "type":  "active_session",
            "user":  parts[0],
            "tty":   parts[1],
            "from":  parts[2],
            "login": parts[3],
            "cmd":   parts[-1] if len(parts) > 7 else "—",
            "time":  datetime.now().strftime("%b %d %H:%M:%S"),
            "raw":   line.strip()[:150],
        }
        user_activity.append(entry)
        rec("INFO", "login", entry["time"],
            f"Active session: {parts[0]} from {parts[2]}",
            line.strip(), "w", entry)

    print(f"{n} activity events")


# ── Patch clear_state ─────────────────────────────────────────
_orig_clear = clear_state
def clear_state():
    _orig_clear()
    global processes, open_ports, autostart, suid_files
    global recent_files, memory_info, top_procs, user_activity
    processes.clear(); open_ports.clear(); autostart.clear()
    suid_files.clear(); recent_files.clear(); memory_info.clear()
    top_procs.clear(); user_activity.clear()

# ── Patch build_report ────────────────────────────────────────
_orig_build = build_report
def build_report():
    r = _orig_build()
    r["processes"]     = processes[:200]
    r["open_ports"]    = open_ports
    r["autostart"]     = autostart
    r["suid_files"]    = suid_files
    r["recent_files"]  = recent_files[:100]
    r["memory_info"]   = memory_info
    r["top_procs"]     = top_procs
    r["user_activity"] = user_activity[:300]
    # Risk score 0-100 (v3.0 — gentle log-scaled formula)
    # 0 critical, 0 high   = 5   (baseline noise)
    # 1 critical           = 18
    # 5 critical           = 35
    # 20 critical          = 55
    # 50 critical          = 70
    # 100+ critical        = 80
    # All bumped by high/medium contributions (capped)
    import math as _m
    s = r["summary"]
    crit_n = s["critical"]
    high_n = s["high"]
    med_n  = s["medium"]
    info_n = s.get("info", 0)

    # Critical events dominate score, others contribute small bonuses
    # crit:  1=15, 3=25, 10=40, 30=55, 100=70
    # high:  small bonus, max +15
    # med:   tiny bonus, max +8
    # info:  almost nothing
    crit_score = min(15 + _m.log1p(crit_n - 1) * 12, 70) if crit_n >= 1 else 0
    high_score = min(_m.log1p(high_n) * 4, 15)
    med_score  = min(_m.log1p(med_n) * 1.5, 8)
    info_score = min(_m.log1p(info_n) * 0.4, 3)
    base       = 0

    score = int(base + crit_score + high_score + med_score + info_score)
    r["risk_score"] = min(95, max(0, score))  # cap at 95, never 100
    r["risk_breakdown"] = {
        "critical_contribution": round(crit_score, 1),
        "high_contribution":     round(high_score, 1),
        "medium_contribution":   round(med_score, 1),
        "info_contribution":     round(info_score, 1),
        "base":                  base,
    }
    # MITRE ATT&CK mapping (v3.0)
    try:
        enrich_mitre(r)
    except Exception as ex:
        r["mitre_coverage"] = {"error": str(ex)}
    return r


# ═══════════════════════════════════════════════════════════════
# CORRELATION ENGINE v2.0
# Builds a graph of related events: nodes + edges
# Correlates by: PID, IP, user, file path, port, time proximity
# ═══════════════════════════════════════════════════════════════

def correlate():
    """
    Build correlation graph from all scan data.
    Returns: { nodes: [...], edges: [...], chains: [...] }

    Node types: process, port, connection, file, user, autostart, finding
    Edge types: opened, connected_to, wrote, read, spawned, belongs_to, triggered
    """
    report = REPORT_CACHE
    if not report:
        return {"nodes": [], "edges": [], "chains": []}

    nodes  = {}   # id -> node dict
    edges  = []   # list of edge dicts
    id_seq = [0]

    def nid():
        id_seq[0] += 1
        return f"n{id_seq[0]}"

    def add_node(key, ntype, label, severity="INFO", meta=None):
        if key not in nodes:
            nodes[key] = {
                "id":       key,
                "type":     ntype,
                "label":    label[:60],
                "severity": severity,
                "meta":     meta or {},
            }
        else:
            # Upgrade severity if worse
            SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "LOW": 4}
            if SEV.get(severity, 4) < SEV.get(nodes[key]["severity"], 4):
                nodes[key]["severity"] = severity
        return key

    def add_edge(src, dst, rel, label=""):
        # Avoid duplicates
        key = f"{src}->{dst}:{rel}"
        for e in edges:
            if e.get("_key") == key:
                return
        edges.append({"source": src, "target": dst, "relation": rel, "label": label, "_key": key})

    # ── 1. Process nodes ──────────────────────────────────────
    pid_to_node = {}
    for p in report.get("processes", []):
        pid  = str(p.get("pid", ""))
        cmd  = p.get("cmd", "?")
        user = p.get("user", "?")
        cpu  = float(p.get("cpu", 0) or 0)
        mem  = float(p.get("mem", 0) or 0)
        sev  = "HIGH" if cpu > 80 or mem > 50 else "MEDIUM" if cpu > 40 else "INFO"
        key  = f"proc:{pid}"
        add_node(key, "process", f"{cmd.split('/')[-1]} [{pid}]", sev,
                 {"pid": pid, "cmd": cmd, "user": user, "cpu": cpu, "mem": mem})
        pid_to_node[pid] = key

        # User node
        ukey = f"user:{user}"
        add_node(ukey, "user", user, "INFO", {"user": user})
        add_edge(ukey, key, "runs", "runs")

    # ── 2. Port nodes + link to processes ─────────────────────
    port_to_node = {}
    for p in report.get("open_ports", []):
        port = str(p.get("port", ""))
        pid  = str(p.get("pid", ""))
        proc = p.get("process", "?")
        sev  = "CRITICAL" if int(port or 0) in MALICIOUS_PORTS else "MEDIUM"
        key  = f"port:{port}"
        add_node(key, "port", f":{port}", sev, {"port": port, "addr": p.get("addr", "")})
        port_to_node[port] = key

        # Link process → port
        pkey = pid_to_node.get(pid)
        if pkey:
            add_edge(pkey, key, "opened", "opened port")
        elif proc and proc != "?":
            # Try match by command name
            for pr in report.get("processes", []):
                if proc in str(pr.get("cmd", "")):
                    pk = pid_to_node.get(str(pr.get("pid", "")))
                    if pk:
                        add_edge(pk, key, "opened", "opened port")
                        break

    # ── 3. Network connection nodes ───────────────────────────
    ip_to_node = {}
    for e in report.get("network_events", []):
        dst  = e.get("dst_ip", "")
        dport= str(e.get("dst_port", ""))
        src  = e.get("src_ip", "")
        susp = e.get("suspicious", False)
        act  = e.get("action", "")
        if not dst:
            continue
        sev = "CRITICAL" if susp else "HIGH" if act == "BLOCK" else "INFO"
        key = f"conn:{dst}:{dport}"
        if key not in ip_to_node:
            add_node(key, "connection", f"{dst}:{dport}", sev,
                     {"dst_ip": dst, "dst_port": dport, "src_ip": src, "action": act})
            ip_to_node[key] = key

        # Link port → connection
        pkey = port_to_node.get(dport)
        if pkey:
            add_edge(pkey, key, "connects_to", "→")
        else:
            # Link process by src port matching — find any process
            if src:
                for pid, pnode in pid_to_node.items():
                    # heuristic: if process has high cpu and there's a suspicious conn
                    if susp and nodes[pnode]["severity"] in ("HIGH", "CRITICAL"):
                        add_edge(pnode, key, "connects_to", "→ ext")
                        break

    # ── 4. Autostart nodes ────────────────────────────────────
    for a in report.get("autostart", []):
        name = a.get("name", "?")
        loc  = a.get("location", "")
        susp = a.get("suspicious", False)
        sev  = "HIGH" if susp else "INFO"
        key  = f"auto:{name}:{loc}"
        add_node(key, "autostart", name[:40], sev,
                 {"name": name, "location": loc, "preview": a.get("preview", "")})

        # Try match autostart entry to a running process by name
        short = name.split("/")[-1].split(".")[0].lower()
        for pid, pnode in pid_to_node.items():
            pcmd = nodes[pnode]["meta"].get("cmd", "").lower()
            if short and short in pcmd:
                add_edge(key, pnode, "launches", "launches")
                break

    # ── 5. SUID file nodes ────────────────────────────────────
    for s in report.get("suid_files", []):
        path = s.get("path", "")
        known= s.get("known", True)
        sev  = "INFO" if known else "HIGH"
        key  = f"suid:{path}"
        add_node(key, "file", path.split("/")[-1], sev,
                 {"path": path, "known": known, "subtype": "suid"})

        # Link to any process running this binary
        fname = path.split("/")[-1].lower()
        for pid, pnode in pid_to_node.items():
            pcmd = nodes[pnode]["meta"].get("cmd", "").lower()
            if fname and fname in pcmd:
                add_edge(pnode, key, "executes", "executes")
                break

    # ── 6. Findings → enrich existing nodes ───────────────────
    for f in report.get("findings", []):
        sev  = f.get("severity", "INFO")
        cat  = f.get("category", "")
        desc = f.get("description", "")
        src  = f.get("source", "")
        pid  = str(f.get("pid") or "")
        user = f.get("user") or f.get("username") or ""
        ip   = f.get("src_ip") or f.get("ip") or ""
        path = f.get("path") or f.get("file_path") or ""

        # Upgrade existing node severity based on finding
        if pid and pid in pid_to_node:
            pkey = pid_to_node[pid]
            SEV  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "LOW": 4}
            if SEV.get(sev, 4) < SEV.get(nodes[pkey]["severity"], 4):
                nodes[pkey]["severity"] = sev
                nodes[pkey]["meta"]["finding"] = desc

        # IP-based finding → add finding node linked to connection
        if ip:
            ukey = f"user:{user}" if user else None
            fkey = f"finding:{cat}:{ip}:{desc[:30]}"
            add_node(fkey, "finding", desc[:50], sev, {"category": cat, "ip": ip, "detail": f.get("detail", "")})
            for ckey in ip_to_node:
                if ip in ckey:
                    add_edge(fkey, ckey, "relates_to", "")
                    break
            if ukey and ukey in nodes:
                add_edge(ukey, fkey, "triggered", "triggered")

        # File-based finding
        if path:
            fkey = f"file:{path}"
            add_node(fkey, "file", path.split("/")[-1] or path, sev,
                     {"path": path, "category": cat})
            # Link to process if pid known
            if pid and pid in pid_to_node:
                add_edge(pid_to_node[pid], fkey, "wrote", "wrote")

        # Standalone finding node for HIGH/CRITICAL without other links
        if sev in ("CRITICAL", "HIGH") and not pid and not ip and not path:
            fkey = f"finding:{sev}:{src}:{desc[:40]}"
            if fkey not in nodes:
                add_node(fkey, "finding", desc[:50], sev,
                         {"category": cat, "source": src, "detail": f.get("detail", "")})
                # Link to user if known
                if user:
                    ukey = f"user:{user}"
                    add_node(ukey, "user", user, "INFO", {"user": user})
                    add_edge(ukey, fkey, "involved_in", "")

    # ── 7. Build attack chains ────────────────────────────────
    # A chain = connected subgraph containing at least one HIGH/CRITICAL node
    # Use BFS to find connected components
    adj = defaultdict(set)
    for e in edges:
        adj[e["source"]].add(e["target"])
        adj[e["target"]].add(e["source"])

    visited = set()
    chains  = []
    SEV_ORD = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "LOW": 4}

    for start_id in nodes:
        if start_id in visited:
            continue
        # BFS
        component = []
        queue = [start_id]
        while queue:
            cur = queue.pop(0)
            if cur in visited:
                continue
            visited.add(cur)
            component.append(cur)
            queue.extend(adj[cur] - visited)

        if len(component) < 2:
            continue

        # Only keep chains with at least one HIGH or CRITICAL node
        max_sev = min((SEV_ORD.get(nodes[n]["severity"], 4) for n in component), default=4)
        if max_sev > 1:  # only INFO/LOW — skip
            continue

        chain_sev = ["CRITICAL","HIGH","MEDIUM","INFO","LOW"][max_sev]
        chain_nodes = [nodes[n] for n in component]
        chain_edges = [e for e in edges
                       if e["source"] in component and e["target"] in component]

        chains.append({
            "id":       f"chain_{len(chains)+1}",
            "severity": chain_sev,
            "node_count": len(component),
            "edge_count": len(chain_edges),
            "label":    _chain_label(chain_nodes),
            "nodes":    [n["id"] for n in chain_nodes],
        })

    chains.sort(key=lambda c: SEV_ORD.get(c["severity"], 4))

    return {
        "nodes":  list(nodes.values()),
        "edges":  [{k: v for k, v in e.items() if k != "_key"} for e in edges],
        "chains": chains,
        "stats": {
            "total_nodes":    len(nodes),
            "total_edges":    len(edges),
            "total_chains":   len(chains),
            "critical_nodes": sum(1 for n in nodes.values() if n["severity"] == "CRITICAL"),
            "high_nodes":     sum(1 for n in nodes.values() if n["severity"] == "HIGH"),
        }
    }


def _chain_label(chain_nodes):
    """Generate human-readable label for an attack chain."""
    types = [n["type"] for n in chain_nodes]
    sevs  = [n["severity"] for n in chain_nodes]
    if "CRITICAL" in sevs:
        sev = "CRITICAL"
    elif "HIGH" in sevs:
        sev = "HIGH"
    else:
        sev = "MEDIUM"

    if "process" in types and "connection" in types:
        procs = [n["label"] for n in chain_nodes if n["type"] == "process"]
        conns = [n["label"] for n in chain_nodes if n["type"] == "connection"]
        return f"[{sev}] {procs[0] if procs else '?'} → {conns[0] if conns else '?'}"
    if "autostart" in types and "process" in types:
        autos = [n["label"] for n in chain_nodes if n["type"] == "autostart"]
        return f"[{sev}] Persistence: {autos[0] if autos else '?'}"
    if "finding" in types:
        findings_n = [n["label"] for n in chain_nodes if n["type"] == "finding"]
        return f"[{sev}] {findings_n[0] if findings_n else '?'}"
    procs = [n["label"] for n in chain_nodes if n["type"] == "process"]
    if procs:
        return f"[{sev}] {procs[0]}"
    return f"[{sev}] {chain_nodes[0]['label'] if chain_nodes else '?'}"


# ═══════════════════════════════════════════════════════════════
# PDF REPORT GENERATOR v2.0
# ═══════════════════════════════════════════════════════════════

def generate_pdf(report, output_path):
    """Generate professional PDF report from scan data."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable, PageBreak)
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    except ImportError:
        return False, "reportlab not installed. Run: pip install reportlab"

    s   = report.get("summary", {})
    F   = report.get("findings", [])
    pr  = report.get("processes", [])
    po  = report.get("open_ports", [])
    au  = report.get("autostart", [])
    su  = report.get("suid_files", [])
    risk = report.get("risk_score", 0)

    # Colors
    RED   = colors.HexColor("#ff4d4d")
    ORA   = colors.HexColor("#ff9933")
    YEL   = colors.HexColor("#cc9900")
    GRN   = colors.HexColor("#33bb77")
    BLU   = colors.HexColor("#4d99ff")
    DARK  = colors.HexColor("#1a1a2e")
    GREY  = colors.HexColor("#666688")
    LGREY = colors.HexColor("#f4f5f8")
    SEV_COL = {"CRITICAL": RED, "HIGH": ORA, "MEDIUM": YEL, "INFO": BLU, "LOW": GRN}

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=20*mm, bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()
    def S(name, **kw):
        base = styles.get(name, styles["Normal"])
        return ParagraphStyle("_", parent=base, **kw)

    title_style   = S("Title",   fontSize=22, textColor=DARK, spaceAfter=2, leading=26)
    h1_style      = S("Heading1",fontSize=14, textColor=DARK, spaceBefore=14, spaceAfter=6, leading=18)
    h2_style      = S("Heading2",fontSize=11, textColor=GREY, spaceBefore=8,  spaceAfter=4, leading=14)
    body_style    = S("Normal",  fontSize=9,  textColor=DARK, leading=13)
    mono_style    = S("Normal",  fontSize=8,  fontName="Courier", textColor=DARK, leading=11)
    caption_style = S("Normal",  fontSize=8,  textColor=GREY, leading=11)

    def risk_color(r):
        if r >= 80: return RED
        if r >= 50: return ORA
        if r >= 20: return YEL
        return GRN

    story = []

    # ── Cover ──────────────────────────────────────────────────
    story.append(Spacer(1, 20*mm))
    story.append(Paragraph("FORENSIQ", S("Normal", fontSize=28, fontName="Helvetica-Bold",
                                          textColor=DARK, letterSpacing=8)))
    story.append(Paragraph("Digital Forensics &amp; Incident Response Report", S("Normal",
                             fontSize=12, textColor=GREY, spaceAfter=20)))
    story.append(HRFlowable(width="100%", thickness=1, color=DARK))
    story.append(Spacer(1, 6*mm))

    # Meta table
    meta = [
        ["Host",       s.get("hostname","—"),  "Scan Date", s.get("scanned_at","—")],
        ["Risk Score", str(risk)+"/100",        "Critical",  str(s.get("critical",0))],
        ["High",       str(s.get("high",0)),    "Total",     str(s.get("total",0))],
    ]
    mt = Table(meta, colWidths=[30*mm,60*mm,30*mm,60*mm])
    mt.setStyle(TableStyle([
        ("FONTNAME",  (0,0),(-1,-1),"Helvetica"),
        ("FONTSIZE",  (0,0),(-1,-1), 9),
        ("FONTNAME",  (0,0),(0,-1),"Helvetica-Bold"),
        ("FONTNAME",  (2,0),(2,-1),"Helvetica-Bold"),
        ("TEXTCOLOR", (0,0),(0,-1), GREY),
        ("TEXTCOLOR", (2,0),(2,-1), GREY),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white, LGREY]),
        ("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
    ]))
    story.append(mt)
    story.append(Spacer(1, 8*mm))

    # Risk bar visual
    risk_col = risk_color(risk)
    risk_label = "CRITICAL" if risk>=80 else "HIGH" if risk>=50 else "MEDIUM" if risk>=20 else "CLEAN"
    story.append(Paragraph(f"<b>RISK ASSESSMENT: <font color='{risk_col.hexval()}'>{risk_label} ({risk}/100)</font></b>",
                            S("Normal", fontSize=11, leading=14)))
    story.append(Spacer(1, 4*mm))
    story.append(PageBreak())

    # ── Executive Summary ───────────────────────────────────────
    story.append(Paragraph("Executive Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    story.append(Spacer(1,3*mm))

    crit_f = [f for f in F if f.get("severity")=="CRITICAL"]
    high_f = [f for f in F if f.get("severity")=="HIGH"]
    summary_text = (
        f"This report presents findings from a ForensIQ automated security scan performed on "
        f"<b>{s.get('hostname','unknown host')}</b> on {s.get('scanned_at','unknown date')}. "
        f"The overall risk score is <b>{risk}/100</b> ({risk_label}). "
        f"A total of <b>{len(F)} security events</b> were detected, including "
        f"<b>{s.get('critical',0)} critical</b>, <b>{s.get('high',0)} high</b>, "
        f"and <b>{s.get('medium',0)} medium severity</b> findings."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1,4*mm))

    # ── Critical Findings ───────────────────────────────────────
    story.append(Paragraph("Critical &amp; High Findings", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    story.append(Spacer(1,3*mm))

    top_f = (crit_f + high_f)[:40]
    if top_f:
        rows = [["Severity","Category","Time","Description"]]
        for f in top_f:
            sev  = f.get("severity","—")
            col  = SEV_COL.get(sev, GREY)
            rows.append([
                Paragraph(f"<font color='{col.hexval()}'><b>{sev}</b></font>", mono_style),
                Paragraph(f.get("category","—")[:20], mono_style),
                Paragraph((f.get("time","—") or "—")[:16], mono_style),
                Paragraph((f.get("description","—") or "—")[:80], body_style),
            ])
        ft = Table(rows, colWidths=[22*mm,25*mm,28*mm,None])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,0), DARK),
            ("TEXTCOLOR",  (0,0),(-1,0), colors.white),
            ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0),(-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LGREY]),
            ("TOPPADDING", (0,0),(-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ("GRID",       (0,0),(-1,-1), 0.25, colors.lightgrey),
        ]))
        story.append(ft)
    else:
        story.append(Paragraph("No critical or high findings detected.", body_style))
    story.append(Spacer(1,5*mm))

    # ── Open Ports ──────────────────────────────────────────────
    if po:
        story.append(Paragraph("Open Ports", h1_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        story.append(Spacer(1,3*mm))
        rows = [["Port","Address","Process","PID"]]
        for p in po[:30]:
            rows.append([str(p.get("port","—")), p.get("addr","—")[:25],
                         p.get("process","—")[:30], str(p.get("pid","—"))])
        pt = Table(rows, colWidths=[20*mm,45*mm,70*mm,None])
        pt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),DARK),("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,-1),"Courier"),("FONTSIZE",(0,0),(-1,-1),8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,LGREY]),
            ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
            ("GRID",(0,0),(-1,-1),0.25,colors.lightgrey),
        ]))
        story.append(pt)
        story.append(Spacer(1,5*mm))

    # ── Suspicious Autostart ────────────────────────────────────
    sus_auto = [a for a in au if a.get("suspicious")]
    if sus_auto:
        story.append(Paragraph("Suspicious Autostart Entries", h1_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        story.append(Spacer(1,3*mm))
        for a in sus_auto[:15]:
            story.append(Paragraph(f"<b>{a.get('name','?')}</b> [{a.get('location','')}]", body_style))
            story.append(Paragraph(a.get("preview","")[:120], mono_style))
            story.append(Spacer(1,2*mm))

    # ── Unknown SUID ────────────────────────────────────────────
    unk_suid = [x for x in su if not x.get("known")]
    if unk_suid:
        story.append(Paragraph("Unknown SUID Files", h1_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        story.append(Spacer(1,3*mm))
        for x in unk_suid[:20]:
            story.append(Paragraph(f"&#9888; {x.get('path','?')}", S("Normal",
                fontSize=9, textColor=RED, fontName="Courier", leading=13)))
        story.append(Spacer(1,5*mm))

    # ── Footer note ─────────────────────────────────────────────
    story.append(Spacer(1,10*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    story.append(Spacer(1,3*mm))
    story.append(Paragraph(
        f"Generated by ForensIQ v2.0 · Egor Gubarev · {s.get('scanned_at','')}",
        caption_style
    ))

    try:
        doc.build(story)
        return True, output_path
    except Exception as e:
        return False, str(e)


# ═══════════════════════════════════════════════════════════════
# WINDOWS SCANNERS v2.0
# Automatically used when running on Windows
# ═══════════════════════════════════════════════════════════════

import platform as _platform
IS_WINDOWS = _platform.system() == "Windows"

def _win_cmd(args, timeout=10):
    """Run command on Windows, return output string."""
    import subprocess
    try:
        return subprocess.check_output(
            args, timeout=timeout,
            stderr=subprocess.DEVNULL,
            shell=True, text=True, encoding="utf-8", errors="replace"
        )
    except Exception:
        return ""

def scan_processes_win():
    """Scan running processes via tasklist/wmic."""
    global processes
    processes.clear()
    print("  [*] processes (Windows) ...", end=" ", flush=True)
    out = _win_cmd("tasklist /fo csv /nh")
    n = 0
    for line in out.splitlines():
        parts = line.strip('"').split('","')
        if len(parts) < 5: continue
        name, pid, _, _, mem = parts[0], parts[1], parts[2], parts[3], parts[4]
        mem_kb = int(mem.replace(",","").replace(" K","").strip() or 0)
        processes.append({
            "pid": pid, "user": "—", "cpu": "0",
            "mem": str(round(mem_kb/1024/1024*100,1)),
            "cmd": name, "raw": line
        })
        n += 1
    print(f"{n} processes")

def scan_ports_win():
    """Scan open ports via netstat."""
    global open_ports
    open_ports.clear()
    print("  [*] ports (Windows) ...", end=" ", flush=True)
    out = _win_cmd("netstat -ano")
    n = 0
    import re
    for line in out.splitlines():
        m = re.match(r"\s+(TCP|UDP)\s+([\d\.\*]+):(\d+)\s+.*\s+(\d+)$", line)
        if not m: continue
        proto, addr, port, pid = m.groups()
        port_i = int(port)
        sev = "CRITICAL" if port_i in MALICIOUS_PORTS else "MEDIUM"
        if sev == "CRITICAL":
            rec("CRITICAL","network",_now(),
                f"Malicious port {port} listening (Windows)",
                f"{proto} {addr}:{port} PID:{pid}","netstat")
        open_ports.append({"port": port_i, "addr": addr, "process": "—", "pid": pid})
        n += 1
    print(f"{n} ports")

def scan_autostart_win():
    """Scan Windows autostart via registry."""
    global autostart
    autostart.clear()
    print("  [*] autostart (Windows) ...", end=" ", flush=True)
    keys = [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]
    n = 0
    for key in keys:
        out = _win_cmd(f'reg query "{key}" /s')
        for line in out.splitlines():
            if "REG_" in line:
                parts = line.strip().split(None, 2)
                if len(parts) >= 3:
                    name, _, val = parts
                    sus = any(x in val.lower() for x in ["temp","appdata","powershell -enc","cmd /c","wscript","cscript"])
                    if sus:
                        rec("HIGH","persistence",_now(),
                            f"Suspicious autostart: {name}",val[:200],"registry")
                    autostart.append({
                        "name": name, "location": key.split("\\")[-1],
                        "preview": val[:100], "suspicious": sus, "mtime": ""
                    })
                    n += 1
    print(f"{n} entries")

def scan_users_win():
    """Scan Windows event log for login events."""
    print("  [*] logins (Windows) ...", end=" ", flush=True)
    out = _win_cmd('wevtutil qe Security /q:"*[System[EventID=4624 or EventID=4625]]" /c:50 /rd:true /f:text')
    n = 0
    import re
    for block in out.split("Event["):
        if "4625" in block:
            user_m = re.search(r"Account Name:\s+(\S+)", block)
            ip_m   = re.search(r"Source Network Address:\s+(\S+)", block)
            user   = user_m.group(1) if user_m else "?"
            ip     = ip_m.group(1) if ip_m else "—"
            rec("HIGH","failed_login",_now(),
                f"Failed login: {user} from {ip}",block[:200],"EventLog")
            n += 1
    print(f"{n} events")

def scan_network_win():
    """Scan active network connections on Windows."""
    print("  [*] network (Windows) ...", end=" ", flush=True)
    out = _win_cmd("netstat -an")
    import re
    n = 0
    for line in out.splitlines():
        m = re.match(r"\s+(TCP|UDP)\s+([\d\.]+):(\d+)\s+([\d\.]+):(\d+)\s+(\S+)", line)
        if not m: continue
        proto, src, sport, dst, dport, state = m.groups()
        susp = int(dport) in MALICIOUS_PORTS if dport.isdigit() else False
        if susp:
            rec("CRITICAL","network",_now(),
                f"Connection to suspicious port {dport}",
                f"{src}:{sport} -> {dst}:{dport}","netstat")
        network_events.append({
            "time": _now(), "src_ip": src, "dst_ip": dst,
            "dst_port": int(dport) if dport.isdigit() else 0,
            "proto": proto, "action": state, "suspicious": susp
        })
        n += 1
    print(f"{n} connections")

def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run_windows_scan():
    """Full scan on Windows platform."""
    clear_state()
    scan_processes_win()
    scan_ports_win()
    scan_autostart_win()
    scan_users_win()
    scan_network_win()
    return build_report()


# ═══════════════════════════════════════════════════════════════
# MITRE ATT&CK MAPPING v3.0
# Maps findings to MITRE ATT&CK techniques (Enterprise matrix)
# Reference: https://attack.mitre.org/
# ═══════════════════════════════════════════════════════════════

# Mapping: technique_id → {name, tactic, description}
MITRE_TECHNIQUES = {
    "T1059":     {"name": "Command and Scripting Interpreter",       "tactic": "Execution",            "url": "https://attack.mitre.org/techniques/T1059/"},
    "T1059.004": {"name": "Unix Shell",                              "tactic": "Execution",            "url": "https://attack.mitre.org/techniques/T1059/004/"},
    "T1078":     {"name": "Valid Accounts",                          "tactic": "Persistence",          "url": "https://attack.mitre.org/techniques/T1078/"},
    "T1078.003": {"name": "Local Accounts",                          "tactic": "Persistence",          "url": "https://attack.mitre.org/techniques/T1078/003/"},
    "T1110":     {"name": "Brute Force",                             "tactic": "Credential Access",    "url": "https://attack.mitre.org/techniques/T1110/"},
    "T1136":     {"name": "Create Account",                          "tactic": "Persistence",          "url": "https://attack.mitre.org/techniques/T1136/"},
    "T1543":     {"name": "Create or Modify System Process",         "tactic": "Persistence",          "url": "https://attack.mitre.org/techniques/T1543/"},
    "T1543.002": {"name": "Systemd Service",                         "tactic": "Persistence",          "url": "https://attack.mitre.org/techniques/T1543/002/"},
    "T1547":     {"name": "Boot or Logon Autostart Execution",       "tactic": "Persistence",          "url": "https://attack.mitre.org/techniques/T1547/"},
    "T1053":     {"name": "Scheduled Task/Job",                      "tactic": "Persistence",          "url": "https://attack.mitre.org/techniques/T1053/"},
    "T1053.003": {"name": "Cron",                                    "tactic": "Persistence",          "url": "https://attack.mitre.org/techniques/T1053/003/"},
    "T1548":     {"name": "Abuse Elevation Control Mechanism",       "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1548/"},
    "T1548.001": {"name": "Setuid and Setgid",                       "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1548/001/"},
    "T1068":     {"name": "Exploitation for Privilege Escalation",   "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1068/"},
    "T1071":     {"name": "Application Layer Protocol",              "tactic": "Command and Control",  "url": "https://attack.mitre.org/techniques/T1071/"},
    "T1571":     {"name": "Non-Standard Port",                       "tactic": "Command and Control",  "url": "https://attack.mitre.org/techniques/T1571/"},
    "T1572":     {"name": "Protocol Tunneling",                      "tactic": "Command and Control",  "url": "https://attack.mitre.org/techniques/T1572/"},
    "T1095":     {"name": "Non-Application Layer Protocol",          "tactic": "Command and Control",  "url": "https://attack.mitre.org/techniques/T1095/"},
    "T1041":     {"name": "Exfiltration Over C2 Channel",            "tactic": "Exfiltration",         "url": "https://attack.mitre.org/techniques/T1041/"},
    "T1505":     {"name": "Server Software Component",               "tactic": "Persistence",          "url": "https://attack.mitre.org/techniques/T1505/"},
    "T1098":     {"name": "Account Manipulation",                    "tactic": "Persistence",          "url": "https://attack.mitre.org/techniques/T1098/"},
    "T1133":     {"name": "External Remote Services",                "tactic": "Persistence",          "url": "https://attack.mitre.org/techniques/T1133/"},
    "T1021":     {"name": "Remote Services",                         "tactic": "Lateral Movement",     "url": "https://attack.mitre.org/techniques/T1021/"},
    "T1021.004": {"name": "SSH",                                     "tactic": "Lateral Movement",     "url": "https://attack.mitre.org/techniques/T1021/004/"},
    "T1014":     {"name": "Rootkit",                                 "tactic": "Defense Evasion",      "url": "https://attack.mitre.org/techniques/T1014/"},
    "T1070":     {"name": "Indicator Removal",                       "tactic": "Defense Evasion",      "url": "https://attack.mitre.org/techniques/T1070/"},
    "T1070.002": {"name": "Clear Linux or Mac System Logs",          "tactic": "Defense Evasion",      "url": "https://attack.mitre.org/techniques/T1070/002/"},
    "T1070.003": {"name": "Clear Command History",                   "tactic": "Defense Evasion",      "url": "https://attack.mitre.org/techniques/T1070/003/"},
    "T1564":     {"name": "Hide Artifacts",                          "tactic": "Defense Evasion",      "url": "https://attack.mitre.org/techniques/T1564/"},
    "T1027":     {"name": "Obfuscated Files or Information",         "tactic": "Defense Evasion",      "url": "https://attack.mitre.org/techniques/T1027/"},
    "T1083":     {"name": "File and Directory Discovery",            "tactic": "Discovery",            "url": "https://attack.mitre.org/techniques/T1083/"},
    "T1057":     {"name": "Process Discovery",                       "tactic": "Discovery",            "url": "https://attack.mitre.org/techniques/T1057/"},
    "T1049":     {"name": "System Network Connections Discovery",    "tactic": "Discovery",            "url": "https://attack.mitre.org/techniques/T1049/"},
    "T1018":     {"name": "Remote System Discovery",                 "tactic": "Discovery",            "url": "https://attack.mitre.org/techniques/T1018/"},
    "T1003":     {"name": "OS Credential Dumping",                   "tactic": "Credential Access",    "url": "https://attack.mitre.org/techniques/T1003/"},
    "T1552":     {"name": "Unsecured Credentials",                   "tactic": "Credential Access",    "url": "https://attack.mitre.org/techniques/T1552/"},
    "T1056":     {"name": "Input Capture",                           "tactic": "Collection",           "url": "https://attack.mitre.org/techniques/T1056/"},
    "T1125":     {"name": "Video Capture",                           "tactic": "Collection",           "url": "https://attack.mitre.org/techniques/T1125/"},
    "T1485":     {"name": "Data Destruction",                        "tactic": "Impact",               "url": "https://attack.mitre.org/techniques/T1485/"},
    "T1486":     {"name": "Data Encrypted for Impact",               "tactic": "Impact",               "url": "https://attack.mitre.org/techniques/T1486/"},
    "T1490":     {"name": "Inhibit System Recovery",                 "tactic": "Impact",               "url": "https://attack.mitre.org/techniques/T1490/"},
    "T1499":     {"name": "Endpoint Denial of Service",              "tactic": "Impact",               "url": "https://attack.mitre.org/techniques/T1499/"},
    "T1190":     {"name": "Exploit Public-Facing Application",       "tactic": "Initial Access",       "url": "https://attack.mitre.org/techniques/T1190/"},
    "T1200":     {"name": "Hardware Additions",                      "tactic": "Initial Access",       "url": "https://attack.mitre.org/techniques/T1200/"},
    "T1091":     {"name": "Replication Through Removable Media",     "tactic": "Initial Access",       "url": "https://attack.mitre.org/techniques/T1091/"},
    "T1562":     {"name": "Impair Defenses",                         "tactic": "Defense Evasion",      "url": "https://attack.mitre.org/techniques/T1562/"},
    "T1562.004": {"name": "Disable or Modify System Firewall",       "tactic": "Defense Evasion",      "url": "https://attack.mitre.org/techniques/T1562/004/"},
}


def _detect_mitre(finding):
    """
    Map a single finding to one or more MITRE ATT&CK techniques.
    Returns a list of technique IDs (most specific first).
    """
    cat   = (finding.get("category") or "").lower()
    desc  = (finding.get("description") or "").lower()
    det   = (finding.get("detail") or "").lower()
    src   = (finding.get("source") or "").lower()
    sev   = finding.get("severity", "")
    text  = f"{desc} {det}".lower()
    techs = []

    # ── Persistence ──────────────────────────────────────────
    if cat == "persistence" or "autostart" in src:
        if "user" in text and ("created" in text or "added" in text):
            techs += ["T1136"]
        if "systemd" in text or "service" in src:
            techs += ["T1543.002"]
        if "cron" in cat or "cron" in src or "crontab" in text:
            techs += ["T1053.003"]
        if not techs:
            techs += ["T1547"]

    elif cat == "cron":
        techs += ["T1053.003"]

    # ── Privilege Escalation (SUID) ──────────────────────────
    elif "suid" in cat or "suid" in src:
        techs += ["T1548.001"]

    # ── Credential Access (failed logins, brute force) ──────
    # Single failed login is not brute force. Need multiple attempts from same IP.
    elif cat in ("failed_login", "auth", "login") or "failed login" in text:
        attempts = 0
        try:
            attempts = int(str(finding.get("attempts","0")))
        except: pass
        if attempts > 3 or "brute" in text:
            techs += ["T1110"]
        elif sev in ("CRITICAL", "HIGH"):
            # Only flag as brute force if it's high severity (meaning many attempts logged)
            techs += ["T1110"]

    elif "password" in text or "shadow" in text or "credential" in text:
        techs += ["T1003"]

    # ── Network / C2 ─────────────────────────────────────────
    elif cat == "network" or "port" in src or "net" in src:
        port = finding.get("dst_port") or finding.get("port")
        try: port_i = int(str(port).strip())
        except: port_i = 0
        # Malicious / common C2 ports
        if port_i in (4444, 1337, 31337, 9001, 6666, 6667, 8080, 8888):
            techs += ["T1571", "T1041"]
        elif "ssh" in text:
            techs += ["T1021.004"]
        elif port_i in (80, 443):
            techs += ["T1071"]
        else:
            techs += ["T1071"]

    # ── Execution (suspicious shells, cmds) ─────────────────
    elif cat == "process":
        if "bash" in text or "sh -c" in text or "/bin/sh" in text:
            techs += ["T1059.004"]
        if "nc " in text or "netcat" in text or "ncat" in text:
            techs += ["T1059.004", "T1095"]
        if "wget" in text or "curl" in text:
            techs += ["T1105"] if "T1105" in MITRE_TECHNIQUES else ["T1071"]
        if not techs:
            techs += ["T1059"]

    # ── Defense Evasion / Log clearing ───────────────────────
    elif "history" in cat or "bash_history" in src:
        if "cleared" in text or "empty" in text or "removed" in text:
            techs += ["T1070.003"]

    elif cat == "syslog" or cat == "kernel":
        if "module load" in text or "kernel module" in text:
            techs += ["T1014"]
        if "log clear" in text or "log removed" in text:
            techs += ["T1070.002"]

    # ── Discovery ────────────────────────────────────────────
    elif cat == "recent" or cat == "files":
        techs += ["T1083"]

    # ── Hardware / USB ───────────────────────────────────────
    # USB events are normal — only map to ATT&CK if severity is high
    elif (cat == "usb" or "usb" in src) and sev in ("CRITICAL", "HIGH"):
        techs += ["T1200", "T1091"]

    # ── Firewall changes (UFW) ──────────────────────────────
    elif cat == "ufw" or "ufw" in src or "firewall" in text:
        techs += ["T1562.004"]

    # ── Package / software changes ──────────────────────────
    elif cat == "software" or cat == "dpkg":
        if "purg" in text or "removed" in text:
            techs += ["T1070"]

    # ── Deleted files ────────────────────────────────────────
    elif "deleted" in cat:
        techs += ["T1070"]

    # ── Memory anomalies → could indicate rootkit ───────────
    elif "memory" in cat:
        if sev in ("CRITICAL", "HIGH"):
            techs += ["T1014"]

    # Deduplicate while preserving order
    seen, out = set(), []
    for t in techs:
        if t not in seen and t in MITRE_TECHNIQUES:
            seen.add(t); out.append(t)
    return out


def enrich_mitre(report):
    """
    Add MITRE ATT&CK metadata to findings.
    Only MEDIUM+ findings are mapped (filters out informational noise).
    Coverage statistics count UNIQUE incidents, not raw event counts.
    """
    tactic_count    = {}   # tactic → count of unique incidents
    technique_count = {}   # technique_id → count of unique incidents
    seen_incidents  = {}   # technique_id → set of unique fingerprints

    findings = report.get("findings", [])

    for f in findings:
        sev = f.get("severity", "INFO")
        # Skip informational/low findings — they create noise
        if sev not in ("CRITICAL", "HIGH", "MEDIUM"):
            f["mitre"] = []
            continue

        techs = _detect_mitre(f)
        if not techs:
            f["mitre"] = []
            continue

        f["mitre"] = []
        for t in techs:
            info = MITRE_TECHNIQUES.get(t, {})
            f["mitre"].append({
                "id":     t,
                "name":   info.get("name", t),
                "tactic": info.get("tactic", "Unknown"),
                "url":    info.get("url", ""),
            })

            # Build fingerprint to deduplicate incidents
            # Same technique from same source IP / user / file = one incident
            ip   = f.get("src_ip") or f.get("dst_ip") or ""
            user = f.get("user") or f.get("username") or ""
            path = f.get("path") or f.get("file_path") or ""
            fingerprint = f"{t}|{ip}|{user}|{path}"

            seen_incidents.setdefault(t, set())
            if fingerprint not in seen_incidents[t]:
                seen_incidents[t].add(fingerprint)
                technique_count[t] = technique_count.get(t, 0) + 1
                tactic = info.get("tactic", "Unknown")
                tactic_count[tactic] = tactic_count.get(tactic, 0) + 1

    # Build coverage summary
    coverage = {
        "tactics":          tactic_count,
        "techniques":       technique_count,
        "total_techniques": len(technique_count),
        "total_tactics":    len(tactic_count),
        "techniques_full":  [
            {
                "id":     tid,
                "name":   MITRE_TECHNIQUES[tid]["name"],
                "tactic": MITRE_TECHNIQUES[tid]["tactic"],
                "url":    MITRE_TECHNIQUES[tid]["url"],
                "count":  cnt,
            }
            for tid, cnt in sorted(technique_count.items(), key=lambda x: -x[1])
        ],
    }
    report["mitre_coverage"] = coverage
    return coverage
