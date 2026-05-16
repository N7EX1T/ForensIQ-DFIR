#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ForensIQ v3.0 — One-click installer for Linux
# Installs ForensIQ as a standalone desktop application
# Egor Gubarev, 2026
# ─────────────────────────────────────────────────────────────────────────────

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       ForensIQ v3.0 — Installer            ║${NC}"
echo -e "${CYAN}║       DFIR Analyzer for Linux              ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
echo ""

# Paths
INSTALL_DIR="$HOME/.local/share/forensiq"
BIN_PATH="$HOME/.local/bin/forensiq"
DESKTOP_FILE="$HOME/.local/share/applications/forensiq.desktop"
ICON_PATH="$INSTALL_DIR/icon.png"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Detect distribution
DISTRO=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
fi
echo -e "${CYAN}Detected distribution:${NC} $DISTRO"

# Choose authentication method
AUTH_METHOD="pkexec"
if [ "$DISTRO" = "kali" ] || [ "$DISTRO" = "parrot" ]; then
    AUTH_METHOD="sudo"
    echo -e "${YELLOW}Note:${NC} Using sudo for root access (Kali/Parrot has known polkit issues)"
elif ! command -v pkexec >/dev/null 2>&1; then
    AUTH_METHOD="sudo"
fi
echo -e "${CYAN}Auth method:${NC} $AUTH_METHOD"
echo ""

echo -e "${CYAN}[1/5]${NC} Installing system dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y python3 python3-pip python3-venv 2>/dev/null || true
fi

echo -e "${CYAN}[2/5]${NC} Installing Python dependencies..."
pip3 install --user --break-system-packages \
    PyQt6 PyQt6-WebEngine reportlab 2>/dev/null \
    || pip3 install --user PyQt6 PyQt6-WebEngine reportlab \
    || pip3 install PyQt6 PyQt6-WebEngine reportlab --break-system-packages

echo -e "${CYAN}[3/5]${NC} Copying files to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$HOME/.local/bin"
mkdir -p "$HOME/.local/share/applications"

cp "$SCRIPT_DIR/forensiq_app.py"    "$INSTALL_DIR/"
cp "$SCRIPT_DIR/forensiq_engine.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/ForensIQ.html"      "$INSTALL_DIR/"

# Generate icon
python3 - <<PYEOF
from PyQt6.QtGui import QImage, QPainter, QColor, QBrush, QPen
from PyQt6.QtCore import Qt, QRectF, QPointF
from PyQt6.QtWidgets import QApplication
import sys
app = QApplication(sys.argv)
SIZE = 256
img = QImage(SIZE, SIZE, QImage.Format.Format_ARGB32)
img.fill(Qt.GlobalColor.transparent)
p = QPainter(img)
p.setRenderHint(QPainter.RenderHint.Antialiasing)
p.setBrush(QBrush(QColor("#1a1a2e")))
p.setPen(QPen(QColor("#ff4d4d"), 8))
p.drawRoundedRect(QRectF(40, 30, 176, 200), 20, 20)
p.setBrush(QBrush(QColor("#ff4d4d")))
p.setPen(QPen(QColor("#fff"), 6))
p.drawEllipse(QPointF(120, 110), 38, 38)
p.setPen(QPen(QColor("#ff4d4d"), 14, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
p.drawLine(150, 140, 185, 175)
p.end()
img.save("$ICON_PATH")
print("  icon: $ICON_PATH")
PYEOF

echo -e "${CYAN}[4/5]${NC} Creating launcher..."

# Launcher script — auth method depends on distribution
if [ "$AUTH_METHOD" = "pkexec" ]; then
cat > "$BIN_PATH" <<'LAUNCHER'
#!/usr/bin/env bash
# ForensIQ launcher (pkexec)
INSTALL_DIR="$HOME/.local/share/forensiq"
cd "$INSTALL_DIR"
if [ "$EUID" -ne 0 ]; then
    if command -v pkexec >/dev/null 2>&1; then
        exec pkexec env DISPLAY="$DISPLAY" XAUTHORITY="$XAUTHORITY" \
            QT_QPA_PLATFORM=xcb HOME="$HOME" \
            python3 "$INSTALL_DIR/forensiq_app.py" "$@"
    else
        exec sudo -E python3 "$INSTALL_DIR/forensiq_app.py" "$@"
    fi
else
    exec python3 "$INSTALL_DIR/forensiq_app.py" "$@"
fi
LAUNCHER
else
# Sudo-based launcher for Kali/Parrot
cat > "$BIN_PATH" <<'LAUNCHER'
#!/usr/bin/env bash
# ForensIQ launcher (sudo — for Kali/Parrot)
INSTALL_DIR="$HOME/.local/share/forensiq"
cd "$INSTALL_DIR"
if [ "$EUID" -ne 0 ]; then
    # Try graphical sudo first, fall back to terminal sudo
    if command -v gnome-terminal >/dev/null 2>&1; then
        exec gnome-terminal -- bash -c "sudo -E python3 '$INSTALL_DIR/forensiq_app.py' || read -p 'Press Enter to close...'"
    elif command -v xterm >/dev/null 2>&1; then
        exec xterm -e "sudo -E python3 '$INSTALL_DIR/forensiq_app.py'; read -p 'Press Enter...'"
    elif command -v konsole >/dev/null 2>&1; then
        exec konsole -e bash -c "sudo -E python3 '$INSTALL_DIR/forensiq_app.py' || read -p 'Press Enter...'"
    else
        # No terminal found — try sudo directly (will fail in pure GUI launches)
        exec sudo -E python3 "$INSTALL_DIR/forensiq_app.py" "$@"
    fi
else
    exec python3 "$INSTALL_DIR/forensiq_app.py" "$@"
fi
LAUNCHER
fi
chmod +x "$BIN_PATH"

# Desktop entry
cat > "$DESKTOP_FILE" <<DESKTOP
[Desktop Entry]
Version=3.0
Type=Application
Name=ForensIQ
GenericName=DFIR Analyzer
Comment=Digital Forensics & Incident Response analyzer
Exec=$BIN_PATH
Icon=$ICON_PATH
Terminal=false
Categories=System;Security;Monitor;
Keywords=forensics;security;dfir;analyzer;
StartupNotify=true
DESKTOP

update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true

echo -e "${CYAN}[5/5]${NC} Installation complete!"
echo ""
echo -e "${GREEN}✓${NC} Installed to: ${INSTALL_DIR}"
echo -e "${GREEN}✓${NC} Launcher:     ${BIN_PATH}"
echo -e "${GREEN}✓${NC} Desktop:      ${DESKTOP_FILE}"
echo -e "${GREEN}✓${NC} Auth method:  ${AUTH_METHOD}"
echo ""
echo -e "${CYAN}How to launch:${NC}"
echo "  • From terminal:  forensiq"
echo "  • From app menu:  search for 'ForensIQ'"
echo ""
echo -e "${CYAN}User data:${NC} ~/.forensiq/"
echo ""
if [ "$AUTH_METHOD" = "pkexec" ] && [ "$DISTRO" = "kali" ]; then
    echo -e "${YELLOW}If polkit fails on Kali, run:${NC}"
    echo "  sudo chmod 4755 /usr/lib/polkit-1/polkit-agent-helper-1"
    echo "  sudo systemctl restart polkit"
    echo ""
fi
echo -e "${CYAN}To enable AI Analyst:${NC}"
echo "  Edit $INSTALL_DIR/forensiq_app.py → set AI_ENABLED = True"
echo ""
