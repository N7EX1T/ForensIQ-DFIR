#!/usr/bin/env bash
# ForensIQ v2.0 — Uninstaller
set -e

echo "Uninstalling ForensIQ..."

rm -rf "$HOME/.local/share/forensiq"
rm -f  "$HOME/.local/bin/forensiq"
rm -f  "$HOME/.local/share/applications/forensiq.desktop"

update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true

echo "✓ ForensIQ removed."
echo ""
echo "User data is preserved at: ~/.forensiq/"
echo "To remove user data too:    rm -rf ~/.forensiq"
