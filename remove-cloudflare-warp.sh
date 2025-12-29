# how to use: sudo bash remove-cloudflare-warp.sh
## chmod +x remove-cloudflare-warp.sh
### sudo ./remove-cloudflare-warp.sh


#!/bin/bash
set -euo pipefail

echo "=== Cloudflare WARP macOS Cleanup ==="

# Must run as root
if [[ $EUID -ne 0 ]]; then
  echo "❌ Run this script with sudo"
  exit 1
fi

echo "[1/9] Stopping WARP processes…"
pkill -f warp 2>/dev/null || true
pkill -f Cloudflare 2>/dev/null || true

echo "[2/9] Unloading LaunchDaemons…"
LAUNCHD_PLIST="/Library/LaunchDaemons/com.cloudflare.warp.plist"
if [[ -f "$LAUNCHD_PLIST" ]]; then
  launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true
  rm -f "$LAUNCHD_PLIST"
fi

echo "[3/9] Removing application bundle…"
rm -rf "/Applications/Cloudflare WARP.app"

echo "[4/9] Removing System Extensions (if present)…"
# List system extensions and attempt uninstall if found
systemextensionsctl list 2>/dev/null | grep -i cloudflare || true

# Common Cloudflare WARP identifiers (safe if not present)
TEAM_ID="9C8YV2L5XW"
BUNDLE_ID="com.cloudflare.1dot1dot1dot1.macos.network-extension"

systemextensionsctl uninstall "$TEAM_ID" "$BUNDLE_ID" 2>/dev/null || true

echo "[5/9] Removing support files (system-wide)…"
rm -rf /Library/Application\ Support/Cloudflare
rm -rf /Library/Logs/Cloudflare
rm -rf /Library/Preferences/com.cloudflare.*
rm -rf /Library/LaunchAgents/com.cloudflare.*

echo "[6/9] Removing support files (user)…"
# Handle all users with home directories
for HOME_DIR in /Users/*; do
  [[ -d "$HOME_DIR" ]] || continue
  rm -rf "$HOME_DIR/Library/Application Support/Cloudflare"
  rm -rf "$HOME_DIR/Library/Logs/Cloudflare"
  rm -rf "$HOME_DIR/Library/Preferences/com.cloudflare.*"
done

echo "[7/9] Removing configuration profiles (if any)…"
profiles list 2>/dev/null | grep -i cloudflare || true

# Attempt removal by identifier if present
profiles list 2>/dev/null | awk '/cloudflare/{print $NF}' | while read -r PID; do
  profiles remove -identifier "$PID" 2>/dev/null || true
done

echo "[8/9] Flushing DNS cache…"
dscacheutil -flushcache
killall -HUP mDNSResponder 2>/dev/null || true

echo "[9/9] Verification…"
echo "→ Remaining Cloudflare files:"
find /Library -iname '*cloudflare*' 2>/dev/null || true

echo "→ Remaining Cloudflare processes:"
ps aux | grep -i cloudflare | grep -v grep || true

echo
echo "✅ Cleanup complete."
echo "ℹ️ A reboot is STRONGLY recommended to fully detach the Network Extension."
echo "   You can reboot now with: sudo shutdown -r now"
