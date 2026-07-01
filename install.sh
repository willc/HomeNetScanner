#!/usr/bin/env bash
# Installs HomeNetScanner: copies the script to /opt/homenetscanner,
# installs arp-scan and nmap if missing, and registers a root cron job
# that runs every 15 minutes.
set -euo pipefail

INSTALL_DIR="/opt/homenetscanner"
CRON_FILE="/etc/cron.d/homenetscanner"
OUTPUT_DIR="${NETSCAN_OUTPUT_DIR:-/var/www/html/netmap}"

if [[ $EUID -ne 0 ]]; then
  echo "This installer needs root (it writes to /opt, /etc/cron.d, and $OUTPUT_DIR)." >&2
  echo "Re-run with: sudo ./install.sh" >&2
  exit 1
fi

# arp-scan is the preferred backend (more reliable than nmap's ARP mode in
# practice); nmap is kept installed as an automatic fallback.
MISSING=()
command -v arp-scan >/dev/null 2>&1 || MISSING+=("arp-scan")
command -v nmap >/dev/null 2>&1 || MISSING+=("nmap")
if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "Installing ${MISSING[*]}..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y "${MISSING[@]}"
  else
    echo "Could not find apt-get. Install ${MISSING[*]} manually, then re-run this script." >&2
    exit 1
  fi
fi

echo "Installing script to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp "$(dirname "$0")/netscan.py" "$INSTALL_DIR/netscan.py"
chmod +x "$INSTALL_DIR/netscan.py"

mkdir -p "$OUTPUT_DIR"

echo "Registering cron job at $CRON_FILE (every 15 minutes, as root)..."
cat > "$CRON_FILE" <<EOF
NETSCAN_OUTPUT_DIR=$OUTPUT_DIR
*/15 * * * * root /usr/bin/python3 $INSTALL_DIR/netscan.py >> /var/log/homenetscanner.log 2>&1
EOF
chmod 644 "$CRON_FILE"

echo "Running an initial scan..."
NETSCAN_OUTPUT_DIR="$OUTPUT_DIR" python3 "$INSTALL_DIR/netscan.py"

echo
echo "Done. Dashboard written to $OUTPUT_DIR/index.html"
echo "If that directory is served by a web server already running on this box"
echo "(e.g. Pi-hole's lighttpd at /var/www/html), browse to it at:"
echo "  http://<this-device-ip-or-hostname>/netmap/"
