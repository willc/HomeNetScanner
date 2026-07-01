#!/usr/bin/env python3
"""
HomeNetScanner

Scans the local subnet with nmap, tracks devices across runs in a JSON
state file, and writes an HTML "Home Network Map" dashboard. Intended to
run from cron every 15 minutes on an always-on Linux box (e.g. the same
Raspberry Pi running Pi-hole), writing into its web root.
"""

import argparse
import subprocess
import sys
import os
import html
import json
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

TS_FMT = "%Y-%m-%d %H:%M:%S"

DEFAULT_OUTPUT_DIR = os.environ.get("NETSCAN_OUTPUT_DIR", "/var/www/html/netmap")
DEFAULT_STATE_PATH = os.environ.get("NETSCAN_STATE_PATH", "/opt/homenetscanner/state.json")
DEFAULT_SUBNET = os.environ.get("NETSCAN_SUBNET") or None
DEFAULT_RETENTION_DAYS = int(os.environ.get("NETSCAN_RETENTION_DAYS", "30"))
DEFAULT_REFRESH_MINUTES = int(os.environ.get("NETSCAN_REFRESH_MINUTES", "15"))
NMAP_TIMEOUT = 120  # seconds

# --- helpers -------------------------------------------------------------


def log(msg):
    ts = datetime.now().strftime(TS_FMT)
    print(f"[{ts}] {msg}", file=sys.stderr)


def detect_subnet():
    out = subprocess.run(
        ["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, check=True
    ).stdout
    for line in out.splitlines():
        parts = line.split()
        iface = parts[1]
        if iface == "lo":
            continue
        cidr = parts[3]
        net = ipaddress.ip_network(cidr, strict=False)
        return str(net)
    raise RuntimeError("Could not auto-detect a local subnet; pass --subnet explicitly")


def run_scan(subnet):
    cmd = ["nmap", "-sn", "-oX", "-", subnet]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT)

    if result.returncode != 0 and "Failed to open device" in result.stderr:
        # Raw Ethernet-frame injection (dnet) can fail to open the interface
        # even as root on some hosts (VPN/security software holding the
        # packet-capture layer). Fall back to raw-IP pings, at the cost of
        # MAC/vendor info (which comes from ARP replies).
        log("nmap couldn't open the network device for ARP scanning. Retrying with")
        log("--send-ip (no MAC/vendor data)...")
        cmd = ["nmap", "-sn", "--send-ip", "-oX", "-", subnet]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT)

    if result.returncode != 0:
        raise RuntimeError(f"nmap failed ({result.returncode}): {result.stderr.strip()}")
    return ET.fromstring(result.stdout)


def parse_hosts(root):
    devices = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip, mac, vendor, hostname = None, None, None, None
        for addr in host.findall("address"):
            addrtype = addr.get("addrtype")
            if addrtype == "ipv4":
                ip = addr.get("addr")
            elif addrtype == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor") or ""

        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        if ip:
            devices.append(
                {"ip": ip, "hostname": hostname or "", "mac": mac or "", "vendor": vendor or ""}
            )
    return devices


def load_state(state_path):
    if os.path.exists(state_path):
        with open(state_path) as f:
            return json.load(f)
    return {}


def save_state(state, state_path):
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    tmp = state_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, state_path)


def update_state(state, seen_devices, now, retention_days):
    now_str = now.strftime(TS_FMT)
    seen_keys = set()

    for d in seen_devices:
        key = d["mac"] or d["ip"]
        seen_keys.add(key)
        entry = state.get(key, {})
        entry.update(
            {
                "ip": d["ip"],
                "mac": d["mac"] or entry.get("mac", ""),
                "hostname": d["hostname"] or entry.get("hostname", ""),
                "vendor": d["vendor"] or entry.get("vendor", ""),
                "status": "online",
                "last_seen": now_str,
                "first_seen": entry.get("first_seen", now_str),
            }
        )
        state[key] = entry

    cutoff = now - timedelta(days=retention_days)
    for key, entry in list(state.items()):
        if key in seen_keys:
            continue
        entry["status"] = "offline"
        try:
            last_seen = datetime.strptime(entry["last_seen"], TS_FMT)
        except (KeyError, ValueError):
            last_seen = cutoff
        if last_seen < cutoff:
            del state[key]

    return state


def render_html(state, subnet, scan_seconds, now, refresh_minutes):
    devices = list(state.values())
    online = sorted(
        (d for d in devices if d["status"] == "online"),
        key=lambda d: ipaddress.ip_address(d["ip"]),
    )
    offline = sorted(
        (d for d in devices if d["status"] == "offline"),
        key=lambda d: d["last_seen"],
        reverse=True,
    )
    ordered = online + offline

    def esc(v):
        return html.escape(v) if v else '<span class="muted">&mdash;</span>'

    rows = []
    for d in ordered:
        badge_class = "online" if d["status"] == "online" else "offline"
        rows.append(
            "      <tr>"
            f'<td><span class="badge {badge_class}">{d["status"]}</span></td>'
            f'<td class="ip">{esc(d["ip"])}</td>'
            f'<td>{esc(d["hostname"])}</td>'
            f'<td class="mac">{esc(d["mac"])}</td>'
            f'<td>{esc(d["vendor"])}</td>'
            f'<td class="muted">{esc(d["last_seen"])}</td>'
            "</tr>"
        )
    rows_html = "\n".join(rows) if rows else '      <tr><td colspan="6" class="muted">No devices found</td></tr>'

    now_str = now.strftime(TS_FMT)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Home Network Map</title>
<meta http-equiv="refresh" content="{refresh_minutes * 60}">
<style>
  :root {{ color-scheme: dark light; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #10141a;
    color: #e6e9ef;
    margin: 0;
    padding: 2rem 1.5rem 4rem;
  }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 0.75rem;
    max-width: 1000px;
    margin: 0 auto 0.25rem;
  }}
  h1 {{ font-size: 1.4rem; margin: 0; }}
  .stats {{ display: flex; gap: 0.6rem; }}
  .stat {{
    border-radius: 999px;
    padding: 0.25rem 0.8rem;
    font-size: 0.82rem;
    font-weight: 600;
    white-space: nowrap;
  }}
  .stat.online {{ background: #16301f; color: #4ade80; }}
  .stat.offline {{ background: #2a1c1c; color: #f2a3a3; }}
  .meta {{
    color: #8b93a3;
    font-size: 0.82rem;
    margin: 0 auto 1.5rem;
    max-width: 1000px;
  }}
  table {{
    width: 100%;
    max-width: 1000px;
    margin: 0 auto;
    border-collapse: collapse;
    background: #171c25;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,0.4);
  }}
  th, td {{
    text-align: left;
    padding: 0.6rem 0.9rem;
    border-bottom: 1px solid #232a36;
    font-size: 0.88rem;
  }}
  th {{
    background: #1d2430;
    color: #9aa4b8;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.72rem;
    letter-spacing: 0.04em;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1c2330; }}
  td.ip {{ font-variant-numeric: tabular-nums; color: #7fd0ff; }}
  td.mac {{
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.8rem;
    color: #b6bdca;
  }}
  .muted {{ color: #556074; }}
  .badge {{
    display: inline-block;
    border-radius: 4px;
    padding: 0.15rem 0.5rem;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }}
  .badge.online {{ background: #16301f; color: #4ade80; }}
  .badge.offline {{ background: #2a1c1c; color: #f2a3a3; }}
</style>
</head>
<body>
  <div class="header">
    <h1>Home Network Map</h1>
    <div class="stats">
      <span class="stat online">Online: {len(online)}</span>
      <span class="stat offline">Tracked Offline: {len(offline)}</span>
    </div>
  </div>
  <div class="meta">
    Subnet {html.escape(subnet)} &middot; scan took {scan_seconds:.1f}s &middot;
    last updated {now_str} (refreshes every {refresh_minutes} min)
  </div>
  <table>
    <thead>
      <tr><th>Status</th><th>IP Address</th><th>Hostname</th><th>MAC Address</th><th>Vendor</th><th>Last Seen</th></tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>
</body>
</html>
"""


def write_atomic(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(content)
    os.chmod(tmp_path, 0o644)
    os.replace(tmp_path, path)


def parse_args():
    p = argparse.ArgumentParser(description="Scan the local subnet and render a device dashboard.")
    p.add_argument("--subnet", default=DEFAULT_SUBNET, help="CIDR to scan, e.g. 192.168.1.0/24 (default: auto-detect)")
    p.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory to write index.html into")
    p.add_argument("--state-path", default=DEFAULT_STATE_PATH, help="Path to the persistent JSON state file")
    p.add_argument("--retention-days", type=int, default=DEFAULT_RETENTION_DAYS, help="Days to keep offline devices before dropping them")
    p.add_argument("--refresh-minutes", type=int, default=DEFAULT_REFRESH_MINUTES, help="Value written into the page's meta-refresh tag")
    return p.parse_args()


def main():
    args = parse_args()
    subnet = args.subnet or detect_subnet()
    log(f"Scanning {subnet}")
    now = datetime.now()
    root = run_scan(subnet)
    elapsed = (datetime.now() - now).total_seconds()
    seen = parse_hosts(root)
    log(f"Found {len(seen)} devices online in {elapsed:.1f}s")

    state = load_state(args.state_path)
    state = update_state(state, seen, now, args.retention_days)
    save_state(state, args.state_path)

    page = render_html(state, subnet, elapsed, now, args.refresh_minutes)
    output_path = os.path.join(args.output_dir, "index.html")
    write_atomic(output_path, page)
    log(f"Wrote {output_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)
