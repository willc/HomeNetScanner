# HomeNetScanner

A self-hosted "who's on my network" dashboard. Runs on an always-on Linux
box (a Raspberry Pi running Pi-hole is the reference setup) as a cron job,
scans the local subnet every 15 minutes with `nmap`, and writes a static
HTML dashboard you can browse to from any device on your network.

Tracks devices across scans, so it can show not just who's online right
now, but who *was* here recently and dropped off.

![status](https://img.shields.io/badge/status-active-brightgreen)

## Features

- ARP-based subnet sweep — prefers `arp-scan` (more reliable in practice),
  falls back to `nmap -sn` automatically if `arp-scan` isn't installed or
  fails. Picks up IP, MAC address, and vendor from whichever ran; hostname
  comes from the script's own parallel reverse-DNS lookups
- Persists state in a small JSON file keyed by MAC address, so a device's
  history survives DHCP lease changes
- Devices that go quiet are kept as "Tracked Offline" for 30 days (configurable)
  before being dropped, instead of just vanishing from the page
- Zero runtime dependencies — pure Python 3 standard library
- Single static HTML file output, so it works with whatever web server is
  already running on the box (e.g. the lighttpd instance Pi-hole ships with)
- Flags decoy ARP replies as **suspicious** instead of trusting them (e.g.
  the network address itself appearing as a "host", or MACs from an IEEE
  OUI block unused since the early 1980s) — those rows are excluded from
  persistent tracking so they can't bloat state.json

## Requirements

- Linux with `arp-scan` and/or `nmap` installed (the installer installs both via `apt`)
- Python 3.7+
- Root/cron access, since ARP-based host discovery needs raw sockets
- A web server already serving the target output directory (Pi-hole's
  lighttpd serves `/var/www/html` out of the box)

## Install

```bash
git clone https://github.com/willc/HomeNetScanner.git
cd HomeNetScanner
sudo ./install.sh
```

This will:

1. Install `nmap` if it isn't already present
2. Copy `netscan.py` to `/opt/homenetscanner/`
3. Create `/var/www/html/netmap/` (or your configured output dir)
4. Register a root cron job at `/etc/cron.d/homenetscanner` that runs every 15 minutes
5. Run an initial scan so the page exists immediately

Then browse to `http://<pi-ip-or-hostname>/netmap/`.

## Configuration

Set these as environment variables (e.g. in the cron file, or export them
before running manually) or pass the equivalent CLI flag:

| Env var                     | Flag                  | Default                          | Description |
|------------------------------|------------------------|-----------------------------------|--------------|
| `NETSCAN_OUTPUT_DIR`         | `--output-dir`         | `/var/www/html/netmap`            | Where `index.html` is written |
| `NETSCAN_STATE_PATH`         | `--state-path`         | `/opt/homenetscanner/state.json`  | Persistent device history |
| `NETSCAN_SUBNET`             | `--subnet`             | auto-detected                     | CIDR to scan, e.g. `192.168.1.0/24` |
| `NETSCAN_RETENTION_DAYS`     | `--retention-days`     | `30`                              | Days to keep an offline device before dropping it |
| `NETSCAN_REFRESH_MINUTES`    | `--refresh-minutes`    | `15`                              | Value written into the page's auto-refresh tag |

Run manually to test:

```bash
sudo python3 netscan.py --subnet 192.168.1.0/24
```

## How it works

Each run:

1. `nmap -sn <subnet>` performs an ARP ping sweep and returns XML with
   live hosts, their MAC addresses, vendors, and any reverse-DNS hostname
2. Results are merged into `state.json`, keyed by MAC (or IP if no MAC
   was returned) — devices seen this run are marked `online`, devices
   missing are marked `offline` and kept until the retention window expires
3. The merged state is rendered into a single self-contained HTML file

## License

MIT — see [LICENSE](LICENSE).

## Usage

```bash
python3 main.py
```
