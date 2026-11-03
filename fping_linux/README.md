# Ping Check Enhanced — Network Monitor

Linux-only multi-host ICMP reachability and latency dashboard built with **PySide6** and **fping**.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![PySide6](https://img.shields.io/badge/UI-PySide6-green)
![Platform](https://img.shields.io/badge/Platform-Linux-blue)

---

## Features

- **CIDR Subnet Auto-Expansion** — directly enter subnets such as `10.128.7.0/24` or `192.168.1.0/28`; the input parser automatically expands usable host addresses (filtering network/broadcast addresses) while preserving your clean CIDR string in the UI input and saved config, protected by a safety prefix threshold (`/22` - max 1022 hosts)
- **RFC 3550 Interarrival Jitter** — telemetry calculates compliant continuous network jitter in target inspection
- **Multi-host monitoring** — one fping process schedules the full target list and reports both replies and timeouts; the application imposes no host concurrency ceiling
- **DNS Issue Isolation & Multi-Check Verification** — hostnames with name resolution errors are vetted with multiple DNS lookups, isolated from the live telemetry stream and chart, and tracked in a dedicated DNS Inspector with live filtering, clipboard copy, and export
- **Live dashboard** — status, sequence, latency, packet loss, consecutive failures with in-place cell updates
- **Latency history chart** — rolling-window multi-host oscilloscope with 20 distinct high-contrast designer colours, area gradients, and glowing live pulse dots, focused on the top 20 active targets for maximum visual legibility and 60 FPS performance
- **No-reply panel** — shows targets that did not answer ICMP; a timeout does not prove the host is offline
- **High-performance table sorting** — $O(1)$ numeric sorting by column without regex parsing; clicking headers (including Packet Loss) sorts immediately without UI freezing, row shifting, or artificial ICMP latency spikes
- **Host detail dialog** — double-click a row for stats + recent timeline
- **Theme toggle** — modern dark / light mode (🌙 / ☀️) with responsive design
- **Import hosts** — load from `.txt` or `.csv` (supports 500+ host lists)
- **Config save/load** — atomically persists hosts, settings, and theme to `fping_linux_config.json`
- **Timestamped secure exports** — TXT, CSV, and XLSX exports automatically include timestamped filenames (`network_report_YYYYMMDD_HHMMSS.<ext>`) to prevent overwriting, with built-in CSV formula injection (DDE) sanitization and UTF-8 BOM encoding
- **Search / filter** — live filter on the host table placed beside telemetry controls
- **Log limiting** — timeline capped at 1000 entries per host

---

## Requirements

```bash
python -m pip install -r requirements_fping_linux.txt
```

This installs **PySide6** for the desktop UI.

### fping setup

Install **fping 5.0 or newer** using your Linux distribution's package manager. The app checks for fping at startup and will not start monitoring if it is missing or too old. JSON output is used when available; fping 5.0–5.4 uses standard per-probe text output.

The app resolves hostnames concurrently to IPv4 addresses before starting one fping process, avoiding a long serial DNS-resolution pause for large lists. Targets that do not resolve are reported as **DNS Error** rather than remaining queued. fping then schedules the resolved addresses in a paced round-robin loop. The app keeps output for successful replies and timeouts so both appear in the live table. The GUI exposes its payload size (`-b`), global send gap in milliseconds (`-i`), per-host repeat period in seconds (`-p`), and timeout in seconds (`-t`). The global gap defaults to 10 ms, but is automatically reduced when needed so a large target list can meet the requested per-host period. fping's safe minimum global gap is 1 ms; if the target count makes the requested period impossible even at that rate, the app uses and displays the fastest achievable period. The per-host period is kept at least as long as the timeout. The app has no fixed maximum host count or parallel setting; actual rate and capacity depend on fping, Linux socket permissions, system resources, and the network.

Install fping from your distribution package repository so its ICMP permissions are configured by the package. The application does not need to run as root.

---

## Quick start

```bash
python -m pip install -r requirements_fping_linux.txt
python fping_linux.py
```

1. Enter hosts (comma-separated) or click **Import**. `IP-test.txt` and `ping_domains.txt` are supplied import samples.
2. Adjust payload size (`-b`), global send gap (`-i`), host period (`-p`), timeout (`-t`), and chart history if needed.
3. Click **Start Monitoring**.
4. Double-click a row for details; use **Export TXT / CSV** when finished.

---

## UI overview

| Area | Description |
|------|-------------|
| **Header** | Title, theme toggle, and system health status cards (Fleet Monitored, Reachability %, Average Latency, Packet Loss) |
| **Config card** | Target list entry, import, save settings, payload/gap/period/timeout adjustments, Start/Stop monitoring |
| **Live Telemetry Bar** | Live search filter placed directly alongside the **DNS Issues Pill Badge** (`⚠ X DNS Issues`) |
| **DNS Inspector Dialog** | Opened via the DNS pill badge; displays all unresolvable hosts, detection timestamp, exact error reason, search bar, and one-click clipboard copy / CSV export |
| **Live Telemetry Table** | Main streaming table with $O(1)$ smooth column sorting (Host, Status, Sequence, Latency, Loss %, Failures); unresolvable DNS hosts are excluded to keep telemetry clean |
| **Latency History** | Custom high-performance rolling oscilloscope displaying real-time telemetry waveforms for the top 20 active fleet targets for maximum visual clarity |
| **No ICMP Reply** | Targets that returned no echo reply before timeout |
| **Footer** | Summary counts, reachable targets, and aggregate loss percentage |

---

## Config file

On first **Save Config**, settings are written to:

```
fping_linux_config.json
```

The path is anchored to the application directory, so launching from another working directory uses the same settings file. Writes are atomic. Invalid config is reported and the application continues with defaults; unsupported values are rejected without partially applying the file.

Fields:

```json
{
  "hosts": "8.8.8.8, 1.1.1.1, google.com",
  "packet_size": 56,
  "interval": 2.0,
  "timeout": 2.0,
  "send_gap_ms": 10,
  "history_points": 60,
  "dark_theme": true
}
```

Loaded automatically on startup if present.

---

## Export formats

Export dialogs automatically generate unique timestamped default filenames (`network_report_YYYYMMDD_HHMMSS.<ext>`) to guarantee exports are never overwritten by default:

### TXT report (`network_report_YYYYMMDD_HHMMSS.txt`)
- Header includes `Generated: YYYY-MM-DD HH:MM:SS` timestamp
- Overview metrics and fleet-wide packet loss summary
- Target aggregate metrics (sent, received, loss %, min/max/avg latency)
- Unresolved DNS hostnames section isolated from live telemetry
- Targets with no ICMP reply at export time
- Full sequence timeline per host

### CSV report (`network_report_YYYYMMDD_HHMMSS.csv`)
- **Formula Injection Protection**: Neutralizes CSV/DDE injection attacks (`=`, `+`, `-`, `@`, `\t`, `\r` escaped with single quote)
- **UTF-8 with BOM (`utf-8-sig`)**: Prevents character corruption when opened in Microsoft Excel
- Per-target summary metrics, DNS failure records, no-reply timeouts, and probe sequence rows

### Excel workbook (`network_report_YYYYMMDD_HHMMSS.xlsx`)
- **Summary Info**: Formatted overview metrics and generation metadata
- **Host Details**: Complete host metrics table with styling
- **Probe Details**: Sequence-by-sequence probe audit trail
- **DNS Failures**: Dedicated sheet for unresolvable targets with timestamps and root-cause details

### DNS issues report (`dns_issues_YYYYMMDD_HHMMSS.csv`)
- Direct export from the DNS Inspector dialog listing all unresolvable domain names, validation attempt count, error message, and timestamp

---

## Project layout

```
.
├── README.md
├── fping_linux.py          # PySide6 application and dashboard
├── fping_linux_probes.py                # Linux fping backend and worker task
├── fping_linux_config.json # Saved runtime settings
├── IP-test.txt              # Supplied host-list import sample
├── ping_domains.txt         # Supplied 500-host import sample (used by tests)
├── requirements_fping_linux.txt
└── tests/
    ├── test_fping_linux.py
    └── test_fping_linux_probes.py
```

Run the regression tests with:

```bash
python -m unittest discover -s tests
```

---

## Notes & limitations

- Many public websites block or rate-limit ICMP while their web service remains available. “No ICMP Reply” means only that no echo reply arrived before timeout.
- A missing or permission-blocked fping process is reported as a probe error and excluded from ICMP packet-loss totals. A host that times out is shown as **No ICMP Reply**.
- The app imposes no fixed maximum target count or concurrency cap. fping and the Linux system still have practical throughput, resource, and permission limits.
- The default ICMP timeout is 2 seconds. fping repeats each target at the greater of the configured interval and timeout to avoid unreliable timeout handling.
- Chart history is bounded by the “Chart History” spin box (default 60 probes); aggregate min/max/average use the full run.
- Timeline / log rows are capped at 1000 entries per host to bound memory.
- Stop requests terminate the fping process and outstanding probes before enabling a new run or report export.
- Probes run through one fping process managed by a background event loop.

---

## License

Use and modify freely for personal or internal tooling. fping is distributed under the BSD license; follow its license terms when redistributing it.
