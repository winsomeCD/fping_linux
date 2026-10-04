# Ping Check Enhanced — Network Monitor

Linux-only multi-host ICMP reachability and latency dashboard built with **PySide6** and **fping**.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![PySide6](https://img.shields.io/badge/UI-PySide6-green)
![Platform](https://img.shields.io/badge/Platform-Linux-blue)

---

## Features

- **Multi-host monitoring** — one fping process schedules the full target list; the application imposes no host concurrency ceiling
- **Live dashboard** — status, sequence, latency, packet loss, consecutive failures
- **Latency history chart** — rolling-window graph with per-host colours and legend
- **No-reply panel** — shows targets that did not answer ICMP; a timeout does not prove the host is offline
- **Sortable dashboards** — live and no-reply tables sort by column, with numeric fields ordered numerically
- **Host detail dialog** — double-click a row for stats + recent timeline
- **Theme toggle** — dark / light mode (🌙 / ☀️)
- **Import hosts** — load from `.txt` or `.csv`
- **Config save/load** — atomically persists hosts, settings, and theme to `ping_monitor_config.json`
- **Export reports** — TXT with a top-level overview, CSV with per-host summary and probe rows, or XLSX with Summary Info, Host Details, and Probe Details tabs
- **Search / filter** — live filter on the host table
- **Log limiting** — timeline capped at 1000 entries per host

---

## Requirements

```bash
python -m pip install -r requirements.txt
```

This installs **PySide6** for the desktop UI.

### fping setup

Install **fping 5.0 or newer** using your Linux distribution's package manager. The app checks for fping at startup and will not start monitoring if it is missing or too old. JSON output is used when available; fping 5.0–5.4 uses standard per-probe text output.

fping uses a single process to schedule probes across the target list in a paced round-robin loop. The app has no fixed maximum host count or parallel setting; actual rate and capacity depend on fping, Linux socket permissions, system resources, and the network.

Install fping from your distribution package repository so its ICMP permissions are configured by the package. The application does not need to run as root.

---

## Quick start

```bash
python -m pip install -r requirements.txt
python ping_monitor.py
```

1. Enter hosts (comma-separated) or click **Import**. `IP-test.txt` and `ping_domains.txt` are supplied import samples.
2. Adjust packet size, interval, timeout, and chart history if needed.
3. Click **Start Monitoring**.
4. Double-click a row for details; use **Export TXT / CSV** when finished.

---

## UI overview

| Area | Description |
|------|-------------|
| **Header** | Title, theme toggle, status pill (IDLE / MONITORING) |
| **Config card** | Host list, import, save config, spin boxes, Start/Stop, Clear, Export |
| **Filter** | Live search over host names/IPs |
| **Live Host Dashboard** | Main table (Host, Status, Sequence, Latency, Loss, Fails) |
| **Latency History** | Custom-painted rolling chart |
| **No ICMP Reply** | Targets that returned no echo reply before timeout |
| **Footer** | Aggregate host count and overall loss |

---

## Config file

On first **Save Config**, settings are written to:

```
ping_monitor_config.json
```

The path is anchored to the application directory, so launching from another working directory uses the same settings file. Writes are atomic. Invalid config is reported and the application continues with defaults; unsupported values are rejected without partially applying the file.

Fields:

```json
{
  "hosts": "8.8.8.8, 1.1.1.1, google.com",
  "packet_size": 56,
  "interval": 1.0,
  "timeout": 2.0,
  "history_points": 60,
  "dark_theme": true
}
```

Loaded automatically on startup if present.

---

## Export formats

### TXT report
- Overview counts and aggregate ICMP/latency metrics at the top
- Aggregated metrics (sent / recv / loss / min / max / avg)
- Targets with no ICMP reply at export time
- Full sequence timeline per host

### CSV report
- Summary metrics per target
- No-reply and per-probe rows
- Current ICMP reply and probe error state per target
- Recent probe rows (sequence, timestamp, result, latency or error)

### Excel workbook
- **Summary Info** overview tab
- **Host Details** metrics per target
- **Probe Details** recent probe timeline

---

## Project layout

```
.
├── README.md
├── ping_monitor.py          # PySide6 application and dashboard
├── probes.py                # Linux fping backend and worker task
├── ping_monitor_config.json # Saved runtime settings
├── IP-test.txt              # Supplied host-list import sample
├── ping_domains.txt         # Supplied 500-host import sample (used by tests)
├── requirements.txt
└── tests/
    ├── test_ping_monitor.py
    └── test_probes.py
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
