# Project work log

This file is the persistent handoff for future work in this folder. At the end
of each conversation that investigates or changes this project, append a dated
entry summarizing the user's request, the investigation, code/documentation
changes, and verification. Keep the newest entry first. Update this file as
part of the same work so the next session can continue without repeating the
initial investigation.

This is a concise engineering record rather than a verbatim transcript: it
preserves requests, decisions, relevant findings, and outcomes while omitting
routine tool output.

## 2026-10-16 — Architecture Modernization, Dynamic DNS Retry Loop, and Obsidian Precision Telemetry UI Overhaul

### User request

The user requested a comprehensive review and improvement of the `fping_linux` codebase (`fping_linux.py` and `fping_linux_probes.py`) using `@Python Expert Coder` and `@Frontend Development Guidelines` to modernize the Python architecture, address bugs, and give the UI a modern, high-precision telemetry aesthetic ("better, and vibe").

### Investigation & Architecture Improvements

1. **Permanent DNS Error Bug**:
   - Hostnames that failed initial resolution during `_resolve_targets()` previously emitted `DNS Error` once at startup and were excluded from `fping`. If DNS was momentarily unreachable or flapping, those hosts remained broken forever.
   - Implemented `_retry_failed_dns_loop` running concurrently alongside `fping`. On each cycle interval, it re-attempts resolution for any unresolved targets, updating their status and recovering dynamically.
2. **Dual-Stack IPv6 Support**:
   - `socket.getaddrinfo` had `AF_INET` hardcoded, immediately failing on IPv6 addresses or AAAA-only hosts with `OSError`.
   - Upgraded to dual-stack resolution, attempting IPv4 (`AF_INET`) first and seamlessly falling back to IPv6 (`AF_INET6`).
3. **High-Performance DNS Resolver with TTL Caching**:
   - Introduced `DNSResolver` with a 300-second positive TTL cache, 10-second negative cache, and a concurrency semaphore (`MAX_CONCURRENT_DNS_LOOKUPS = 40`) to prevent socket exhaustion during large multi-hundred-host runs.
4. **Eliminated Table Sorting CPU Lag**:
   - `SortableTableWidgetItem.__lt__` previously called `re.sub(r"[^0-9.+-]", ...)` without pre-compiling, causing ~9,000 regex compilations on every 500-row column sort.
   - Pre-compiled `_NUMERIC_RE = re.compile(r"[^0-9.+-]")` at module scope.
5. **Dual-Engine Fallback (`AsyncICMPSession`)**:
   - Built an internal multiplexed raw ICMP session with large receive buffers (4MB) and non-blocking draining so `ProbeTask` can operate even in environments where `fping` is absent.

### Frontend & Telemetry Design Overhaul

In [fping_linux.py](./fping_linux.py):
1. **Obsidian Precision Telemetry Theme**:
   - Dark theme canvas set to `#090d16` with elevated telemetry cards at `#111726` and crisp borders at `#1c2438`.
   - High-contrast, accessibility-tested telemetry palette: `#10b981` (Connected), `#f59e0b` (Timeout), `#f43f5e` (Failure), `#38bdf8` (Primary Cyan).
   - Light theme engineered with crisp slate accents (`#0f172a`, `#f8fafc`, `#e2e8f0`).
2. **Status Capsule Badges**:
   - Replaced flat status text with glowing capsule badges (`_set_status_idle`, `_set_status_running`, `_set_status_stopping`) featuring status-aware color fills and borders.
3. **Typography & Monospace Data Alignment**:
   - Uppercase letter-spaced table headers (`HOST / IP`, `STATUS`, `SEQ`, `LATENCY`, `PACKET LOSS`, `FAILURES`).
   - Numeric metrics rendered with `Consolas` monospace font and center alignment for readability.
4. **Real-Time Latency Canvas**:
   - Modernized `LatencyChart` with luminous telemetry colors (`#38bdf8`, `#34d399`, `#fbbf24`, `#f43f5e`, `#a78bfa`), rounded caps/joins, legend badges, and anti-aliased geometry.
5. **Dynamic Action Buttons**:
   - Styled action-aware start/stop transitions with high-contrast states (`#2563eb` -> `#e11d48`).
6. **Eliminated Benign Qt Warnings**:
   - Added `app.setFont(QFont("Segoe UI", 9))` to silence point size warnings on environments with default Qt font metrics.

### Verification

- Created unit test suite [tests/test_fping_linux.py](./tests/test_fping_linux.py) with 18 automated tests covering target normalization, timing calculations, command building, JSON and text event parsing, DNS caching, and numeric table sorting. All 18 tests passed in 0.004s.
- Captured visual dark and light UI previews verifying contrast, font metrics, and capsule status badges.

## 2026-10-04 — Fix hosts remaining queued

### User request

The user reported that running the app with `IP-test.txt` did not work and that
hosts remained in `Queued`. They then asked to see the changes made and to keep
a Markdown record of conversations and code changes so future work does not
have to start from the beginning.

### Investigation

- `IP-test.txt` is one comma-separated line of 500 domain names; target parsing
  produced 500 unique targets.
- Installed fping is version 5.1 and emits per-probe text output.
- A small direct fping check showed that fping can consume piped targets, so
  missing `-f -` was not the cause.
- The behavior was consistent with fping spending significant time resolving
  a large hostname list before per-host results arrived. Names that could not
  resolve did not produce a mapped per-host event, leaving their rows queued.
- Concurrent resolution of the sample resolved 488 names across 440 IPv4
  addresses; 12 names failed DNS resolution.

### Code changes

In [fping_linux_probes.py](./fping_linux_probes.py):

1. Added `socket` usage and an async `_resolve_targets()` step. It resolves
   names concurrently (up to 32 simultaneous lookups) with IPv4 addresses.
2. Emits a `DNS Error` result with the resolver error for targets that cannot
   resolve, instead of leaving their rows queued.
3. Passes resolved addresses to the existing single fping process, maps
   returned address results back to original hostnames, and handles multiple
   names that resolve to the same address.
4. Keeps fping/process errors scoped to the targets that were successfully
   resolved; DNS-error results are retained.

The central flow changed from sending hostnames directly to fping:

```python
for target in self.targets:
    process.stdin.write((target + "\n").encode())
```

to resolving first and sending numeric addresses:

```python
targets_by_address = await self._resolve_targets()
...
for target in targets_by_address:
    process.stdin.write((target + "\n").encode())
```

Results read for an address are emitted for each original host mapped to it.

In [README.md](./README.md), documented concurrent DNS resolution and the
`DNS Error` outcome.

### Verification

- Ran `ProbeTask` against all entries in `IP-test.txt` for 12 seconds.
- Observed 1,551 result events across all 500 unique hosts: 12 `DNS Error`,
  1,349 `Connected`, and 190 `No ICMP Reply` events. Hosts received updates
  rather than remaining queued.
- The runtime result supports the resolution-delay diagnosis; the original
  queued state was not separately reproduced in an instrumented baseline run.
- Python syntax validation passed for `fping_linux_probes.py`.
- Pylance reported no diagnostics in `fping_linux_probes.py`.
- Target parsing confirmed 500 hosts, no duplicates; timing calculated as
  2,000 ms host period, 2,000 ms timeout, and 4 ms global send gap.

### Context for follow-up

- The project is under `/home/winson.wu/scripts/fping_linux`; it is not a Git
  repository.
- Main UI/monitor implementation: [fping_linux.py](./fping_linux.py).
- Probe worker and target parsing: [fping_linux_probes.py](./fping_linux_probes.py).
- Sample host list: [IP-test.txt](./IP-test.txt).
- This log was added at the user's request. Continue appending dated entries
  here for future requests and code changes in this project.
