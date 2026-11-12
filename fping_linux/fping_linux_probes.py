"""Linux fping monitor and target validation with robust DNS caching and fallback."""

import asyncio
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass

from PySide6.QtCore import QObject, QRunnable, Signal

MAX_CONCURRENT_DNS_LOOKUPS = 40
DNS_CACHE_TTL = 300.0  # 5 minutes
DNS_NEGATIVE_CACHE_TTL = 10.0  # 10 seconds backoff for unresolvable domains

_TEXT_LINE_RE = re.compile(r"^(.*?)\s+:\s+\[\d+\],\s+(.*)$")
_LATENCY_RE = re.compile(r"\bbytes,\s*([0-9]+(?:\.[0-9]+)?)\s*ms\b")
_TIMESTAMP_PREFIX_RE = re.compile(r"^\[[^]]+\]\s*")


@dataclass(frozen=True, slots=True)
class ProbeResult:
    status: str
    latency_ms: float | None = None
    error: str | None = None
    packet_sent: bool = True


def calculate_rfc3550_jitter(latencies: Sequence[float]) -> float:
    """Calculate interarrival jitter according to RFC 3550 / RFC 1889.

    Formula: J_i = J_{i-1} + (|D(i-1, i)| - J_{i-1}) / 16
    """
    valid = [float(val) for val in latencies if val is not None and val >= 0]
    if len(valid) < 2:
        return 0.0
    jitter = 0.0
    for i in range(1, len(valid)):
        diff = abs(valid[i] - valid[i - 1])
        jitter += (diff - jitter) / 16.0
    return round(jitter, 2)


def calculate_percentile(values: Sequence[float], percentile: float = 95.0) -> float:
    """Calculate the p-th percentile of a numerical sample."""
    valid = sorted([float(v) for v in values if v is not None and v >= 0])
    if not valid:
        return 0.0
    if len(valid) == 1:
        return round(valid[0], 2)
    k = (len(valid) - 1) * (percentile / 100.0)
    floor_idx = int(math.floor(k))
    ceil_idx = int(math.ceil(k))
    if floor_idx == ceil_idx:
        return round(valid[floor_idx], 2)
    d0 = valid[floor_idx] * (ceil_idx - k)
    d1 = valid[ceil_idx] * (k - floor_idx)
    return round(d0 + d1, 2)


def normalize_targets(raw_targets: str) -> tuple[list[str], int]:
    """Return unique targets and the number of duplicate entries removed, with CIDR subnet expansion."""
    raw_tokens = re.split(r"[\r\n\t,]+", raw_targets)
    targets = [target.strip() for target in raw_tokens if target.strip()]
    unique_targets = []
    seen = set()
    duplicate_count = 0

    for target in targets:
        if any(character.isspace() for character in target):
            raise ValueError(f"Target contains whitespace: {target!r}")
        if any(ord(character) < 32 or ord(character) == 127 for character in target):
            raise ValueError(f"Target contains invalid control characters: {target!r}")
        if len(target) > 255:
            raise ValueError(f"Target exceeds maximum allowed length of 255 characters: {target[:30]}...")

        if "/" in target:
            try:
                net = ipaddress.ip_network(target, strict=False)
            except ValueError:
                raise ValueError(f"Invalid CIDR subnet notation or target format: {target!r}")

            if net.version == 4:
                if net.prefixlen < 22:
                    raise ValueError(
                        f"CIDR prefix /{net.prefixlen} for '{target}' exceeds safe GUI limit (/22 - max 1022 hosts). "
                        "Subnets broader than /22 are not permitted for live ICMP monitoring."
                    )
                if net.num_addresses > 2:
                    expanded = [str(ip) for ip in net.hosts()]
                else:
                    expanded = [str(ip) for ip in net]
            else:
                if net.prefixlen < 120:
                    raise ValueError(
                        f"IPv6 CIDR prefix /{net.prefixlen} for '{target}' exceeds safe limit (/120)."
                    )
                expanded = [str(ip) for ip in net]

            for ip_str in expanded:
                normalized = ip_str.casefold()
                if normalized in seen:
                    duplicate_count += 1
                    continue
                seen.add(normalized)
                unique_targets.append(ip_str)
        else:
            normalized = target.casefold()
            if normalized in seen:
                duplicate_count += 1
                continue
            seen.add(normalized)
            unique_targets.append(target)

    return unique_targets, duplicate_count


class NameLookupError(OSError):
    """Raised when DNS resolution fails for a target after multiple check attempts."""

    def __init__(self, target: str, attempts: int = 1, reason: str = ""):
        self.target = target
        self.attempts = attempts
        self.reason = reason
        detail = f": {reason}" if reason else ""
        super().__init__(f"DNS resolution failed for '{target}' after {attempts} checks{detail}")


class DNSResolver:
    """Async DNS resolver with multi-check retries, TTL caching, negative cache, and dual-stack lookup."""

    def __init__(
        self,
        ttl: float = DNS_CACHE_TTL,
        negative_ttl: float = DNS_NEGATIVE_CACHE_TTL,
        max_concurrent: int = MAX_CONCURRENT_DNS_LOOKUPS,
        ttl_seconds: float | None = None,
        retries: int = 3,
        retry_delay: float = 0.25,
    ):
        self.ttl = ttl_seconds if ttl_seconds is not None else ttl
        self.negative_ttl = negative_ttl
        self.max_concurrent = max(1, int(max_concurrent))
        self.retries = max(2, int(retries))
        self.retry_delay = max(0.05, float(retry_delay))
        self._cache: dict[str, tuple[str, float]] = {}
        self._negative_cache: dict[str, tuple[Exception, float]] = {}
        self._resolution_info: dict[str, tuple[int, str | None]] = {}
        self._semaphore: asyncio.Semaphore | None = None

    @staticmethod
    def is_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def get_resolution_info(self, target: str) -> tuple[int, str | None]:
        """Return (attempts_performed, last_error_message_or_none) for target."""
        return self._resolution_info.get(target, (self.retries, None))

    async def resolve(
        self,
        target: str,
        retries: int | None = None,
        retry_delay: float | None = None,
    ) -> str:
        """Resolve a hostname to an IP address with multi-check retry verification."""
        if self.is_ip(target):
            self._resolution_info[target] = (1, None)
            return target

        max_attempts = max(2, retries if retries is not None else self.retries)
        delay = retry_delay if retry_delay is not None else self.retry_delay
        now = time.monotonic()

        # Check positive cache
        cached = self._cache.get(target)
        if cached:
            ip, expire_at = cached
            if now < expire_at:
                return ip

        # Check negative cache
        neg_cached = self._negative_cache.get(target)
        if neg_cached:
            err, expire_at = neg_cached
            if now < expire_at:
                if cached:
                    return cached[0]
                raise err

        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)

        async with self._semaphore:
            # Re-check cache after acquiring semaphore
            now = time.monotonic()
            cached = self._cache.get(target)
            if cached and now < cached[1]:
                return cached[0]

            loop = asyncio.get_running_loop()
            last_err: Exception | None = None

            per_check_timeout = 2.5
            for attempt in range(1, max_attempts + 1):
                try:
                    # Check 1: IPv4
                    lookup = await asyncio.wait_for(
                        loop.getaddrinfo(
                            target, None, family=socket.AF_INET, type=socket.SOCK_DGRAM
                        ),
                        timeout=per_check_timeout,
                    )
                    ip = lookup[0][4][0]
                    self._cache[target] = (ip, now + self.ttl)
                    self._negative_cache.pop(target, None)
                    self._resolution_info[target] = (attempt, None)
                    return ip
                except (OSError, asyncio.TimeoutError) as e4:
                    try:
                        # Check 2: IPv6 fallback
                        lookup = await asyncio.wait_for(
                            loop.getaddrinfo(
                                target, None, family=socket.AF_INET6, type=socket.SOCK_DGRAM
                            ),
                            timeout=per_check_timeout,
                        )
                        ip = lookup[0][4][0]
                        self._cache[target] = (ip, now + self.ttl)
                        self._negative_cache.pop(target, None)
                        self._resolution_info[target] = (attempt, None)
                        return ip
                    except (OSError, asyncio.TimeoutError) as e6:
                        last_err = e4 if isinstance(e4, OSError) else e6
                        if attempt < max_attempts:
                            await asyncio.sleep(delay * attempt)

            # All check attempts failed
            err = NameLookupError(
                target,
                attempts=max_attempts,
                reason=str(last_err or "getaddrinfo failed"),
            )
            self._resolution_info[target] = (max_attempts, str(err))
            if cached:
                # Soft-extend stale cache briefly (15s) while logging failure
                self._cache[target] = (cached[0], now + 15.0)
                return cached[0]
            self._negative_cache[target] = (err, now + self.negative_ttl)
            raise err

    async def pre_resolve_all(
        self, targets: Sequence[str], retries: int | None = None
    ) -> dict[str, str | None]:
        """Pre-resolve targets concurrently with multi-check verification before probing starts."""
        non_ips = [target for target in targets if not self.is_ip(target)]
        if not non_ips:
            return {}

        max_attempts = max(2, retries if retries is not None else self.retries)

        async def _resolve_safe(target: str) -> tuple[str, str | None]:
            try:
                ip = await self.resolve(target, retries=max_attempts)
                return target, ip
            except Exception:
                return target, None

        results = await asyncio.gather(
            *(_resolve_safe(target) for target in non_ips), return_exceptions=True
        )
        resolved: dict[str, str | None] = {}
        for item in results:
            if isinstance(item, tuple):
                resolved[item[0]] = item[1]
        return resolved

    def clear_cache(self):
        self._cache.clear()
        self._negative_cache.clear()
        self._resolution_info.clear()


def fping_info() -> tuple[str, bool] | None:
    """Return a supported fping path and whether its JSON mode is available."""
    executable = shutil.which("fping")
    if not executable:
        return None
    try:
        version_check = subprocess.run(
            [executable, "-v"], capture_output=True, text=True, timeout=3
        )
        version_text = version_check.stdout + version_check.stderr
        version_match = re.search(
            r"\bversion\s+(\d+)\.(\d+)", version_text, re.IGNORECASE
        )
        if not version_match or tuple(map(int, version_match.groups())) < (5, 0):
            return None
        check = subprocess.run(
            [executable, "-h"], capture_output=True, text=True, timeout=3
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    help_text = check.stdout + check.stderr
    return executable, ("--json" in help_text or "-J" in help_text)


def fping_available() -> bool:
    return fping_info() is not None


def parse_fping_event(
    line: str | bytes, aliases: dict[str, str] | None = None
) -> tuple[str, ProbeResult] | None:
    """Map one fping JSON result line to the monitor's target and result."""
    try:
        if isinstance(line, bytes):
            line = line.decode(errors="replace")
        event = json.loads(line)
        data = event.get("resp") or event.get("timeout")
        if not isinstance(data, dict):
            return None
        raw_host = str(data.get("host", ""))
        host_key = raw_host.casefold()
        target = aliases.get(host_key, raw_host) if aliases is not None else raw_host
        if not target:
            return None
        if "resp" in event:
            result = ProbeResult("Connected", round(float(data["rtt"]), 2))
        else:
            result = ProbeResult("No ICMP Reply")
        return target, result
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def parse_fping_text_line(
    line: str | bytes, aliases: dict[str, str] | None = None
) -> tuple[str, ProbeResult] | None:
    """Map fping 5.x's stable human-readable per-probe output."""
    if isinstance(line, bytes):
        line = line.decode(errors="replace")
    line = line.strip()
    line = _TIMESTAMP_PREFIX_RE.sub("", line)
    match = _TEXT_LINE_RE.match(line)
    if not match:
        return None
    raw_host = match.group(1)
    host_key = raw_host.casefold()
    target = aliases.get(host_key, raw_host) if aliases is not None else raw_host
    if not target:
        return None
    detail = match.group(2)
    if detail.startswith("timed out"):
        return target, ProbeResult("No ICMP Reply")
    if detail.startswith("unreachable"):
        return target, ProbeResult("Unreachable")
    latency_match = _LATENCY_RE.search(detail)
    if not latency_match:
        return None
    return target, ProbeResult("Connected", round(float(latency_match.group(1)), 2))


def build_fping_command(
    executable: str,
    use_json: bool,
    payload_size: int,
    send_gap_ms: int,
    period_ms: int,
    timeout_ms: int,
) -> list[str]:
    """Build the continuous-monitor command and retain both reply classes."""
    command = [executable]
    if use_json:
        command.append("-J")
    command.extend([
        "-l", "-e",
        "-b", str(payload_size),
        "-i", str(send_gap_ms),
        "-p", str(period_ms),
        "-t", str(timeout_ms),
        "-r", "0",
    ])
    return command


def calculate_fping_timing(
    target_count: int,
    interval_seconds: float,
    timeout_seconds: float,
    requested_send_gap_ms: int,
) -> tuple[int, int, int]:
    """Return an achievable per-host period and global packet gap in ms."""
    if target_count < 1:
        raise ValueError("At least one target is required to calculate fping timing.")
    requested_period_ms = max(10, round(max(interval_seconds, timeout_seconds) * 1000))
    timeout_ms = max(1, round(timeout_seconds * 1000))
    requested_gap_ms = max(1, int(requested_send_gap_ms))
    gap_budget_ms = max(1, requested_period_ms // target_count)
    effective_gap_ms = min(requested_gap_ms, gap_budget_ms)
    effective_period_ms = max(requested_period_ms, effective_gap_ms * target_count)
    return effective_period_ms, timeout_ms, effective_gap_ms


class AsyncICMPSession:
    """High-performance multiplexed ICMP fallback session when fping is unavailable."""

    def __init__(self, payload_size: int = 56):
        self.payload_size = payload_size
        self._v4_sock: socket.socket | None = None
        self._v6_sock: socket.socket | None = None
        self._pending_v4: dict[tuple[int, int], tuple[asyncio.Future, float]] = {}
        self._pending_v6: dict[tuple[int, int], tuple[asyncio.Future, float]] = {}
        self._seq = 0
        self._id = (os.getpid() ^ int(time.time() * 1000)) & 0xFFFF or 12345
        self._receiver_tasks: list[asyncio.Task] = []
        self._stop_event: asyncio.Event | None = None
        self._is_active = False

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2 == 1:
            data += b"\0"
        words = struct.unpack(f"!{len(data)//2}H", data)
        total = sum(words)
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return (~total) & 0xFFFF

    async def start(self) -> bool:
        """Attempt to open multiplexed raw ICMP sockets."""
        try:
            self._v4_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self._v4_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            self._v4_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            try:
                self._v4_sock.bind(("", 0))
            except OSError:
                pass
            self._v4_sock.setblocking(False)
        except OSError:
            self._v4_sock = None

        try:
            self._v6_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
            self._v6_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            self._v6_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            try:
                self._v6_sock.bind(("::", 0))
            except OSError:
                pass
            self._v6_sock.setblocking(False)
        except OSError:
            self._v6_sock = None

        if self._v4_sock is None and self._v6_sock is None:
            return False

        self._stop_event = asyncio.Event()
        self._is_active = True
        if self._v4_sock is not None:
            self._receiver_tasks.append(asyncio.create_task(self._v4_receiver()))
        if self._v6_sock is not None:
            self._receiver_tasks.append(asyncio.create_task(self._v6_receiver()))
        return True

    def _process_v4_packet(self, data: bytes, recv_time: float) -> None:
        if len(data) >= 28:
            ip_header_len = (data[0] & 0x0F) * 4
            if len(data) >= ip_header_len + 8:
                icmp_header = data[ip_header_len : ip_header_len + 8]
                icmp_type, _code, _chk, pkt_id, seq = struct.unpack("!BBHHH", icmp_header)
                if icmp_type == 0:  # Echo Reply
                    key = (pkt_id, seq)
                    item = self._pending_v4.pop(key, None)
                    if item is not None:
                        fut, send_time = item
                        if not fut.done():
                            latency = round((recv_time - send_time) * 1000, 2)
                            fut.set_result(latency)

    async def _v4_receiver(self):
        loop = asyncio.get_running_loop()
        while self._is_active and not self._stop_event.is_set():
            try:
                data = await loop.sock_recv(self._v4_sock, 2048)
                recv_time = time.monotonic()
                self._process_v4_packet(data, recv_time)
                while self._is_active and not self._stop_event.is_set():
                    try:
                        more_data = self._v4_sock.recv(2048)
                        if not more_data:
                            break
                        self._process_v4_packet(more_data, time.monotonic())
                    except (BlockingIOError, InterruptedError):
                        break
            except (asyncio.CancelledError, OSError):
                if not self._is_active or self._stop_event.is_set():
                    break
                await asyncio.sleep(0.001)

    def _process_v6_packet(self, data: bytes, recv_time: float) -> None:
        if len(data) >= 8:
            icmp_type, _code, _chk, pkt_id, seq = struct.unpack("!BBHHH", data[:8])
            if icmp_type == 129:  # ICMPv6 Echo Reply
                key = (pkt_id, seq)
                item = self._pending_v6.pop(key, None)
                if item is not None:
                    fut, send_time = item
                    if not fut.done():
                        latency = round((recv_time - send_time) * 1000, 2)
                        fut.set_result(latency)

    async def _v6_receiver(self):
        loop = asyncio.get_running_loop()
        while self._is_active and not self._stop_event.is_set():
            try:
                data = await loop.sock_recv(self._v6_sock, 2048)
                recv_time = time.monotonic()
                self._process_v6_packet(data, recv_time)
                while self._is_active and not self._stop_event.is_set():
                    try:
                        more_data = self._v6_sock.recv(2048)
                        if not more_data:
                            break
                        self._process_v6_packet(more_data, time.monotonic())
                    except (BlockingIOError, InterruptedError):
                        break
            except (asyncio.CancelledError, OSError):
                if not self._is_active or self._stop_event.is_set():
                    break
                await asyncio.sleep(0.001)

    async def ping(self, ip: str, timeout: float) -> float | None:
        """Send an ICMP echo request and await reply."""
        is_v6 = ":" in ip
        sock = self._v6_sock if is_v6 else self._v4_sock
        if sock is None:
            return None

        self._seq = (self._seq + 1) & 0xFFFF
        seq = self._seq
        pkt_id = self._id
        payload = b"Q" * self.payload_size

        if is_v6:
            header = struct.pack("!BBHHH", 128, 0, 0, pkt_id, seq)
            packet = header + payload
            pending_map = self._pending_v6
        else:
            header = struct.pack("!BBHHH", 8, 0, 0, pkt_id, seq)
            chk = self._checksum(header + payload)
            packet = struct.pack("!BBHHH", 8, 0, chk, pkt_id, seq) + payload
            pending_map = self._pending_v4

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        send_time = time.monotonic()
        key = (pkt_id, seq)
        pending_map[key] = (fut, send_time)

        try:
            sock.sendto(packet, (ip, 1))
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            pending_map.pop(key, None)
            return None
        except Exception:
            pending_map.pop(key, None)
            return None

    def close(self):
        self._is_active = False
        if self._stop_event is not None:
            self._stop_event.set()
        for task in self._receiver_tasks:
            task.cancel()
        self._receiver_tasks.clear()
        if self._v4_sock is not None:
            try:
                self._v4_sock.close()
            except OSError:
                pass
            self._v4_sock = None
        if self._v6_sock is not None:
            try:
                self._v6_sock.close()
            except OSError:
                pass
            self._v6_sock = None


class ProbeSignals(QObject):
    completed = Signal(int, str, object)
    finished = Signal(int)


class ProbeTask(QRunnable):
    """Monitor targets through Linux fping process or multiplexed ICMP fallback."""

    def __init__(
        self,
        run_id: int,
        targets: Sequence[str],
        payload_size: int,
        timeout: float,
        interval: float,
        send_gap_ms: int,
    ):
        super().__init__()
        self.run_id = run_id
        self.targets = list(targets)
        self.payload_size = payload_size
        self.timeout = timeout
        self.interval = interval
        self.send_gap_ms = send_gap_ms
        self.signals = ProbeSignals()
        self._dns_resolver = DNSResolver()
        self._stop_requested = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._async_stop_event: asyncio.Event | None = None
        self._icmp_session: AsyncICMPSession | None = None

    def request_stop(self):
        self._stop_requested.set()
        if (
            self._loop is not None
            and self._loop.is_running()
            and self._async_stop_event is not None
        ):
            try:
                self._loop.call_soon_threadsafe(self._async_stop_event.set)
            except RuntimeError:
                pass

    async def _resolve_targets(self) -> tuple[dict[str, list[str]], set[str]]:
        """Resolve hostnames concurrently with multi-check verification and return mapped targets plus failed targets."""
        resolved_hosts = await self._dns_resolver.pre_resolve_all(self.targets)
        targets_by_address: dict[str, list[str]] = {}
        failed_targets: set[str] = set()

        for target in self.targets:
            if self._dns_resolver.is_ip(target):
                targets_by_address.setdefault(target, []).append(target)
            else:
                address = resolved_hosts.get(target)
                if address is not None:
                    targets_by_address.setdefault(address, []).append(target)
                else:
                    failed_targets.add(target)
                    attempts, err_msg = self._dns_resolver.get_resolution_info(target)
                    err_desc = err_msg or f"Could not resolve '{target}' after {attempts} DNS checks"
                    self.signals.completed.emit(
                        self.run_id,
                        target,
                        ProbeResult("DNS Error", error=err_desc, packet_sent=False),
                    )

        return targets_by_address, failed_targets

    async def _retry_failed_dns_loop(
        self,
        failed_targets: set[str],
        targets_by_address: dict[str, list[str]],
    ):
        """Periodically re-attempt DNS resolution for targets that failed at startup."""
        retry_interval = max(3.0, min(10.0, self.interval * 3))
        while not self._async_stop_event.is_set() and failed_targets:
            try:
                await asyncio.wait_for(self._async_stop_event.wait(), timeout=retry_interval)
                break
            except asyncio.TimeoutError:
                pass

            for target in list(failed_targets):
                if self._async_stop_event.is_set():
                    break
                try:
                    self._dns_resolver._negative_cache.pop(target, None)
                    ip = await self._dns_resolver.resolve(target, retries=1)
                    if ip:
                        failed_targets.discard(target)
                        if ip in targets_by_address:
                            targets_by_address[ip].append(target)
                        else:
                            targets_by_address.setdefault(ip, []).append(target)
                            if self._fping_executable:
                                asyncio.create_task(self._probe_single_target(target, ip))
                            elif self._icmp_session:
                                asyncio.create_task(self._probe_fallback_target(target, ip))
                except Exception:
                    pass

    async def _probe_single_target(self, target: str, ip: str):
        if not self._fping_executable:
            return
        cmd = [self._fping_executable, "-c", "1", "-t", str(int(self.timeout * 1000)), "-b", str(self.payload_size), ip]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            aliases = {ip.casefold(): ip}
            for line in stdout.splitlines():
                parsed = parse_fping_text_line(line, aliases)
                if parsed:
                    _, res = parsed
                    self.signals.completed.emit(self.run_id, target, res)
                    return
            self.signals.completed.emit(self.run_id, target, ProbeResult("No ICMP Reply"))
        except Exception as e:
            self.signals.completed.emit(self.run_id, target, ProbeResult("Probe Error", error=str(e), packet_sent=False))

    async def _probe_fallback_target(self, target: str, ip: str):
        if not self._icmp_session:
            return
        try:
            latency = await self._icmp_session.ping(ip, self.timeout)
            res = ProbeResult("Connected", latency) if latency is not None else ProbeResult("No ICMP Reply")
        except Exception as e:
            res = ProbeResult("Probe Error", error=str(e), packet_sent=False)
        self.signals.completed.emit(self.run_id, target, res)

    async def _run_fallback_engine(self):
        """Fallback to internal AsyncICMPSession when fping is not installed."""
        targets_by_address, failed_targets = await self._resolve_targets()
        if self._async_stop_event.is_set():
            return

        resolved_targets = [
            target
            for targets in targets_by_address.values()
            for target in targets
        ]

        if not resolved_targets:
            await self._async_stop_event.wait()
            return

        self._icmp_session = AsyncICMPSession(self.payload_size)
        session_started = await self._icmp_session.start()
        if not session_started:
            for target in resolved_targets:
                self.signals.completed.emit(
                    self.run_id,
                    target,
                    ProbeResult("Permission Denied", error="Raw ICMP socket permission denied.", packet_sent=False),
                )
            return

        target_count = len(resolved_targets)
        stagger_step = (
            min(0.05, (self.interval * 0.95) / max(1, target_count))
            if target_count > 1
            else 0.0
        )

        async def _monitor_one(target: str, initial_delay: float):
            loop = asyncio.get_running_loop()
            if initial_delay > 0:
                try:
                    await asyncio.wait_for(self._async_stop_event.wait(), timeout=initial_delay)
                    return
                except asyncio.TimeoutError:
                    pass

            while not self._async_stop_event.is_set():
                started = loop.time()
                try:
                    dest_ip = await self._dns_resolver.resolve(target)
                    latency = await self._icmp_session.ping(dest_ip, self.timeout)
                    if latency is not None:
                        res = ProbeResult("Connected", latency)
                    else:
                        res = ProbeResult("No ICMP Reply")
                except NameLookupError as err:
                    res = ProbeResult("DNS Error", error=str(err), packet_sent=False)
                    self.signals.completed.emit(self.run_id, target, res)
                    return
                except Exception as err:
                    res = ProbeResult("Probe Error", error=str(err), packet_sent=False)

                self.signals.completed.emit(self.run_id, target, res)
                if self._async_stop_event.is_set():
                    return
                delay = max(0.0, self.interval - (loop.time() - started))
                if delay:
                    try:
                        await asyncio.wait_for(self._async_stop_event.wait(), timeout=delay)
                    except asyncio.TimeoutError:
                        pass

        retry_task: asyncio.Task | None = None
        if failed_targets:
            retry_task = asyncio.create_task(
                self._retry_failed_dns_loop(failed_targets, targets_by_address)
            )

        try:
            tasks = [
                _monitor_one(target, idx * stagger_step)
                for idx, target in enumerate(resolved_targets)
            ]
            await asyncio.gather(*tasks)
        finally:
            if retry_task is not None and not retry_task.done():
                retry_task.cancel()
                await asyncio.gather(retry_task, return_exceptions=True)
            self._icmp_session.close()
            self._icmp_session = None

    async def _run_fping(self) -> bool:
        """Use fping's single paced event loop instead of one socket per host."""
        targets_by_address, failed_targets = await self._resolve_targets()
        if self._async_stop_event.is_set():
            return True
        if not targets_by_address:
            if failed_targets:
                retry_task = asyncio.create_task(
                    self._retry_failed_dns_loop(failed_targets, targets_by_address)
                )
                await self._async_stop_event.wait()
                if not retry_task.done():
                    retry_task.cancel()
                await asyncio.gather(retry_task, return_exceptions=True)
            else:
                await self._async_stop_event.wait()
            return True

        resolved_targets = [
            target
            for targets in targets_by_address.values()
            for target in targets
        ]

        retry_task: asyncio.Task | None = None
        if failed_targets:
            retry_task = asyncio.create_task(
                self._retry_failed_dns_loop(failed_targets, targets_by_address)
            )

        period_ms, timeout_ms, send_gap_ms = calculate_fping_timing(
            len(resolved_targets), self.interval, self.timeout, self.send_gap_ms
        )
        command = build_fping_command(
            self._fping_executable,
            self._fping_json,
            self.payload_size,
            send_gap_ms,
            period_ms,
            timeout_ms,
        )
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as error:
            for target in resolved_targets:
                self.signals.completed.emit(
                    self.run_id, target,
                    ProbeResult("Probe Error", error=f"Could not start fping: {error}", packet_sent=False),
                )
            return False

        results_seen = 0
        stderr_task = asyncio.create_task(process.stderr.read())

        async def consume_results():
            nonlocal results_seen
            aliases = {
                address.casefold(): address
                for address in targets_by_address
            }
            while line := await process.stdout.readline():
                parsed = (
                    parse_fping_event(line, aliases)
                    if self._fping_json else parse_fping_text_line(line, aliases)
                )
                if parsed is None:
                    continue
                address, result = parsed
                results_seen += 1
                for target in targets_by_address.get(address, []):
                    self.signals.completed.emit(self.run_id, target, result)

        reader_task = asyncio.create_task(consume_results())

        try:
            for address in targets_by_address:
                if self._async_stop_event.is_set():
                    break
                process.stdin.write((address + "\n").encode())
                await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()
        except (OSError, AttributeError) as error:
            if process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), timeout=1.5)
                except asyncio.TimeoutError:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    await process.wait()
            if not reader_task.done():
                reader_task.cancel()
            await asyncio.gather(reader_task, return_exceptions=True)
            stderr = (await stderr_task).decode(errors="replace").strip()
            error_text = stderr or f"Could not send target list to fping: {error}"
            for target in resolved_targets:
                self.signals.completed.emit(
                    self.run_id, target,
                    ProbeResult("Probe Error", error=error_text, packet_sent=False),
                )
            return True

        stop_task = asyncio.create_task(self._async_stop_event.wait())
        done, _ = await asyncio.wait(
            (reader_task, stop_task), return_when=asyncio.FIRST_COMPLETED
        )
        if stop_task in done and self._async_stop_event.is_set() and process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        if process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), timeout=1.5)
            except asyncio.TimeoutError:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                await process.wait()
        if not reader_task.done():
            reader_task.cancel()
        await asyncio.gather(reader_task, return_exceptions=True)
        stop_task.cancel()
        await asyncio.gather(stop_task, return_exceptions=True)
        if retry_task is not None and not retry_task.done():
            retry_task.cancel()
            await asyncio.gather(retry_task, return_exceptions=True)
        stderr = (await stderr_task).decode(errors="replace").strip()

        if results_seen == 0 and not self._async_stop_event.is_set():
            error_text = stderr or f"fping exited with code {process.returncode} before returning results"
            for target in resolved_targets:
                self.signals.completed.emit(
                    self.run_id, target,
                    ProbeResult("Probe Error", error=error_text, packet_sent=False),
                )
            return True
        if process.returncode not in (0, 1, -15) and not self._async_stop_event.is_set():
            error_text = stderr or f"fping exited with code {process.returncode}"
            for target in resolved_targets:
                self.signals.completed.emit(
                    self.run_id, target,
                    ProbeResult("Probe Error", error=error_text, packet_sent=False),
                )
        return True

    async def _run(self):
        self._loop = asyncio.get_running_loop()
        self._async_stop_event = asyncio.Event()
        if self._stop_requested.is_set():
            self._async_stop_event.set()

        info = fping_info()
        if info is not None:
            self._fping_executable, self._fping_json = info
            success = await self._run_fping()
            if success:
                return

        # Fallback engine when fping is absent or fails execution
        await self._run_fallback_engine()

    def run(self):
        try:
            asyncio.run(self._run())
        except Exception as error:
            for target in self.targets:
                self.signals.completed.emit(
                    self.run_id,
                    target,
                    ProbeResult("Probe Error", error=str(error), packet_sent=False),
                )
        finally:
            self.signals.finished.emit(self.run_id)
