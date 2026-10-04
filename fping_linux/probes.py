"""Linux fping monitor and target validation."""

import asyncio
import json
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass
from typing import Optional

from PySide6.QtCore import QObject, QRunnable, Signal

@dataclass(frozen=True)
class ProbeResult:
    status: str
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    packet_sent: bool = True


def normalize_targets(raw_targets: str) -> tuple[list[str], int]:
    """Return unique targets and the number of duplicate entries removed."""
    targets = [target.strip() for target in raw_targets.split(",") if target.strip()]
    unique_targets = []
    seen = set()
    duplicate_count = 0

    for target in targets:
        if any(character.isspace() for character in target):
            raise ValueError(f"Target contains whitespace: {target!r}")
        normalized = target.casefold()
        if normalized in seen:
            duplicate_count += 1
            continue
        seen.add(normalized)
        unique_targets.append(target)

    return unique_targets, duplicate_count


def fping_info():
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


def parse_fping_event(line, aliases: dict[str, str]):
    """Map one fping JSON result line to the monitor's target and result."""
    try:
        event = json.loads(line)
        data = event.get("resp") or event.get("timeout")
        if not isinstance(data, dict):
            return None
        target = aliases.get(str(data.get("host", "")).casefold())
        if target is None:
            return None
        if "resp" in event:
            result = ProbeResult("Connected", round(float(data["rtt"]), 2))
        else:
            result = ProbeResult("No ICMP Reply")
        return target, result
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def parse_fping_text_line(line, aliases: dict[str, str]):
    """Map fping 5.x's stable human-readable per-probe output."""
    if isinstance(line, bytes):
        line = line.decode(errors="replace")
    line = line.strip()
    line = re.sub(r"^\[[^]]+\]\s*", "", line)
    match = re.match(r"^(.*?)\s+:\s+\[\d+\],\s+(.*)$", line)
    if not match:
        return None
    target = aliases.get(match.group(1).casefold())
    if target is None:
        return None
    detail = match.group(2)
    if detail.startswith("timed out"):
        return target, ProbeResult("No ICMP Reply")
    latency_match = re.search(r"\bbytes,\s*([0-9]+(?:\.[0-9]+)?)\s*ms\b", detail)
    if not latency_match:
        return None
    return target, ProbeResult("Connected", round(float(latency_match.group(1)), 2))


class ProbeSignals(QObject):
    completed = Signal(int, str, object)
    finished = Signal(int)


class ProbeTask(QRunnable):
    """Monitor targets through one Linux fping process, with no app host cap."""

    def __init__(
        self,
        run_id: int,
        targets: list[str],
        payload_size: int,
        timeout: float,
        interval: float,
    ):
        super().__init__()
        self.run_id = run_id
        self.targets = targets
        self.payload_size = payload_size
        self.timeout = timeout
        self.interval = interval
        self.signals = ProbeSignals()
        self._stop_requested = threading.Event()
        self._loop = None
        self._async_stop_event = None

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

    async def _run(self):
        self._loop = asyncio.get_running_loop()
        self._async_stop_event = asyncio.Event()
        if self._stop_requested.is_set():
            self._async_stop_event.set()
        info = fping_info()
        self._fping_executable, self._fping_json = info or ("fping", False)
        await self._run_fping()

    async def _run_fping(self) -> bool:
        """Use fping's single paced event loop instead of one socket per host."""
        period_ms = max(10, round(max(self.interval, self.timeout) * 1000))
        timeout_ms = max(1, round(self.timeout * 1000))
        command = [self._fping_executable]
        if self._fping_json:
            command.append("-J")
        command.extend([
            "-l", "-e", "-u",
            "-b", str(self.payload_size),
            "-p", str(period_ms),
            "-t", str(timeout_ms),
            "-r", "0",
        ])
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            process.stdin.write(("\n".join(self.targets) + "\n").encode())
            await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()
        except (OSError, AttributeError):
            if process is not None and process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                await process.wait()
            for target in self.targets:
                self.signals.completed.emit(
                    self.run_id, target,
                    ProbeResult(
                        "Probe Error",
                        error="Could not start fping. Verify its installation and ICMP permissions.",
                        packet_sent=False,
                    ),
                )
            return

        results_seen = 0
        stderr_task = asyncio.create_task(process.stderr.read())

        async def consume_results():
            nonlocal results_seen
            aliases = {target.casefold(): target for target in self.targets}
            while line := await process.stdout.readline():
                parsed = (
                    parse_fping_event(line, aliases)
                    if self._fping_json else parse_fping_text_line(line, aliases)
                )
                if parsed is None:
                    continue
                target, result = parsed
                results_seen += 1
                self.signals.completed.emit(self.run_id, target, result)

        reader_task = asyncio.create_task(consume_results())
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
        stderr = (await stderr_task).decode(errors="replace").strip()

        if results_seen == 0 and not self._async_stop_event.is_set():
            error_text = stderr or f"fping exited with code {process.returncode} before returning results"
            for target in self.targets:
                self.signals.completed.emit(
                    self.run_id, target,
                    ProbeResult("Probe Error", error=error_text, packet_sent=False),
                )
            return
        if process.returncode not in (0, 1, -15) and not self._async_stop_event.is_set():
            error_text = stderr or f"fping exited with code {process.returncode}"
            for target in self.targets:
                self.signals.completed.emit(
                    self.run_id, target,
                    ProbeResult("Probe Error", error=error_text, packet_sent=False),
                )

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
