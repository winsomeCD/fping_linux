"""Pure-Python telemetry state, aggregation, and reporting core for fping_linux (zero Qt)."""

from __future__ import annotations

import csv
import math
import time
from collections import deque
from pathlib import Path

from fping_linux_probes import ProbeResult

MAX_LOG_ENTRIES = 1000
VALID_STATUSES = frozenset({
    "Connected",
    "No ICMP Reply",
    "DNS Error",
    "Permission Denied",
    "Probe Error",
    "Unreachable",
})


def sanitize_csv_cell(value: object) -> object:
    """Neutralize spreadsheet formula injection (DDE attacks) for exported CSVs."""
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        try:
            float(text)
            return value
        except ValueError:
            return "'" + text
    return value


def is_down_status(status: str | None) -> bool:
    return status in ("No ICMP Reply", "Unreachable")


def create_host_record(host: str, history_points: int = 60) -> dict:
    """Create initial per-host telemetry state dictionary."""
    return {
        "latencies": deque(maxlen=history_points),
        "latency_count": 0,
        "latency_sum": 0.0,
        "min_latency": None,
        "max_latency": None,
        "sent": 0,
        "checks": 0,
        "received": 0,
        "timeline_stats": [],
        "log_rows": [],
        "tree_id": host,
        "last_status": None,
        "last_error": None,
        "consecutive_fails": 0,
        "last_down_time": "-",
    }


def record_probe_result(
    data: dict,
    result: ProbeResult,
    max_log_entries: int = MAX_LOG_ENTRIES,
    timestamp: str | None = None,
) -> tuple[ProbeResult, int, float | None, str]:
    """Validate a ProbeResult, update host telemetry state in-place, and return normalized values."""
    if not isinstance(result, ProbeResult):
        result = ProbeResult("Probe Error", error="The probe returned an invalid result.")

    if result.status not in VALID_STATUSES:
        result = ProbeResult("Probe Error", error=f"Unknown probe status: {result.status!r}")
    elif result.status == "Connected" and (
        result.latency_ms is None
        or not isinstance(result.latency_ms, (int, float))
        or not math.isfinite(result.latency_ms)
        or result.latency_ms < 0
    ):
        result = ProbeResult("Probe Error", error="The probe returned an invalid latency value.")
    if not isinstance(result.packet_sent, bool):
        result = ProbeResult("Probe Error", error="The probe returned invalid send metadata.", packet_sent=False)
    elif result.status == "Connected" and not result.packet_sent:
        result = ProbeResult("Probe Error", error="A connected result must correspond to a sent packet.", packet_sent=False)
    elif result.status in {"DNS Error", "Permission Denied", "Probe Error"} and result.packet_sent:
        result = ProbeResult(result.status, error=result.error, packet_sent=False)

    data["checks"] = data.get("checks", data["sent"]) + 1
    if result.packet_sent:
        data["sent"] += 1
    sequence = data["checks"]
    ts = timestamp if timestamp is not None else time.strftime("%Y-%m-%d %H:%M:%S")
    status = result.status
    data["last_status"] = status
    data["last_error"] = result.error

    latency: float | None = None
    if status == "Connected" and result.latency_ms is not None and result.packet_sent:
        latency = result.latency_ms
        data["received"] += 1
        data["latencies"].append(latency)
        data["latency_count"] += 1
        data["latency_sum"] += latency
        data["min_latency"] = latency if data["min_latency"] is None else min(data["min_latency"], latency)
        data["max_latency"] = latency if data["max_latency"] is None else max(data["max_latency"], latency)
        data["consecutive_fails"] = 0
        latency_text = f"{latency:.2f} ms"
        timeline = f"[{ts}] Seq {sequence}: Success — Latency {latency:.2f} ms"
        log_result = (sequence, ts, "Success", latency)
    else:
        if result.packet_sent:
            data["latencies"].append(0)
        data["consecutive_fails"] += 1
        if is_down_status(status):
            data["last_down_time"] = ts
        latency_text = "—"
        error_text = f" — {result.error}" if result.error else ""
        timeline = f"[{ts}] Seq {sequence}: FAILED — {status}{error_text}"
        detail_msg = result.error or ("No ICMP reply before timeout" if is_down_status(status) else "")
        log_result = (sequence, ts, status, detail_msg)

    data["timeline_stats"].append(timeline)
    data["log_rows"].append(log_result)
    del data["timeline_stats"][:-max_log_entries]
    del data["log_rows"][:-max_log_entries]

    return result, sequence, latency, latency_text


def compute_host_stats(
    data: dict,
) -> tuple[int, int, float | None, float | None, float | None, float | None]:
    """Compute (sent, received, loss_pct, min_lat, max_lat, avg_lat) for a host record."""
    sent = data["sent"]
    received = data["received"]
    loss_pct = round(((sent - received) / sent) * 100, 1) if sent > 0 else None
    latency_count = data.get("latency_count", 0)
    if latency_count:
        min_lat = data["min_latency"]
        max_lat = data["max_latency"]
        avg_lat = round(data["latency_sum"] / latency_count, 2)
    else:
        min_lat = max_lat = avg_lat = None
    return sent, received, loss_pct, min_lat, max_lat, avg_lat


def build_summary_info(data_snapshot: dict, is_monitoring: bool = False) -> dict:
    """Build aggregate summary metrics across all targets."""
    statuses = [data.get("last_status") for data in data_snapshot.values()]
    total_sent = sum(data.get("sent", 0) for data in data_snapshot.values())
    total_received = sum(data.get("received", 0) for data in data_snapshot.values())
    latency_samples = sum(data.get("latency_count", 0) for data in data_snapshot.values())
    latency_sum = sum(data.get("latency_sum", 0.0) for data in data_snapshot.values())
    minima = [
        data.get("min_latency") for data in data_snapshot.values()
        if data.get("min_latency") is not None
    ]
    maxima = [
        data.get("max_latency") for data in data_snapshot.values()
        if data.get("max_latency") is not None
    ]
    loss_pct = (
        round((total_sent - total_received) / total_sent * 100, 1)
        if total_sent else None
    )
    return {
        "Report generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "Monitoring state": "Monitoring" if is_monitoring else "Stopped",
        "Target status counts based on": "Each target's latest probe result",
        "Total targets": len(data_snapshot),
        "Targets responding to ICMP": sum(status == "Connected" for status in statuses),
        "Targets with no ICMP reply": sum(is_down_status(status) for status in statuses),
        "DNS errors": sum(status == "DNS Error" for status in statuses),
        "Permission errors": sum(status == "Permission Denied" for status in statuses),
        "Probe errors": sum(status == "Probe Error" for status in statuses),
        "Awaiting first result": sum(status is None for status in statuses),
        "Completed checks": sum(
            data.get("checks", data.get("sent", 0)) for data in data_snapshot.values()
        ),
        "ICMP requests sent": total_sent,
        "ICMP replies received": total_received,
        "ICMP packet loss (%)": loss_pct if loss_pct is not None else "N/A",
        "Latency samples": latency_samples,
        "Minimum latency (ms)": min(minima) if minima else "N/A",
        "Average latency (ms)": round(latency_sum / latency_samples, 2) if latency_samples else "N/A",
        "Maximum latency (ms)": max(maxima) if maxima else "N/A",
    }


def export_summary_txt(
    data_snapshot: dict,
    file_path: str | Path,
    is_monitoring: bool = False,
) -> Path:
    """Write human-readable 5-section performance summary TXT report."""
    out_path = Path(file_path)
    summary_info = build_summary_info(data_snapshot, is_monitoring=is_monitoring)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("             NETWORK PERFORMANCE SUMMARY REPORT\n")
        f.write(f"             Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

        f.write("[1. SUMMARY INFO]\n")
        f.write("-" * 50 + "\n")
        for metric, value in summary_info.items():
            f.write(f"{metric:<34}: {value}\n")
        f.write("\n")

        f.write("[2. HOST AGGREGATE METRICS]\n")
        f.write("-" * 80 + "\n")
        f.write(
            f"{'Target Host':<20} | {'Sent':<6} | {'Recv':<6} | {'Loss %':<8} | "
            f"{'Min':<9} | {'Max':<9} | {'Avg':<9}\n"
        )
        f.write("-" * 80 + "\n")

        for host, data in data_snapshot.items():
            sent, received, loss_pct, min_lat, max_lat, avg_lat = compute_host_stats(data)
            if min_lat is None:
                min_s, max_s, avg_s = "-", "-", "-"
            else:
                min_s, max_s, avg_s = f"{min_lat}ms", f"{max_lat}ms", f"{avg_lat}ms"
            loss_text = f"{loss_pct}%" if loss_pct is not None else "n/a"
            f.write(
                f"{host:<20} | {sent:<6} | {received:<6} | {loss_text:<8} | "
                f"{min_s:<9} | {max_s:<9} | {avg_s:<9}\n"
            )
        f.write("-" * 80 + "\n\n")

        f.write("[3. TARGETS WITHOUT AN ICMP REPLY]\n")
        f.write("-" * 50 + "\n")
        down_now = [
            h for h, d in data_snapshot.items() if is_down_status(d.get("last_status"))
        ]
        recovered_with_loss = [
            h for h, d in data_snapshot.items()
            if not is_down_status(d.get("last_status"))
            and (
                (d.get("last_down_time") and d.get("last_down_time") != "-")
                or any(is_down_status(r[2]) for r in d.get("log_rows", []))
            )
        ]
        if down_now or recovered_with_loss:
            for h in down_now:
                f.write(
                    f"• {h} (last failed: {data_snapshot[h].get('last_down_time', '-')})\n"
                )
            for h in recovered_with_loss:
                d = data_snapshot[h]
                sent = d.get("sent", 0)
                recv = d.get("received", 0)
                loss = round((sent - recv) / sent * 100, 1) if sent else 0.0
                f.write(
                    f"• {h} [Recovered] (last failed: {d.get('last_down_time', '-')}, packet loss: {loss}%)\n"
                )
        else:
            f.write("No target recorded an ICMP timeout. Web-service health is not tested.\n")
        f.write("\n")

        f.write("[4. UNRESOLVED DNS HOSTNAMES (EXCLUDED FROM LIVE TELEMETRY)]\n")
        f.write("-" * 50 + "\n")
        dns_failures = [
            (h, d) for h, d in data_snapshot.items() if d.get("last_status") == "DNS Error"
        ]
        if dns_failures:
            for h, d in dns_failures:
                err = d.get("last_error") or "Name resolution failed"
                t = d.get("last_down_time", "-")
                f.write(f"• {h:<25} | Detected: {t} | Error: {err}\n")
        else:
            f.write("All target hostnames were resolved successfully.\n")
        f.write("\n")

        f.write("[5. DETAILED SEQUENCE TIMELINES]\n")
        for host, data in data_snapshot.items():
            f.write(f"\n# Stream: {host}\n")
            f.write("-" * 50 + "\n")
            if data.get("timeline_stats"):
                for log_entry in data["timeline_stats"]:
                    f.write(log_entry + "\n")
            elif data.get("log_rows"):
                for seq, ts, st, det in data["log_rows"]:
                    if st == "Success":
                        lat = f"{float(det):.2f} ms" if isinstance(det, (int, float)) else f"{det} ms"
                        f.write(f"[{ts}] Seq {seq}: Success — Latency {lat}\n")
                    else:
                        err = f" — {det}" if det else ""
                        f.write(f"[{ts}] Seq {seq}: FAILED — {st}{err}\n")
    return out_path


def _style_workbook_table(sheet, header_row: int = 1) -> None:
    from openpyxl.styles import Alignment, Font, PatternFill

    sheet.freeze_panes = f"A{header_row + 1}"
    sheet.sheet_view.showGridLines = False
    if sheet.max_row >= header_row and sheet.max_column:
        sheet.auto_filter.ref = (
            f"A{header_row}:{sheet.cell(sheet.max_row, sheet.max_column).coordinate}"
        )
    for cell in sheet[header_row]:
        cell.fill = PatternFill("solid", fgColor="1F4E78")
        cell.font = Font(color="FFFFFF", bold=True)
        cell.alignment = Alignment(vertical="center")


def export_report_xlsx(
    data_snapshot: dict,
    file_path: str | Path,
    is_monitoring: bool = False,
    title: str = "fping Linux Summary Info",
) -> Path:
    """Export telemetry summary, host details, probe log, and DNS failures to Excel."""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill

    out_path = Path(file_path)
    summary_info = build_summary_info(data_snapshot, is_monitoring=is_monitoring)

    workbook = Workbook()
    summary_sheet = workbook.active
    summary_sheet.title = "Summary Info"
    summary_sheet.merge_cells("A1:B1")
    summary_sheet["A1"] = title
    summary_sheet["A1"].font = Font(size=16, bold=True, color="FFFFFF")
    summary_sheet["A1"].fill = PatternFill("solid", fgColor="17365D")
    summary_sheet["A1"].alignment = Alignment(vertical="center")
    summary_sheet.row_dimensions[1].height = 28
    summary_sheet.append(["Generated", summary_info["Report generated"]])
    summary_sheet.append(["Monitoring state", summary_info["Monitoring state"]])
    summary_sheet.append([])
    summary_sheet.append(["Metric", "Value"])
    for metric, value in summary_info.items():
        if metric not in {"Report generated", "Monitoring state"}:
            summary_sheet.append([metric, value])
    _style_workbook_table(summary_sheet, header_row=4)
    summary_sheet.column_dimensions["A"].width = 34
    summary_sheet.column_dimensions["B"].width = 24

    host_sheet = workbook.create_sheet("Host Details")
    host_sheet.append([
        "Host", "Last Status", "Checks", "ICMP Sent", "ICMP Received",
        "Loss %", "Min ms", "Max ms", "Avg ms", "Consecutive Failures",
        "Last No Reply",
    ])
    for host, data in data_snapshot.items():
        sent, received, loss, minimum, maximum, average = compute_host_stats(data)
        host_sheet.append([
            host, data.get("last_status") or "Awaiting first result",
            data.get("checks", sent), sent, received,
            loss if loss is not None else "N/A",
            minimum if minimum is not None else "N/A",
            maximum if maximum is not None else "N/A",
            average if average is not None else "N/A",
            data.get("consecutive_fails", 0), data.get("last_down_time", "-"),
        ])
    _style_workbook_table(host_sheet)
    host_sheet.column_dimensions["A"].width = 30
    host_sheet.column_dimensions["B"].width = 24
    for column in "CDEFGHIJ":
        host_sheet.column_dimensions[column].width = 18
    host_sheet.column_dimensions["K"].width = 22

    probe_sheet = workbook.create_sheet("Probe Details")
    probe_sheet.append(["Host", "Sequence", "Timestamp", "Status", "Latency ms", "Details"])
    for host, data in data_snapshot.items():
        for sequence, timestamp, status, details in data.get("log_rows", []):
            probe_details = "" if status == "Success" else (
                details or ("No ICMP reply before timeout" if is_down_status(status) else "")
            )
            probe_sheet.append([
                host, sequence, timestamp,
                "Connected" if status == "Success" else status,
                details if status == "Success" else None,
                probe_details,
            ])
    _style_workbook_table(probe_sheet)
    for column, width in {"A": 30, "B": 12, "C": 22, "D": 24, "E": 16, "F": 50}.items():
        probe_sheet.column_dimensions[column].width = width

    dns_failures = [
        (host, data) for host, data in data_snapshot.items() if data.get("last_status") == "DNS Error"
    ]
    if dns_failures:
        dns_sheet = workbook.create_sheet("DNS Failures")
        dns_sheet.append(["Target Hostname", "Status", "Detected At", "Error Details"])
        for host, data in dns_failures:
            dns_sheet.append([
                host,
                "DNS Error",
                data.get("last_down_time", "-"),
                data.get("last_error") or "Name resolution failed",
            ])
        _style_workbook_table(dns_sheet)
        dns_sheet.column_dimensions["A"].width = 30
        dns_sheet.column_dimensions["B"].width = 16
        dns_sheet.column_dimensions["C"].width = 22
        dns_sheet.column_dimensions["D"].width = 50

    workbook.save(out_path)
    return out_path


def export_report_csv(data_snapshot: dict, file_path: str | Path) -> Path:
    """Export DDE-sanitized CSV report with Summary, No ICMP Reply, DNS Failures, and Probe sections."""
    out_path = Path(file_path)
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        fieldnames = [
            "Section", "Host", "Sequence", "Status", "Sent", "Received",
            "Loss_Pct", "Latency_ms", "Min_ms", "Max_ms", "Avg_ms",
            "Consecutive_Fails", "Last_Down_At", "Timestamp", "Details",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        def write_sanitized_row(row_dict):
            writer.writerow({k: sanitize_csv_cell(v) for k, v in row_dict.items()})

        generated = time.strftime("%Y-%m-%d %H:%M:%S")
        for host, data in data_snapshot.items():
            sent, received, loss_pct, min_lat, max_lat, avg_lat = compute_host_stats(data)
            write_sanitized_row({
                "Section": "Summary",
                "Host": host,
                "Status": data.get("last_status") or "-",
                "Sent": sent,
                "Received": received,
                "Loss_Pct": loss_pct if loss_pct is not None else "",
                "Min_ms": min_lat if min_lat is not None else "",
                "Max_ms": max_lat if max_lat is not None else "",
                "Avg_ms": avg_lat if avg_lat is not None else "",
                "Consecutive_Fails": data.get("consecutive_fails", 0),
                "Last_Down_At": data.get("last_down_time", "-"),
                "Timestamp": generated,
            })
            had_no_reply = (
                is_down_status(data.get("last_status"))
                or (data.get("last_down_time") and data.get("last_down_time") != "-")
                or any(is_down_status(r[2]) for r in data.get("log_rows", []))
            )
            if had_no_reply:
                is_currently_down = is_down_status(data.get("last_status"))
                status_val = (
                    data.get("last_status")
                    if is_currently_down
                    else "No ICMP Reply (Recovered)"
                )
                details_val = (
                    data.get("last_error")
                    or ("Host currently down" if is_currently_down else "Host recovered after packet loss")
                )
                write_sanitized_row({
                    "Section": "No ICMP Reply",
                    "Host": host,
                    "Status": status_val,
                    "Consecutive_Fails": data.get("consecutive_fails", 0),
                    "Last_Down_At": data.get("last_down_time", "-"),
                    "Details": details_val,
                })
            if data.get("last_status") == "DNS Error":
                write_sanitized_row({
                    "Section": "DNS Failures",
                    "Host": host,
                    "Status": "DNS Error",
                    "Consecutive_Fails": data.get("consecutive_fails", 0),
                    "Last_Down_At": data.get("last_down_time", "-"),
                    "Timestamp": generated,
                    "Details": data.get("last_error") or "Name resolution failed",
                })
            for sequence, timestamp, status, details in data.get("log_rows", []):
                probe_details = "" if status == "Success" else (
                    details or ("No ICMP reply before timeout" if is_down_status(status) else "")
                )
                write_sanitized_row({
                    "Section": "Probe",
                    "Host": host,
                    "Sequence": sequence,
                    "Status": status,
                    "Latency_ms": details if status == "Success" else "",
                    "Timestamp": timestamp,
                    "Details": probe_details,
                })
    return out_path

