"""
Comprehensive Unit Tests for fping_linux & fping_linux_probes
"""

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from fping_linux_probes import (
    DNSResolver,
    NameLookupError,
    ProbeResult,
    build_fping_command,
    calculate_fping_timing,
    calculate_rfc3550_jitter,
    calculate_percentile,
    normalize_targets,
    parse_fping_event,
    parse_fping_text_line,
)
from fping_linux import (
    DNSIssuesDialog,
    PingMonitorApp,
    SortableTableWidgetItem,
    _sanitize_csv_cell,
)


class TestNormalizeTargets(unittest.TestCase):
    def test_normalize_valid_comma_and_spaces(self):
        raw = " 8.8.8.8, 1.1.1.1, google.com  "
        targets, dupes = normalize_targets(raw)
        self.assertEqual(targets, ["8.8.8.8", "1.1.1.1", "google.com"])
        self.assertEqual(dupes, 0)

    def test_normalize_duplicates(self):
        raw = "8.8.8.8, 1.1.1.1, 8.8.8.8, 1.1.1.1"
        targets, dupes = normalize_targets(raw)
        self.assertEqual(targets, ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(dupes, 2)

    def test_normalize_newlines_and_tabs(self):
        raw = "8.8.8.8\n1.1.1.1\t9.9.9.9"
        targets, dupes = normalize_targets(raw)
        self.assertEqual(targets, ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
        self.assertEqual(dupes, 0)

    def test_normalize_empty(self):
        targets, dupes = normalize_targets("")
        self.assertEqual(targets, [])
        self.assertEqual(dupes, 0)

    def test_normalize_invalid_characters(self):
        with self.assertRaises(ValueError):
            normalize_targets("8.8.8.8; rm -rf /")

    def test_cidr_expansion_24(self):
        targets, dupes = normalize_targets("10.128.7.0/24")
        self.assertEqual(len(targets), 254)
        self.assertEqual(targets[0], "10.128.7.1")
        self.assertEqual(targets[-1], "10.128.7.254")
        self.assertNotIn("10.128.7.0", targets)
        self.assertNotIn("10.128.7.255", targets)
        self.assertEqual(dupes, 0)

    def test_cidr_expansion_with_host_bits(self):
        targets, dupes = normalize_targets("10.128.7.50/24")
        self.assertEqual(len(targets), 254)
        self.assertEqual(targets[0], "10.128.7.1")
        self.assertEqual(targets[-1], "10.128.7.254")

    def test_cidr_safety_threshold_22_allowed(self):
        # /22 generates 1022 usable hosts
        targets, dupes = normalize_targets("10.0.0.0/22")
        self.assertEqual(len(targets), 1022)
        self.assertEqual(dupes, 0)

    def test_cidr_safety_threshold_22_exceeded(self):
        # Prefixes broader than /22 (e.g. /21, /16, /8, /0) must be rejected
        for prefix in (21, 16, 15, 8):
            with self.assertRaises(ValueError) as ctx:
                normalize_targets(f"10.0.0.0/{prefix}")
            self.assertIn("/22", str(ctx.exception))

    def test_cidr_boundary_31_and_32(self):
        targets_31, _ = normalize_targets("192.168.1.0/31")
        self.assertEqual(targets_31, ["192.168.1.0", "192.168.1.1"])

        targets_32, _ = normalize_targets("192.168.1.5/32")
        self.assertEqual(targets_32, ["192.168.1.5"])

    def test_cidr_mixed_with_domains_and_ips_deduplication(self):
        raw = "10.128.7.1, 10.128.7.0/24, 8.8.8.8, google.com"
        targets, dupes = normalize_targets(raw)
        # 10.128.7.1 is duplicate because /24 also produces 10.128.7.1
        self.assertEqual(dupes, 1)
        self.assertEqual(len(targets), 256)  # 254 hosts + 8.8.8.8 + google.com
        self.assertIn("10.128.7.1", targets)
        self.assertIn("8.8.8.8", targets)
        self.assertIn("google.com", targets)

    def test_cidr_ipv6_expansion_and_limit(self):
        targets, dupes = normalize_targets("2001:db8::/126")
        self.assertEqual(len(targets), 4)
        self.assertEqual(dupes, 0)

        with self.assertRaises(ValueError) as ctx:
            normalize_targets("2001:db8::/64")
        self.assertIn("IPv6", str(ctx.exception))


class TestNetworkMetrics(unittest.TestCase):
    def test_rfc3550_jitter_calculation(self):
        # Empty or single sample has 0 jitter
        self.assertEqual(calculate_rfc3550_jitter([]), 0.0)
        self.assertEqual(calculate_rfc3550_jitter([10.0]), 0.0)
        # Constant latency has 0 jitter
        self.assertEqual(calculate_rfc3550_jitter([15.0, 15.0, 15.0]), 0.0)
        # Fluctuating samples: difference of 16 ms in first step adds 1.0 ms jitter
        samples = [10.0, 26.0]
        # J_1 = 0 + (16 - 0) / 16 = 1.0
        self.assertAlmostEqual(calculate_rfc3550_jitter(samples), 1.0, places=2)

    def test_percentile_calculation(self):
        self.assertEqual(calculate_percentile([], 95), 0.0)
        samples = list(range(1, 101))  # 1 to 100
        # 95th percentile of 1..100 should be approx 95.05
        p95 = calculate_percentile(samples, 95)
        self.assertTrue(94.0 <= p95 <= 96.0)
        self.assertEqual(calculate_percentile([10.0], 95), 10.0)


class TestCalculateFpingTiming(unittest.TestCase):
    def test_timing_calculation_normal(self):
        period, timeout, gap = calculate_fping_timing(
            target_count=10,
            interval_seconds=1.0,
            timeout_seconds=0.5,
            requested_send_gap_ms=10,
        )
        self.assertEqual(timeout, 500)
        self.assertGreaterEqual(period, 1000)
        self.assertLessEqual(gap, 100)

    def test_timing_zero_targets_raises(self):
        with self.assertRaises(ValueError):
            calculate_fping_timing(0, 1.0, 0.5, 10)


class TestBuildFpingCommand(unittest.TestCase):
    def test_command_json(self):
        cmd = build_fping_command("fping", use_json=True, payload_size=56, send_gap_ms=10, period_ms=1000, timeout_ms=500)
        self.assertIn("-J", cmd)
        self.assertIn("-l", cmd)
        self.assertIn("-e", cmd)
        self.assertIn("-r", cmd)
        self.assertEqual(cmd[0], "fping")

    def test_command_text(self):
        cmd = build_fping_command("fping", use_json=False, payload_size=64, send_gap_ms=5, period_ms=500, timeout_ms=250)
        self.assertNotIn("-J", cmd)
        self.assertIn("-b", cmd)
        self.assertIn("64", cmd)


class TestParseFpingEvent(unittest.TestCase):
    def test_parse_json_reply(self):
        payload = '{"resp": {"host": "8.8.8.8", "seq": 0, "rtt": 12.34}}'
        host, res = parse_fping_event(payload)
        self.assertEqual(host, "8.8.8.8")
        self.assertEqual(res.status, "Connected")
        self.assertAlmostEqual(res.latency_ms, 12.34)

    def test_parse_json_timeout(self):
        payload = '{"timeout": {"host": "192.0.2.1", "seq": 0}}'
        host, res = parse_fping_event(payload)
        self.assertEqual(host, "192.0.2.1")
        self.assertEqual(res.status, "No ICMP Reply")
        self.assertIsNone(res.latency_ms)


class TestParseFpingTextLine(unittest.TestCase):
    def test_parse_text_reply(self):
        line = "8.8.8.8 : [0], 84 bytes, 14.2 ms (14.2 avg, 0% loss)"
        host, res = parse_fping_text_line(line)
        self.assertEqual(host, "8.8.8.8")
        self.assertEqual(res.status, "Connected")
        self.assertAlmostEqual(res.latency_ms, 14.2)

    def test_parse_text_timed_out(self):
        line = "192.0.2.1 : [0], timed out"
        host, res = parse_fping_text_line(line)
        self.assertEqual(host, "192.0.2.1")
        self.assertEqual(res.status, "No ICMP Reply")
        self.assertIsNone(res.latency_ms)

    def test_parse_text_unreachable(self):
        line = "192.0.2.1 : [0], unreachable"
        host, res = parse_fping_text_line(line)
        self.assertEqual(host, "192.0.2.1")
        self.assertEqual(res.status, "Unreachable")


class TestDNSResolver(unittest.TestCase):
    def test_resolver_ip_literal(self):
        resolver = DNSResolver()
        resolved = asyncio.run(resolver.resolve("8.8.8.8"))
        self.assertEqual(resolved, "8.8.8.8")

    def test_resolver_caching(self):
        resolver = DNSResolver(ttl_seconds=60)
        res1 = asyncio.run(resolver.resolve("1.1.1.1"))
        res2 = asyncio.run(resolver.resolve("1.1.1.1"))
        self.assertEqual(res1, res2)

    def test_multi_check_dns_failure(self):
        """Verify that DNSResolver performs more than 1 DNS check on invalid targets before raising."""
        resolver = DNSResolver(retries=3, retry_delay=0.05)
        call_count = 0

        async def _test():
            nonlocal call_count
            loop = asyncio.get_running_loop()
            orig_getaddrinfo = loop.getaddrinfo

            async def mock_getaddrinfo(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                raise OSError("Name or service not known")

            loop.getaddrinfo = mock_getaddrinfo
            try:
                with self.assertRaises(NameLookupError) as ctx:
                    await resolver.resolve("definitely-unresolved-host.invalid")
                self.assertGreaterEqual(ctx.exception.attempts, 2)
                self.assertGreaterEqual(call_count, 2)
            finally:
                loop.getaddrinfo = orig_getaddrinfo

        asyncio.run(_test())

    def test_multi_check_success_after_initial_glitch(self):
        """Verify that a transient glitch on check 1 recovers on check 2."""
        resolver = DNSResolver(retries=3, retry_delay=0.05)
        call_count = 0

        async def _test():
            nonlocal call_count
            loop = asyncio.get_running_loop()
            orig_getaddrinfo = loop.getaddrinfo

            async def mock_getaddrinfo(host, port, *args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count <= 2:  # fail both IPv4 and IPv6 on attempt 1
                    raise OSError("Temporary name server failure")
                # succeed on attempt 2
                return [(None, None, None, None, ("93.184.216.34", 0))]

            loop.getaddrinfo = mock_getaddrinfo
            try:
                ip = await resolver.resolve("recovered.example.com")
                self.assertEqual(ip, "93.184.216.34")
                self.assertGreater(call_count, 2)
            finally:
                loop.getaddrinfo = orig_getaddrinfo

        asyncio.run(_test())

    def test_pre_resolve_large_fleet_does_not_timeout_in_queue(self):
        """Verify that a fleet with many domains waiting in the semaphore queue does not prematurely time out."""
        resolver = DNSResolver(max_concurrent=5, retries=2, retry_delay=0.01)

        async def _test():
            loop = asyncio.get_running_loop()
            orig_getaddrinfo = loop.getaddrinfo

            async def mock_getaddrinfo(host, port, *args, **kwargs):
                await asyncio.sleep(0.01)
                return [(None, None, None, None, ("192.0.2.1", 0))]

            loop.getaddrinfo = mock_getaddrinfo
            try:
                targets = [f"queued_host_{i}.lan" for i in range(40)]
                resolved = await resolver.pre_resolve_all(targets)
                self.assertEqual(len(resolved), 40)
                for target in targets:
                    self.assertEqual(resolved[target], "192.0.2.1")
            finally:
                loop.getaddrinfo = orig_getaddrinfo

        asyncio.run(_test())


class TestSortableTableWidgetItem(unittest.TestCase):
    def test_numeric_sorting(self):
        item1 = SortableTableWidgetItem("12.5 ms", numeric=True)
        item2 = SortableTableWidgetItem("5.1 ms", numeric=True)
        item3 = SortableTableWidgetItem("100.0 ms", numeric=True)

        self.assertTrue(item2 < item1)
        self.assertTrue(item1 < item3)
        self.assertTrue(item2 < item3)

    def test_text_sorting(self):
        item_a = SortableTableWidgetItem("alpha", numeric=False)
        item_b = SortableTableWidgetItem("beta", numeric=False)
        self.assertTrue(item_a < item_b)


class TestDNSIssuesIsolationAndUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)

    def test_dns_issues_dialog_and_export(self):
        issues = [
            ("bad1.invalid", {"last_error": "DNS resolution failed after 3 checks: lookup timed out", "last_down_time": "2026-10-18 12:00:00"}),
            ("bad2.invalid", {"last_error": "DNS resolution failed after 3 checks: no address found", "last_down_time": "2026-10-18 12:01:00"}),
        ]
        dialog = DNSIssuesDialog(issues, dark=True)
        dialog.show()
        self.app.processEvents()

        self.assertEqual(dialog.table.rowCount(), 2)
        self.assertEqual(dialog.table.item(0, 0).text(), "bad1.invalid")
        self.assertEqual(dialog.table.item(0, 1).text(), "DNS Error")
        self.assertIn("3 checks", dialog.table.item(0, 2).text())

        # Test filtering
        dialog._filter_table("bad2")
        self.assertTrue(dialog.table.isRowHidden(0))
        self.assertFalse(dialog.table.isRowHidden(1))
        self.assertIn("1 of 2", dialog.counter_label.text())

        dialog._filter_table("")
        self.assertFalse(dialog.table.isRowHidden(0))
        self.assertFalse(dialog.table.isRowHidden(1))
        dialog.close()

    def test_dns_error_host_excluded_from_table_and_chart(self):
        win = PingMonitorApp()
        win.show()
        self.app.processEvents()

        # Set up 3 hosts directly
        hosts = ["valid1.test", "valid2.test", "bad-dns.invalid"]
        win.hosts = hosts
        win.host_entry.setText(", ".join(hosts))
        win.is_monitoring = True
        win._run_id = 42

        for host in hosts:
            win.host_data[host] = {
                "sent": 0, "received": 0, "checks": 0,
                "latencies": [], "latency_count": 0, "latency_sum": 0.0,
                "min_latency": None, "max_latency": None,
                "consecutive_fails": 0, "last_status": "Queued",
                "last_error": None, "last_down_time": "-",
                "timeline_stats": [], "log_rows": [],
            }
            row = win.table.rowCount()
            win.table.insertRow(row)
            item = SortableTableWidgetItem(host)
            win.table.setItem(row, 0, item)
            win._host_items[host] = item

        self.assertEqual(win.table.rowCount(), 3)

        # Emit results
        win._handle_probe_result(42, "valid1.test", ProbeResult("Connected", 12.4))
        win._handle_probe_result(42, "valid2.test", ProbeResult("No ICMP Reply", None))
        win._handle_probe_result(
            42, "bad-dns.invalid",
            ProbeResult("DNS Error", error="DNS lookup failed after 3 checks", packet_sent=False)
        )
        self.app.processEvents()
        win.refresh_dashboard()

        # 1. DNS error host MUST be removed from Live Telemetry table!
        table_hosts = [win.table.item(r, 0).text() for r in range(win.table.rowCount())]
        self.assertIn("valid1.test", table_hosts)
        self.assertIn("valid2.test", table_hosts)
        self.assertNotIn("bad-dns.invalid", table_hosts)
        self.assertEqual(win.table.rowCount(), 2)

        # 2. DNS Pill button must show count
        self.assertEqual(win.dns_issues_btn.text(), "⚠ 1 DNS Issue")

        # 3. Chart data MUST exclude the DNS Error host
        chart_data = win.chart.history
        self.assertIn("valid1.test", chart_data)
        self.assertIn("valid2.test", chart_data)
        self.assertNotIn("bad-dns.invalid", chart_data)

        # 4. Header label must show monitored count
        self.assertIn("2 monitored", win.host_count_label.text())

        # 5. Down summary label must mention DNS issue
        self.assertIn("1 DNS issue", win.down_summary_label.text())

        win.is_monitoring = False
        win.close()

    def test_chart_renders_all_hosts_without_cap(self):
        win = PingMonitorApp()
        win.show()
        self.app.processEvents()

        # Generate 120 resolvable hosts + 2 DNS failed hosts (122 total)
        hosts = [f"host_{i}.lan" for i in range(1, 121)] + ["dns_bad_1.corp", "dns_bad_2.corp"]
        win.hosts = hosts
        win.host_entry.setText(", ".join(hosts))
        win.is_monitoring = True
        win._run_id = 99

        for i, host in enumerate(hosts):
            if "dns_bad" in host:
                win.host_data[host] = {
                    "sent": 0, "received": 0, "checks": 0,
                    "latencies": [], "latency_count": 0, "latency_sum": 0.0,
                    "min_latency": None, "max_latency": None,
                    "consecutive_fails": 3, "last_status": "DNS Error",
                    "last_error": "Lookup failed after 3 checks", "last_down_time": "-",
                    "timeline_stats": [], "log_rows": [],
                }
            else:
                win.host_data[host] = {
                    "sent": 5, "received": 5, "checks": 5,
                    "latencies": [10.0 + (i % 20), 12.0 + (i % 20)], "latency_count": 2, "latency_sum": 22.0,
                    "min_latency": 10.0, "max_latency": 12.0,
                    "consecutive_fails": 0, "last_status": "Connected",
                    "last_error": None, "last_down_time": "-",
                    "timeline_stats": [], "log_rows": [],
                }
            row = win.table.rowCount()
            win.table.insertRow(row)
            item = SortableTableWidgetItem(host)
            win.table.setItem(row, 0, item)
            win._host_items[host] = item

        self.app.processEvents()
        win.refresh_dashboard()
        self.app.processEvents()

        # Latency chart renders all 120 resolvable hosts
        self.assertEqual(len(win.chart.history), 120)
        self.assertEqual(win.chart.total_candidates, 120)

        # Must contain hosts throughout the fleet in the chart
        self.assertIn("host_1.lan", win.chart.history)
        self.assertIn("host_20.lan", win.chart.history)
        self.assertIn("host_21.lan", win.chart.history)
        self.assertIn("host_50.lan", win.chart.history)
        self.assertIn("host_120.lan", win.chart.history)

        # DNS failed hosts must remain excluded
        self.assertNotIn("dns_bad_1.corp", win.chart.history)

        # Repaint must execute without exception
        win.chart.repaint()
        self.app.processEvents()

        win.is_monitoring = False
        win.close()

    def test_packet_loss_sorting_and_row_integrity(self):
        win = PingMonitorApp()
        win.show()
        self.app.processEvents()

        hosts = [f"host_{i}.net" for i in range(1, 21)]
        win.hosts = hosts
        win.host_entry.setText(", ".join(hosts))
        win.is_monitoring = True
        win._run_id = 10

        for i, host in enumerate(hosts):
            win.host_data[host] = {
                "sent": 10, "received": 10 - (i % 5) * 2, "checks": 10,
                "latencies": [15.0 + i], "latency_count": 1, "latency_sum": 15.0 + i,
                "min_latency": 15.0 + i, "max_latency": 15.0 + i,
                "consecutive_fails": (i % 5), "last_status": "Connected",
                "last_error": None, "last_down_time": "-",
                "timeline_stats": [], "log_rows": [],
            }
            row = win.table.rowCount()
            win.table.insertRow(row)
            loss_pct = ((10 - win.host_data[host]["received"]) / 10) * 100
            vals = [host, "Connected", "10", f"{15.0+i:.1f} ms", f"{loss_pct:.1f}%", str(i % 5)]
            sort_vals = {2: 10, 3: 15.0 + i, 4: loss_pct, 5: i % 5}
            for col, val in enumerate(vals):
                it = SortableTableWidgetItem(val, numeric=col in (2, 3, 4, 5), sort_value=sort_vals.get(col))
                win.table.setItem(row, col, it)
                if col == 0:
                    win._host_items[host] = it

        # Click Packet Loss header (col 4) - should default to Descending (highest loss first)
        win.on_table_header_clicked(4)
        self.app.processEvents()

        # Check top row has highest loss
        top_loss_item = win.table.item(0, 4)
        top_loss_val = top_loss_item.data(Qt.UserRole)
        self.assertEqual(top_loss_val, 80.0)

        # Send an update for host_1.net while sort is active
        # host_1 currently has loss 0%. Update it to 100% loss
        win._handle_probe_result(10, "host_1.net", ProbeResult("No ICMP Reply", None))
        self.app.processEvents()

        # Row integrity: col 0 must match host_items lookup
        for host in hosts:
            it = win._host_items[host]
            row_idx = it.row()
            cell_host = win.table.item(row_idx, 0).text()
            self.assertEqual(cell_host, host)

        # Trigger dashboard refresh (which does periodic sort)
        win.refresh_dashboard()
        self.app.processEvents()

        # host_1.net now has loss, ensure it remains matched with its row
        it_1 = win._host_items["host_1.net"]
        row_1 = it_1.row()
        self.assertEqual(win.table.item(row_1, 0).text(), "host_1.net")

        win.is_monitoring = False
        win.close()

    def test_export_default_filenames_include_timestamp(self):
        import re
        win = PingMonitorApp()
        win.show()
        self.app.processEvents()

        target = "router.example"
        win.host_data[target] = {
            "sent": 1, "received": 1, "checks": 1,
            "latencies": [5.0], "latency_count": 1,
            "latency_sum": 5.0, "min_latency": 5.0, "max_latency": 5.0,
            "last_status": "Connected", "last_error": None,
            "consecutive_fails": 0, "last_down_time": "-",
            "timeline_stats": ["Seq 1: Connected"], "log_rows": [(1, "12:00:00", "Connected", "5.0 ms")],
        }
        captured_defaults = {}

        def fake_dialog(title, name_filter, save=False, default_name="", default_suffix=""):
            captured_defaults[default_suffix] = default_name
            return None

        win._open_file_dialog = fake_dialog

        win.export_report_summary()
        win.export_report_xlsx()
        win.export_report_csv()

        self.assertTrue(re.match(r"^network_report_\d{8}_\d{6}\.txt$", captured_defaults.get("txt", "")))
        self.assertTrue(re.match(r"^network_report_\d{8}_\d{6}\.xlsx$", captured_defaults.get("xlsx", "")))
        self.assertTrue(re.match(r"^network_report_\d{8}_\d{6}\.csv$", captured_defaults.get("csv", "")))

        win.close()

    def test_csv_sanitization_dde_attacks(self):
        # Formula injection strings must be prefixed with single quote
        self.assertEqual(_sanitize_csv_cell("=cmd|'/C calc'!A0"), "'=cmd|'/C calc'!A0")
        self.assertEqual(_sanitize_csv_cell("+cmd|'/C calc'!A0"), "'+cmd|'/C calc'!A0")
        self.assertEqual(_sanitize_csv_cell("-cmd|'/C calc'!A0"), "'-cmd|'/C calc'!A0")
        self.assertEqual(_sanitize_csv_cell("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(_sanitize_csv_cell("\tmalicious"), "'\tmalicious")
        # Regular numeric values must remain unchanged
        self.assertEqual(_sanitize_csv_cell(12.5), 12.5)
        self.assertEqual(_sanitize_csv_cell("-5.2"), "-5.2")
        self.assertEqual(_sanitize_csv_cell("+10"), "+10")
        self.assertEqual(_sanitize_csv_cell("8.8.8.8"), "8.8.8.8")

    def test_csv_export_includes_recovered_hosts_with_lost_pings(self):
        import csv
        import tempfile
        win = PingMonitorApp()
        win._msg = lambda *args, **kwargs: None
        win._confirm = lambda *args: False
        win.show()
        self.app.processEvents()

        target = "recovered.example"
        win.host_data[target] = {
            "sent": 3, "received": 2, "checks": 3,
            "latencies": [10.0, 0, 12.0], "latency_count": 2,
            "latency_sum": 22.0, "min_latency": 10.0, "max_latency": 12.0,
            "last_status": "Connected", "last_error": None,
            "consecutive_fails": 0, "last_down_time": "2026-10-03 12:00:01",
            "timeline_stats": [
                "[2026-10-03 12:00:00] Seq 1: Success — Latency 10.00 ms",
                "[2026-10-03 12:00:01] Seq 2: FAILED — No ICMP Reply",
                "[2026-10-03 12:00:02] Seq 3: Success — Latency 12.00 ms",
            ],
            "log_rows": [
                (1, "2026-10-03 12:00:00", "Success", 10.0),
                (2, "2026-10-03 12:00:01", "No ICMP Reply", ""),
                (3, "2026-10-03 12:00:02", "Success", 12.0),
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report_recovered.csv"
            win._open_file_dialog = lambda *args, **kwargs: str(report_path)

            win.export_report_csv()

            with report_path.open(encoding="utf-8-sig", newline="") as report_file:
                rows = list(csv.DictReader(report_file))

            # 1. Recovered host with lost pings must appear in No ICMP Reply section
            no_reply_rows = [r for r in rows if r["Section"] == "No ICMP Reply"]
            self.assertEqual(len(no_reply_rows), 1)
            self.assertEqual(no_reply_rows[0]["Host"], target)
            self.assertIn("Recovered", no_reply_rows[0]["Status"])
            self.assertEqual(no_reply_rows[0]["Last_Down_At"], "2026-10-03 12:00:01")

            # 2. Probe section must contain the No ICMP Reply row with diagnostic details
            probe_rows = [r for r in rows if r["Section"] == "Probe"]
            self.assertEqual(len(probe_rows), 3)
            lost_ping_probe = next(r for r in probe_rows if r["Status"] == "No ICMP Reply")
            self.assertEqual(lost_ping_probe["Sequence"], "2")
            self.assertEqual(lost_ping_probe["Details"], "No ICMP reply before timeout")

        win.close()

    def test_txt_export_includes_recovered_hosts_with_lost_pings(self):
        import tempfile
        win = PingMonitorApp()
        win._msg = lambda *args, **kwargs: None
        win._confirm = lambda *args: False
        win.show()
        self.app.processEvents()

        target = "recovered.example"
        win.host_data[target] = {
            "sent": 3, "received": 2, "checks": 3,
            "latencies": [10.0, 0, 12.0], "latency_count": 2,
            "latency_sum": 22.0, "min_latency": 10.0, "max_latency": 12.0,
            "last_status": "Connected", "last_error": None,
            "consecutive_fails": 0, "last_down_time": "2026-10-03 12:00:01",
            "timeline_stats": [
                "[2026-10-03 12:00:00] Seq 1: Success — Latency 10.00 ms",
                "[2026-10-03 12:00:01] Seq 2: FAILED — No ICMP Reply",
                "[2026-10-03 12:00:02] Seq 3: Success — Latency 12.00 ms",
            ],
            "log_rows": [
                (1, "2026-10-03 12:00:00", "Success", 10.0),
                (2, "2026-10-03 12:00:01", "No ICMP Reply", ""),
                (3, "2026-10-03 12:00:02", "Success", 12.0),
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report_recovered.txt"
            win._open_file_dialog = lambda *args, **kwargs: str(report_path)

            win.export_report_summary()

            report = report_path.read_text(encoding="utf-8")
            self.assertNotIn("No target recorded an ICMP timeout", report)
            self.assertIn("recovered.example", report)
            self.assertIn("Recovered", report)
            self.assertIn("2026-10-03 12:00:01", report)

        win.close()

    def test_xlsx_export_probe_details_includes_no_icmp_reply_description(self):
        import tempfile
        from openpyxl import load_workbook
        win = PingMonitorApp()
        win._msg = lambda *args, **kwargs: None
        win._confirm = lambda *args: False
        win.show()
        self.app.processEvents()

        target = "recovered.example"
        win.host_data[target] = {
            "sent": 2, "received": 1, "checks": 2,
            "latencies": [10.0, 0], "latency_count": 1,
            "latency_sum": 10.0, "min_latency": 10.0, "max_latency": 10.0,
            "last_status": "Connected", "last_error": None,
            "consecutive_fails": 0, "last_down_time": "2026-10-03 12:00:01",
            "timeline_stats": [],
            "log_rows": [
                (1, "2026-10-03 12:00:00", "Success", 10.0),
                (2, "2026-10-03 12:00:01", "No ICMP Reply", ""),
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report_recovered.xlsx"
            win._open_file_dialog = lambda *args, **kwargs: str(report_path)

            win.export_report_xlsx()

            workbook = load_workbook(report_path, data_only=True)
            probe_sheet = workbook["Probe Details"]
            rows = list(probe_sheet.iter_rows(values_only=True))
            self.assertEqual(rows[0], ("Host", "Sequence", "Timestamp", "Status", "Latency ms", "Details"))
            lost_ping_row = next(r for r in rows[1:] if r[3] == "No ICMP Reply")
            self.assertEqual(lost_ping_row[0], target)
            self.assertEqual(lost_ping_row[1], 2)
            self.assertEqual(lost_ping_row[5], "No ICMP reply before timeout")

        win.close()

    def test_in_flight_probes_processed_during_stop_pending(self):
        win = PingMonitorApp()
        win._msg = lambda *args, **kwargs: None
        win._confirm = lambda *args: False
        win.show()
        self.app.processEvents()

        target = "pending.example"
        win._run_id = 77
        win.is_monitoring = False
        win._stop_pending = True
        win.host_data[target] = {
            "sent": 0, "received": 0, "checks": 0,
            "latencies": [], "latency_count": 0,
            "latency_sum": 0.0, "min_latency": None, "max_latency": None,
            "timeline_stats": [], "log_rows": [], "last_status": None,
            "last_error": None, "consecutive_fails": 0, "last_down_time": "-",
        }
        win.table.setRowCount(1)
        item = SortableTableWidgetItem(target)
        win.table.setItem(0, 0, item)
        win._host_items[target] = item

        win._handle_probe_result(77, target, ProbeResult("No ICMP Reply"))

        self.assertEqual(len(win.host_data[target]["log_rows"]), 1)
        self.assertEqual(win.host_data[target]["log_rows"][0][2], "No ICMP Reply")
        self.assertEqual(win.host_data[target]["last_status"], "No ICMP Reply")
        self.assertNotEqual(win.host_data[target]["last_down_time"], "-")

        win.close()


if __name__ == "__main__":
    unittest.main()


