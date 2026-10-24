"""
Verification script for fping_linux redesign and security controls
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtWidgets import QApplication
from fping_linux import PingMonitorApp, _sanitize_csv_cell, _ensure_system_fonts
from fping_linux_probes import normalize_targets, ProbeResult


class TestVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)
        _ensure_system_fonts()

    def test_csv_sanitization(self):
        self.assertEqual(_sanitize_csv_cell("=cmd"), "'=cmd")
        self.assertEqual(_sanitize_csv_cell("+123"), "+123")
        self.assertEqual(_sanitize_csv_cell(-12.4), -12.4)
        self.assertEqual(_sanitize_csv_cell("@SUM(1+1)"), "'@SUM(1+1)")
        self.assertEqual(_sanitize_csv_cell("-dangerous_calc"), "'-dangerous_calc")
        self.assertEqual(_sanitize_csv_cell("normal_text"), "normal_text")

    def test_target_security(self):
        targets, dupes = normalize_targets("8.8.8.8, 1.1.1.1, 8.8.8.8")
        self.assertEqual(targets, ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(dupes, 1)

        with self.assertRaises(ValueError):
            normalize_targets("test\x00evil.com")

        with self.assertRaises(ValueError):
            normalize_targets("a" * 260)

    def test_app_ui_and_telemetry(self):
        win = PingMonitorApp()
        win.show()
        win.resize(1200, 800)
        self.app.processEvents()

        self.assertEqual(win.card_fleet.lbl_val.text(), "0 Targets")
        self.assertEqual(win.card_reachability.lbl_val.text(), "100%")

        # Setup hosts and simulate telemetry with mocked background runner and message boxes
        win._fallback_notice_shown = True
        win._msg = lambda *args, **kwargs: None
        win.host_entry.setText("8.8.8.8, 1.1.1.1")
        with patch.object(win.probe_pool, "start"):
            win.toggle_monitoring()
        self.app.processEvents()

        win._handle_probe_result(win._run_id, "8.8.8.8", ProbeResult("Connected", 14.5))
        win._handle_probe_result(win._run_id, "1.1.1.1", ProbeResult("No ICMP Reply", None))
        self.app.processEvents()
        win.refresh_dashboard()

        self.assertEqual(win.card_fleet.lbl_val.text(), "2 Targets")
        self.assertEqual(win.card_reachability.lbl_val.text(), "50.0%")

        # Grab dark mode screenshot
        pix_dark = win.grab()
        pix_dark.save("ui_redesign_dark.png")

        # Toggle theme and verify
        initial_dark = win._is_dark
        win.toggle_theme()
        self.app.processEvents()
        self.assertEqual(win._is_dark, not initial_dark)

        # Grab toggled screenshot
        pix_light = win.grab()
        pix_light.save("ui_redesign_toggled.png")

        # Stop monitoring and reset
        win._confirm = lambda *args: False
        win.stop_monitoring()
        win.host_data.clear()
        win.update_footer_stats()
        self.assertEqual(win.card_fleet.lbl_val.text(), "0 Targets")
        win.close()


if __name__ == "__main__":
    unittest.main()
