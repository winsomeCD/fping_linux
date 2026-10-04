import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from probes import (
    ProbeResult,
    fping_available,
    fping_info,
    normalize_targets,
    parse_fping_event,
    parse_fping_text_line,
)


class TargetValidationTests(unittest.TestCase):
    def test_supplied_domain_list_count_and_duplicates(self):
        domain_list = Path(__file__).resolve().parents[1] / "ping_domains.txt"
        raw_targets = domain_list.read_text(encoding="utf-8").strip()

        targets, duplicate_count = normalize_targets(raw_targets)

        self.assertEqual(len(raw_targets.split(",")), 500)
        self.assertEqual(len(targets), 500)
        self.assertEqual(duplicate_count, 0)

    def test_normalize_targets_deduplicates_case_insensitively(self):
        targets, duplicate_count = normalize_targets("router.local, ROUTER.LOCAL, 1.1.1.1")
        self.assertEqual(targets, ["router.local", "1.1.1.1"])
        self.assertEqual(duplicate_count, 1)

    def test_normalize_targets_rejects_embedded_whitespace(self):
        with self.assertRaisesRegex(ValueError, "whitespace"):
            normalize_targets("router one.local")

    def test_normalize_targets_has_no_application_host_ceiling(self):
        targets, duplicate_count = normalize_targets(
            ",".join(f"host-{index}.local" for index in range(5000))
        )
        self.assertEqual(len(targets), 5000)
        self.assertEqual(duplicate_count, 0)


class FpingBackendTests(unittest.TestCase):
    def test_fping_json_response_maps_latency(self):
        result = parse_fping_event(
            b'{"resp":{"host":"ROUTER.LOCAL","rtt":4.126}}',
            {"router.local": "router.local"},
        )
        self.assertEqual(result, ("router.local", ProbeResult("Connected", 4.13)))

    def test_fping_timeout_maps_no_reply(self):
        result = parse_fping_event(
            '{"timeout":{"host":"192.0.2.1","seq":0}}',
            {"192.0.2.1": "192.0.2.1"},
        )
        self.assertEqual(result, ("192.0.2.1", ProbeResult("No ICMP Reply")))

    def test_fping_parser_ignores_unknown_or_malformed_events(self):
        aliases = {"known.example": "known.example"}
        self.assertIsNone(parse_fping_event("not json", aliases))
        self.assertIsNone(
            parse_fping_event('{"resp":{"host":"other.example","rtt":1}}', aliases)
        )
        self.assertIsNone(parse_fping_event('{"stats":{"targets":2}}', aliases))

    def test_older_fping_text_reply_and_timeout_are_parsed(self):
        aliases = {"router.local": "router.local", "192.0.2.1": "192.0.2.1"}
        reply = parse_fping_text_line(
            "[1596092373.18424] router.local : [0], 64 bytes, 12.3 ms (12.3 avg, 0% loss)",
            aliases,
        )
        timeout = parse_fping_text_line(
            "[1596092374.18223] 192.0.2.1 : [0], timed out (NaN avg, 100% loss)",
            aliases,
        )
        self.assertEqual(reply, ("router.local", ProbeResult("Connected", 12.3)))
        self.assertEqual(timeout, ("192.0.2.1", ProbeResult("No ICMP Reply")))

    @patch("probes.shutil.which", return_value=None)
    def test_fping_required_when_executable_is_missing(self, _which):
        self.assertFalse(fping_available())

    @patch("probes.shutil.which", return_value="/usr/bin/fping")
    @patch("probes.subprocess.run")
    def test_fping_json_capability_detection_is_optional(self, run_mock, _which):
        run_mock.side_effect = [
            SimpleNamespace(stdout="fping: Version 5.5", stderr=""),
            SimpleNamespace(stdout="fping usage --json", stderr=""),
        ]
        self.assertEqual(fping_info(), ("/usr/bin/fping", True))
        run_mock.side_effect = [
            SimpleNamespace(stdout="fping: Version 5.1", stderr=""),
            SimpleNamespace(stdout="fping usage", stderr=""),
        ]
        self.assertEqual(fping_info(), ("/usr/bin/fping", False))


if __name__ == "__main__":
    unittest.main()
