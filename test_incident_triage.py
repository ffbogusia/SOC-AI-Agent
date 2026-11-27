from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from incident_triage import find_cases, list_cases, read_log


NOW = datetime(2026, 6, 11, 12, tzinfo=timezone.utc)


def log_line(seconds, ip="192.0.2.1", endpoint="/admin/login", status=401, offset=0):
    time = (NOW + timedelta(seconds=seconds)).astimezone(timezone(timedelta(hours=offset)))
    return (
        f'{ip} - - [{time:%d/%b/%Y:%H:%M:%S %z}] '
        f'"POST {endpoint} HTTP/1.1" {status} 0 "-" "Browser"\n'
    )


class IncidentTriageTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.log = self.root / "access.log"

    def write_log(self, lines):
        self.log.write_text("".join(lines), encoding="utf-8")

    def cases(self, **kwargs):
        return find_cases(self.log, read_log(self.log), **kwargs)

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, str(Path(__file__).with_name("incident_triage.py").resolve()), *args],
            cwd=self.root, check=True, capture_output=True, text=True,
        ).stdout

    def test_single_failure_and_http_200(self):
        self.write_log([log_line(0, status=403), *[log_line(i, status=200) for i in range(12)]])
        self.assertEqual(self.cases(), [])

    def test_threshold_merges_windows_and_keeps_original_lines(self):
        self.write_log(["malformed line\n", *[
            log_line(30 * i, offset=i % 2 * 3, status=401 if i % 2 else 403)
            for i in reversed(range(12))
        ]])
        case, = self.cases()
        self.assertEqual(case["attempt_count"], 12)
        self.assertEqual(case["started_at"], NOW.isoformat())
        self.assertEqual(case["ended_at"], (NOW + timedelta(seconds=330)).isoformat())
        self.assertEqual([item["line"] for item in case["evidence"]], list(range(13, 1, -1)))

    def test_default_boundary_and_configurable_threshold(self):
        self.write_log([*[log_line(0) for _ in range(9)], log_line(300)])
        self.assertEqual(len(self.cases()), 1)
        self.assertEqual(self.cases(window_seconds=299), [])
        self.assertEqual(self.cases(min_attempts=11), [])

    def test_outside_window_and_separate_bursts(self):
        self.write_log([log_line(i * 301) for i in range(10)])
        self.assertEqual(self.cases(), [])
        self.write_log([log_line(start + i) for start in (0, 400) for i in range(10)])
        self.assertEqual([case["attempt_count"] for case in self.cases()], [10, 10])

    def test_different_ips_and_endpoints(self):
        self.write_log([
            *[log_line(i) for i in range(6)],
            *[log_line(i, ip="192.0.2.2") for i in range(6)],
            *[log_line(i, endpoint="/admin/login.php") for i in range(6)],
            *[log_line(i, endpoint="/admin/login-other") for i in range(10)],
        ])
        self.assertEqual(self.cases(), [])
        self.write_log([log_line(i, endpoint=f"/admin/login.php?retry={i}") for i in range(10)])
        self.assertEqual(self.cases()[0]["endpoint"], "/admin/login.php")

    def test_ipv6_normalizes_equivalent_addresses(self):
        self.write_log([
            log_line(i, ip="2001:db8::1" if i % 2 else "2001:0db8:0:0:0:0:0:1")
            for i in range(10)
        ])
        case, = self.cases()
        self.assertEqual(case["ip"], "2001:db8::1")

    def test_cli_rescan_preserves_case_status_and_comment(self):
        self.write_log([log_line(i) for i in range(10)])
        self.cli("scan", self.log.name)
        case, = json.loads(self.cli("list"))
        self.assertEqual(case["status"], "new")
        self.cli("set-status", case["id"], "investigating", "--comment", "Review approved")
        self.cli("scan", str(self.log))
        updated, = json.loads(self.cli("list"))
        self.assertEqual(updated["id"], case["id"])
        self.assertEqual(updated["status"], "investigating")
        self.assertEqual(updated["comment"], "Review approved")

    def test_report_pipeline_keeps_other_detections_and_uses_triage(self):
        import agent

        sql = log_line(370, endpoint="/products?q=or%201=1", status=400)
        jndi = log_line(371, endpoint="/", status=400).replace('"Browser"', '"${jndi:fixture}"')
        scan = log_line(372, endpoint="/.env", status=404)
        isolated = log_line(380, ip="192.0.2.2")
        self.write_log([isolated, sql, jndi, scan, *[log_line(i) for i in range(10)]])
        db = self.root / "report.db"
        previous_dir = Path.cwd()
        self.addCleanup(os.chdir, previous_dir)
        os.chdir(self.root)
        with patch.object(agent, "DB_FILE", db), patch.object(agent, "model") as model:
            model.invoke.return_value.content = "Report from test double"
            self.assertEqual(agent.run(self.log), "Report from test double")
            model.invoke.assert_called_once()
            failures = agent.get_events_by_type("BRUTE_FORCE")
            self.assertEqual(len(failures), 10)
            self.assertEqual({event["ip"] for event in failures}, {"192.0.2.1"})
            self.assertEqual(len(agent.get_events_by_type("SQLI")), 1)
            self.assertEqual(len(agent.get_events_by_type("LOG4SHELL")), 1)
            self.assertTrue(agent.get_events_by_type("SCAN"))
        self.assertIn("Report from test double", next(self.root.glob("SOC_REPORT_*.txt")).read_text())
        self.assertEqual(len(list_cases(db)), 1)


if __name__ == "__main__":
    unittest.main()
