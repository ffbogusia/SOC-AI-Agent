from contextlib import closing
import json
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from suricata_eve import EveReader, open_database


CLI = Path(__file__).with_name("suricata_eve.py").resolve()


def alert(second, *, ports=True):
    event = {
        "event_type": "alert",
        "timestamp": f"2026-11-26T13:00:{second:02}+0100",
        "src_ip": "127.0.0.1",
        "dest_ip": "::1",
        "alert": {"signature_id": 1000001, "signature": "Example", "severity": 3, "rev": 4},
    }
    if ports:
        event.update(src_port=41233, dest_port=41234)
    return (json.dumps(event) + "\n").encode()


class EveTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.eve = Path(directory.name) / "eve.json"
        self.database = self.eve.with_suffix(".sqlite3")

    def import_once(self):
        with closing(open_database(self.database)) as db:
            return list(EveReader(db, self.eve).batches())

    def rows(self):
        with closing(open_database(self.database)) as db:
            return db.execute("SELECT * FROM suricata_alerts ORDER BY id").fetchall()

    def test_import_and_replay_preserve_fields(self):
        self.eve.write_bytes(alert(1) + alert(2, ports=False))
        self.assertEqual(self.import_once(), [(2, 0)])
        self.assertEqual(self.import_once(), [])
        first, second = self.rows()
        self.assertEqual(first["timestamp"], "2026-11-26T13:00:01+0100")
        self.assertEqual(first["severity"], 3)
        self.assertEqual(first["src_port"], 41233)
        self.assertEqual(first["dest_port"], 41234)
        self.assertEqual(first["dest_ip"], "::1")
        self.assertEqual(first["source"], str(self.eve))
        self.assertEqual(second["source_offset"], len(alert(1)))
        self.assertIsNone(second["src_port"])
        self.assertIsNone(second["dest_port"])
        self.assertEqual(json.loads(second["eve_json"])["alert"]["rev"], 4)

    def test_partial_and_malformed_records(self):
        partial = alert(1)
        invalid_alert = b'{"event_type":"alert","alert":{}}\n'
        self.eve.write_bytes(b'{"event_type":"flow"}\n' + b'bad json\n' + invalid_alert + partial[:25])
        self.assertEqual(self.import_once(), [(0, 2)])
        self.assertEqual(self.import_once(), [])
        with self.eve.open("ab") as stream:
            stream.write(partial[25:])
        self.assertEqual(self.import_once(), [(1, 0)])
        self.assertEqual(len(self.rows()), 1)

    def test_restart_after_rename_rotation_and_replayed_alert(self):
        self.eve.write_bytes(alert(1))
        self.import_once()
        self.eve.rename(self.eve.with_name("eve.json.1"))
        self.eve.write_bytes(alert(1) + alert(2))
        self.assertEqual(self.import_once(), [(1, 0)])
        self.assertEqual(len(self.rows()), 2)

    def test_copytruncate_with_regrowth_beyond_checkpoint(self):
        self.eve.write_bytes(alert(1))
        self.import_once()
        self.eve.write_bytes(alert(2) + alert(3))
        self.assertEqual(self.import_once(), [(2, 0)])
        self.assertEqual(len(self.rows()), 3)

    def test_follow_drains_old_file_before_switching(self):
        self.eve.write_bytes(alert(1))
        with closing(open_database(self.database)) as db:
            reader = EveReader(db, self.eve)
            with closing(reader.batches(follow=True)) as batches:
                self.assertEqual(next(batches), (1, 0))
                old = self.eve.with_name("eve.json.1")
                self.eve.rename(old)
                self.eve.write_bytes(alert(3))
                with old.open("ab") as stream:
                    stream.write(alert(2) + b'{"unfinished"')
                with patch("suricata_eve.time.sleep", side_effect=AssertionError("Unexpected wait")):
                    self.assertEqual(next(batches), (1, 0))
                    self.assertEqual(next(batches), (1, 0))
        self.assertEqual([row["timestamp"][-7:-5] for row in self.rows()], ["01", "02", "03"])

    def test_follow_ctrl_c_keeps_checkpoint(self):
        self.eve.write_bytes(alert(1))
        command = [sys.executable, str(CLI), "--db", str(self.database)]
        with subprocess.Popen([*command, "follow", str(self.eve)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and process.poll() is None:
                    try:
                        with closing(sqlite3.connect(self.database)) as db:
                            if db.execute("SELECT COUNT(*) FROM suricata_alerts").fetchone()[0] == 1:
                                break
                    except sqlite3.OperationalError:
                        pass
                    time.sleep(0.02)
                else:
                    self.fail("Follow did not commit the alert")
                process.send_signal(signal.SIGINT)
                output, errors = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, errors)
                self.assertEqual(json.loads(output), {"inserted": 1, "rejected": 0})
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        self.assertEqual(self.import_once(), [])
        summary = json.loads(subprocess.check_output([*command, "summary"]))
        self.assertEqual(summary["alerts"], 1)
        listed = json.loads(subprocess.check_output([*command, "list"]))
        self.assertEqual(listed[0]["signature_id"], 1000001)


if __name__ == "__main__":
    unittest.main()
