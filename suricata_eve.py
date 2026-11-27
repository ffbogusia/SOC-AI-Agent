"""Import Suricata EVE JSON alerts into SQLite."""

import argparse
from contextlib import closing
from datetime import datetime
import hashlib
import ipaddress
import json
import os
import sqlite3
import time


SCHEMA = """
CREATE TABLE IF NOT EXISTS suricata_alerts (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    source_offset INTEGER NOT NULL,
    event_hash TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    signature_id INTEGER NOT NULL,
    signature TEXT NOT NULL,
    severity INTEGER NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER,
    eve_json TEXT NOT NULL,
    UNIQUE (source, event_hash)
);
CREATE TABLE IF NOT EXISTS suricata_checkpoints (
    source TEXT PRIMARY KEY,
    device INTEGER NOT NULL,
    inode INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    anchor BLOB NOT NULL
);
"""

BATCH_SIZE = 256


def open_database(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    return db


def alert_values(line):
    event = json.loads(line.decode("utf-8"))
    if not isinstance(event, dict) or not isinstance(event.get("event_type"), str):
        raise ValueError("missing EVE event type")
    if event["event_type"] != "alert":
        return None

    alert = event["alert"]
    timestamp = event["timestamp"]
    if datetime.fromisoformat(timestamp).utcoffset() is None:
        raise ValueError("missing timestamp offset")
    signature = alert["signature"]
    signature_id = alert["signature_id"]
    severity = alert["severity"]
    if not isinstance(signature, str) or not signature:
        raise ValueError("invalid signature")
    signature.encode("utf-8")
    if any(type(value) is not int or not 0 <= value <= 2**63 - 1
           for value in (signature_id, severity)):
        raise ValueError("invalid signature ID or severity")
    ports = (event.get("src_port"), event.get("dest_port"))
    if any(value is not None and (type(value) is not int or not 0 <= value <= 65535)
           for value in ports):
        raise ValueError("invalid port")
    if not all(isinstance(event[key], str) for key in ("src_ip", "dest_ip")):
        raise ValueError("invalid IP address")
    src_ip = str(ipaddress.ip_address(event["src_ip"]))
    dest_ip = str(ipaddress.ip_address(event["dest_ip"]))
    payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return (hashlib.sha256(payload.encode()).hexdigest(), timestamp, signature_id, signature, severity,
            src_ip, ports[0], dest_ip, ports[1], payload)


class EveReader:
    """Read complete records and commit them together with their byte cursor."""

    def __init__(self, db, source, poll_interval=0.25):
        self.db = db
        self.source = os.path.abspath(source)
        self.poll_interval = poll_interval

    @staticmethod
    def matches_cursor(stream, offset, anchor):
        stream.seek(0, 2)
        if stream.tell() < offset:
            return False
        if not anchor:
            return True
        # The cursor fingerprints the whole last line, including its timestamp.
        line_size = int.from_bytes(anchor[:8], "big")
        stream.seek(offset - line_size)
        return hashlib.sha256(stream.read(line_size)).digest() == anchor[8:]

    def read_batch(self, stream, identity, offset, anchor):
        stream.seek(offset)
        count = 0
        rows = []
        rejected = 0
        while count < BATCH_SIZE:
            start = offset
            line = stream.readline()
            if not line.endswith(b"\n"):
                break
            offset = stream.tell()
            last_line = line
            count += 1
            try:
                values = alert_values(line)
            except (ValueError, KeyError, TypeError, RecursionError):
                rejected += 1
                continue
            if values is not None:
                rows.append((self.source, start, *values))
        if not count:
            return count, 0, rejected, offset, anchor
        anchor = len(last_line).to_bytes(8, "big") + hashlib.sha256(last_line).digest()
        with self.db:
            inserted = self.db.executemany("""
                INSERT INTO suricata_alerts (
                    source, source_offset, event_hash, timestamp, signature_id,
                    signature, severity, src_ip, src_port, dest_ip, dest_port, eve_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source, event_hash) DO NOTHING
            """, rows).rowcount
            self.db.execute("""
                INSERT INTO suricata_checkpoints VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    device = excluded.device, inode = excluded.inode,
                    offset = excluded.offset, anchor = excluded.anchor
            """, (self.source, *identity, offset, anchor))
        return count, inserted, rejected, offset, anchor

    def batches(self, follow=False):
        while True:
            try:
                stream = open(self.source, "rb")
            except FileNotFoundError:
                if not follow:
                    raise
                time.sleep(self.poll_interval)
                continue
            with stream:
                stat = os.fstat(stream.fileno())
                identity = (stat.st_dev, stat.st_ino)
                cursor = self.db.execute("""
                    SELECT device, inode, offset, anchor FROM suricata_checkpoints WHERE source = ?
                """, (self.source,)).fetchone()
                offset, anchor = 0, b""
                if cursor and (cursor["device"], cursor["inode"]) == identity:
                    offset, anchor = cursor["offset"], cursor["anchor"]

                while True:
                    if not self.matches_cursor(stream, offset, anchor):
                        offset, anchor = 0, b""
                    count, inserted, rejected, offset, anchor = self.read_batch(
                        stream, identity, offset, anchor
                    )
                    if count:
                        yield inserted, rejected
                        continue
                    if not follow:
                        return
                    try:
                        current = os.stat(self.source)
                    except FileNotFoundError:
                        current = None
                    if current and (current.st_dev, current.st_ino) != identity:
                        break
                    time.sleep(self.poll_interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="suricata_alerts.sqlite3", help="SQLite database path")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("import", "follow"):
        commands.add_parser(command).add_argument("eve_json")
    commands.add_parser("list")
    commands.add_parser("summary")
    args = parser.parse_args()
    try:
        with closing(open_database(args.db)) as db:
            if args.command in ("import", "follow"):
                inserted = rejected = 0
                with closing(EveReader(db, args.eve_json).batches(args.command == "follow")) as batches:
                    try:
                        for added, skipped in batches:
                            inserted += added
                            rejected += skipped
                    except KeyboardInterrupt:
                        if args.command != "follow":
                            raise
                print(json.dumps({"inserted": inserted, "rejected": rejected}))
            elif args.command == "list":
                rows = db.execute("""
                    SELECT id, timestamp, signature_id, signature, severity, src_ip,
                           src_port, dest_ip, dest_port, source, source_offset
                    FROM suricata_alerts ORDER BY id
                """)
                print(json.dumps([dict(row) for row in rows], indent=2))
            else:
                rows = db.execute("""
                    SELECT signature_id, signature, severity, COUNT(*) AS alerts
                    FROM suricata_alerts GROUP BY signature_id, signature, severity
                    ORDER BY alerts DESC, signature_id, signature, severity
                """)
                groups = [dict(row) for row in rows]
                print(json.dumps({"alerts": sum(row["alerts"] for row in groups),
                                  "by_signature": groups}, indent=2))
    except (OSError, sqlite3.Error) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
