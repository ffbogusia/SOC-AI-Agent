"""Detect and review suspicious series of failed admin login requests."""

import argparse
from collections import defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from ipaddress import ip_address
from pathlib import Path
import re
import sqlite3


DB_FILE = "soc_events.db"
DEFAULT_MIN_ATTEMPTS = 10
DEFAULT_WINDOW_SECONDS = 300
STATUSES = ("new", "investigating", "confirmed_threat", "false_positive", "authorized_test")
LOGIN_ENDPOINTS = {"/admin/login", "/admin/login.php"}

LOG_PATTERN = re.compile(
    r'(?P<ip>[\dA-Fa-f:.]+)\s-\s-\s\[(?P<time>.*?)\]\s'
    r'"(?P<method>\w+)\s(?P<url>.*?)\sHTTP/1\.\d"\s'
    r'(?P<status>\d+)\s\d+\s".*?"\s"(?P<ua>.*?)"'
)


def parse_timestamp(value):
    return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)


def read_log(source):
    with open(source, encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            match = LOG_PATTERN.search(line)
            if not match:
                continue
            record = match.groupdict()
            try:
                record["ip"] = str(ip_address(record["ip"]))
                record["timestamp"] = parse_timestamp(record["time"])
            except ValueError:
                continue
            yield number, record


def find_cases(source, records, min_attempts=DEFAULT_MIN_ATTEMPTS,
               window_seconds=DEFAULT_WINDOW_SECONDS):
    if min_attempts < 2 or window_seconds < 1:
        raise ValueError("Use at least 2 attempts and a positive window in seconds.")

    source = str(Path(source).resolve())
    window = timedelta(seconds=window_seconds)
    groups = defaultdict(list)
    for line, record in records:
        endpoint = record["url"].split("?", 1)[0]
        if endpoint not in LOGIN_ENDPOINTS or record["status"] not in ("401", "403"):
            continue
        groups[record["ip"], endpoint].append((record["timestamp"], line, record["status"]))

    cases = []
    for (ip, endpoint), attempts in groups.items():
        attempts.sort()
        ranges = []
        for last in range(min_attempts - 1, len(attempts)):
            first = last - min_attempts + 1
            if attempts[last][0] - attempts[first][0] > window:
                continue
            # Merge qualifying windows only when they share an attempt.
            if ranges and first <= ranges[-1][1]:
                ranges[-1] = (ranges[-1][0], last)
            else:
                ranges.append((first, last))

        for first, last in ranges:
            evidence = [
                {"line": line, "time": timestamp.isoformat(), "status": int(status)}
                for timestamp, line, status in attempts[first:last + 1]
            ]
            identity = json.dumps([source, ip, endpoint, evidence], sort_keys=True)
            cases.append({
                "id": sha256(identity.encode("utf-8")).hexdigest(),
                "source": source,
                "ip": ip,
                "endpoint": endpoint,
                "attempt_count": len(evidence),
                "started_at": evidence[0]["time"],
                "ended_at": evidence[-1]["time"],
                "reason": (
                    f"At least {min_attempts} HTTP 401/403 responses from one IP "
                    f"to this endpoint within {window_seconds} seconds. "
                    "This pattern warrants investigation."
                ),
                "evidence": evidence,
            })
    return cases


def open_database(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS incident_cases (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            ip TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            attempt_count INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            comment TEXT
        )
    """)
    return db


def save_cases(path, cases):
    with closing(open_database(path)) as db, db:
        db.executemany("""
            INSERT INTO incident_cases (
                id, source, ip, endpoint, attempt_count, started_at, ended_at, reason, evidence
            ) VALUES (
                :id, :source, :ip, :endpoint, :attempt_count, :started_at, :ended_at, :reason,
                :evidence
            ) ON CONFLICT(id) DO NOTHING
        """, ({**case, "evidence": json.dumps(case["evidence"])} for case in cases))


def list_cases(path):
    with closing(open_database(path)) as db:
        return [
            {**dict(row), "evidence": json.loads(row["evidence"])}
            for row in db.execute("SELECT * FROM incident_cases ORDER BY started_at, id")
        ]


def update_case(path, case_id, status, comment):
    if status not in STATUSES or not comment.strip():
        raise ValueError("Provide a valid status and a nonempty comment.")
    with closing(open_database(path)) as db, db:
        result = db.execute(
            "UPDATE incident_cases SET status = ?, comment = ? WHERE id = ?",
            (status, comment, case_id),
        )
        if not result.rowcount:
            raise ValueError(f"Unknown case ID: {case_id}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=DB_FILE, help="SQLite database path")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Detect and store cases from an access log")
    scan.add_argument("log_file", type=Path)
    scan.add_argument("--min-attempts", type=int, default=DEFAULT_MIN_ATTEMPTS)
    scan.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    commands.add_parser("list", help="List stored cases as JSON")
    status = commands.add_parser("set-status", help="Update a case status and comment")
    status.add_argument("id")
    status.add_argument("status", choices=STATUSES)
    status.add_argument("--comment", required=True)
    args = parser.parse_args()

    try:
        if args.command == "scan":
            cases = find_cases(
                args.log_file, read_log(args.log_file), args.min_attempts, args.window_seconds
            )
            save_cases(args.db, cases)
            print(f"Cases detected: {len(cases)}")
        elif args.command == "list":
            print(json.dumps(list_cases(args.db), indent=2))
        else:
            update_case(args.db, args.id, args.status, args.comment)
            print(f"Case {args.id} updated to {args.status}.")
    except (OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
