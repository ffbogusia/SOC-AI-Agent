"""Run an isolated Suricata demo on loopback or a generated PCAP."""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time


DEMO = Path(__file__).resolve().parent
ADAPTER = DEMO.parent / "suricata_eve.py"
MARKER = b"SOC-AI-SURICATA-DEMO-2026"
SIGNATURE_ID = 1000001
SIGNATURE = "SOC demo benign UDP marker"
PAYLOADS = (b"ordinary demo traffic", MARKER)


def packet(payload):
    address = socket.inet_aton("127.0.0.1")
    udp = struct.pack("!HHHH", 41233, 41234, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     address, address)
    total = sum(struct.unpack("!10H", ip))
    total = (total & 0xFFFF) + (total >> 16)
    checksum = (~((total & 0xFFFF) + (total >> 16))) & 0xFFFF
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip[:10] + struct.pack("!H", checksum) + ip[12:] + udp


def create_capture(path):
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        second = int(time.time())
        for index, payload in enumerate(PAYLOADS):
            frame = packet(payload)
            output.write(struct.pack("<IIII", second, index * 1000, len(frame), len(frame)))
            output.write(frame)


def live_available():
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture:
            capture.bind(("lo", 0))
    except OSError as error:
        print(f"Loopback capture unavailable ({error}). Using offline PCAP.", flush=True)
        return False
    return True


def live_capture(base, workdir):
    log = workdir / "sensor.log"
    eve = workdir / "eve.json"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender, \
         log.open("wb") as output:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(2)
        port = receiver.getsockname()[1]
        filter_path = workdir / "capture.bpf"
        filter_path.write_text(f"udp and dst host 127.0.0.1 and dst port {port}\n")
        with subprocess.Popen([*base, "-i", "lo", "-F", str(filter_path)],
                              stdout=output, stderr=subprocess.STDOUT) as sensor:
            try:
                deadline = time.monotonic() + 15
                while "engine started" not in log.read_text(errors="replace").lower():
                    if sensor.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("Suricata did not start loopback capture")
                    time.sleep(0.1)
                for payload in PAYLOADS:
                    sender.sendto(payload, receiver.getsockname())
                    if receiver.recv(65535) != payload:
                        raise RuntimeError("Unexpected loopback datagram")
                deadline = time.monotonic() + 5
                while not eve.exists() or SIGNATURE not in eve.read_text(errors="replace"):
                    if sensor.poll() is not None or time.monotonic() >= deadline:
                        break
                    time.sleep(0.1)
            finally:
                if sensor.poll() is None:
                    sensor.send_signal(signal.SIGINT)
                    try:
                        sensor.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        sensor.kill()
                        sensor.wait()
                        raise RuntimeError("Suricata did not stop cleanly") from None
            if sensor.returncode:
                raise RuntimeError(f"Suricata exited with status {sensor.returncode}")


def verify_alerts(workdir, mode):
    eve = workdir / "eve.json"
    expected = []
    for line in eve.read_text().splitlines():
        event = json.loads(line)
        if event["event_type"] == "alert":
            alert = event["alert"]
            if (alert["signature_id"], alert["signature"]) != (SIGNATURE_ID, SIGNATURE):
                raise RuntimeError(f"Unexpected signature: {alert}")
            expected.append(event)
    if not expected or (mode == "pcap" and len(expected) != 1):
        raise RuntimeError(f"Unexpected count for the demo signature: {len(expected)}")

    database = workdir / "alerts.sqlite3"
    cli = [sys.executable, str(ADAPTER), "--db", str(database)]
    ingest = [*cli, "import", str(eve)]
    first = json.loads(subprocess.check_output(ingest))
    second = json.loads(subprocess.check_output(ingest))
    if first != {"inserted": len(expected), "rejected": 0} or second != {
        "inserted": 0, "rejected": 0
    }:
        raise RuntimeError(f"Unexpected adapter counters: {first}, {second}")
    with sqlite3.connect(database) as db:
        stored = db.execute("""
            SELECT signature_id, signature, severity, timestamp, src_ip, src_port,
                   dest_ip, dest_port, source
            FROM suricata_alerts ORDER BY id
        """).fetchall()
    wanted = [
        (SIGNATURE_ID, SIGNATURE, event["alert"]["severity"], event["timestamp"],
         event["src_ip"], event.get("src_port"), event["dest_ip"], event.get("dest_port"),
         str(eve))
        for event in expected
    ]
    if stored != wanted:
        raise RuntimeError(f"SQLite contents differ from EVE: {stored}")
    summary = json.loads(subprocess.check_output([*cli, "summary"]))
    if summary["alerts"] != len(wanted):
        raise RuntimeError(f"Unexpected CLI summary: {summary}")
    print(f"Mode: {mode}. EVE alerts: {len(expected)}. SQLite alerts: {len(stored)}. "
          f"New rows on reimport: {second['inserted']}.")
    print(json.dumps(summary, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suricata", default=os.environ.get("SURICATA_BIN", "suricata"))
    parser.add_argument("--mode", choices=("auto", "live", "pcap"), default="auto")
    args = parser.parse_args()
    mode = args.mode
    if mode == "auto":
        mode = "live" if live_available() else "pcap"
    try:
        subprocess.run([args.suricata, "-V"], check=True)
        with tempfile.TemporaryDirectory(prefix="soc-suricata-") as temporary:
            workdir = Path(temporary)
            base = [args.suricata, "-c", str(DEMO / "suricata.yaml"),
                    "-S", str(DEMO / "local.rules"), "-l", str(workdir),
                    "--set", "unix-command.enabled=no"]
            try:
                if mode == "live":
                    live_capture(base, workdir)
                else:
                    capture = workdir / "traffic.pcap"
                    create_capture(capture)
                    subprocess.run([*base, "-r", str(capture)], check=True, timeout=30)
                verify_alerts(workdir, mode)
            except (OSError, RuntimeError, subprocess.SubprocessError, ValueError):
                log = workdir / "sensor.log"
                if log.exists():
                    print(log.read_text(errors="replace"), file=sys.stderr)
                raise
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        parser.exit(1, f"Demo failed ({mode}): {error}\n")


if __name__ == "__main__":
    main()
