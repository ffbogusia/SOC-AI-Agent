import os
import sqlite3
from collections import defaultdict, Counter
from datetime import datetime
import json
import pandas as pd
from langchain_ollama import ChatOllama
from incident_triage import (
    DB_FILE,
    DEFAULT_MIN_ATTEMPTS,
    DEFAULT_WINDOW_SECONDS,
    find_cases,
    parse_timestamp,
    read_log,
    save_cases,
)


# =========================
# LLM (Ollama)
# =========================
model = ChatOllama(model="llama3.1", temperature=0)

# =========================
# DATABASE SETUP
# =========================
def init_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip TEXT,
        method TEXT,
        url TEXT,
        status INTEGER,
        user_agent TEXT,
        event_type TEXT,
        severity TEXT
    )''')
    conn.commit()
    conn.close()

def store_event(timestamp, ip, method, url, status, user_agent, event_type, severity):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''INSERT INTO events 
                 (timestamp, ip, method, url, status, user_agent, event_type, severity)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (timestamp, ip, method, url, status, user_agent, event_type, severity))
    conn.commit()
    conn.close()

# =========================
# MITRE mapping (deterministyczny)
# =========================
MITRE_MAP = {
    "SQLI": {
        "technique": "T1190",
        "tactic": "TA0001",
        "name": "Exploit Public-Facing Application",
        "severity": "WYSOKIE"
    },
    "LOG4SHELL": {
        "technique": "T1190",
        "tactic": "TA0001",
        "name": "Exploit Public-Facing Application",
        "severity": "KRYTYCZNE"
    },
    "SCAN": {
        "technique": "T1595.002",
        "tactic": "TA0043",
        "name": "Active Scanning",
        "severity": "ŚREDNIE"
    },
    "BRUTE_FORCE": {
        "technique": "T1110.001",
        "tactic": "TA0006",
        "name": "Password Guessing",
        "severity": "WYSOKIE"
    }
}


# =========================
# DETECTION ENGINE
# =========================
def detect_events(ip, method, url, status, user_agent):
    events = []

    u = url.lower()
    ua = user_agent.lower()

    # SQLi - multiple patterns
    sqli_patterns = [
        "or%201=1", "or 1=1", "union select", "1' or '1'='1",
        "admin' --", "' or 1=1 --", "%27 or %271%27=%271"
    ]
    if any(pattern in u for pattern in sqli_patterns):
        events.append("SQLI")

    # Log4Shell - JNDI Injection patterns
    if "${jndi:" in ua or "${jndi:" in u:
        events.append("LOG4SHELL")

    # Scanning - suspicious paths
    scanning_paths = ["/.env", "/etc/passwd", "/config.php", "/wp-admin", 
                      "/.git", "/.aws", "/backup", "/admin"]
    if any(path in u for path in scanning_paths):
        events.append("SCAN")

    # Scanner user agents
    scanner_patterns = ["nmap", "dirbuster", "sqlmap", "masscan", 
                        "nikto", "metasploit", "curl/", "python-requests"]
    if any(pattern in ua for pattern in scanner_patterns):
        if method not in ["GET"] or status in ["404", "403"]:
            events.append("SCAN")

    return events


# =========================
# LOG PARSER
# =========================
def parse_logs(file_path, min_attempts=DEFAULT_MIN_ATTEMPTS,
               window_seconds=DEFAULT_WINDOW_SECONDS):
    if not os.path.exists(file_path):
        return {"error": "File not found"}

    source_records = list(read_log(file_path))
    cases = find_cases(file_path, source_records, min_attempts, window_seconds)
    if cases:
        save_cases(DB_FILE, cases)
    brute_force_lines = {item["line"] for case in cases for item in case["evidence"]}

    records = []
    for number, record in source_records:
        events = detect_events(
            record["ip"], record["method"], record["url"], record["status"], record["ua"]
        )
        if number in brute_force_lines:
            events.append("BRUTE_FORCE")

        if events:
            severity = max(
                (MITRE_MAP[event]["severity"] for event in events),
                key=("ŚREDNIE", "WYSOKIE", "KRYTYCZNE").index,
            )
            record["events"] = events
            record["status"] = int(record["status"])
            record["severity"] = severity
            records.append(record)

            for event in events:
                store_event(
                    record["time"], record["ip"], record["method"], record["url"],
                    record["status"], record["ua"], event, severity,
                )

    if not records:
        return {"error": "No suspicious activity detected"}

    df = pd.DataFrame(records)
    return df


# =========================
# ANALYSIS LAYER
# =========================
def build_attack_map(df):
    attack_map = defaultdict(list)

    for _, row in df.iterrows():
        for event in row["events"]:
            attack_map[row["ip"]].append({
                "event": event,
                "time": row["time"],
                "url": row["url"],
                "method": row["method"],
                "status": row["status"]
            })

    summary = {}

    for ip, events_list in attack_map.items():
        event_types = [e["event"] for e in events_list]
        counter = Counter(event_types)

        summary[ip] = {
            "total_events": len(events_list),
            "event_types": dict(counter),
            "events_detail": events_list,
            "first_seen": events_list[0]["time"],
            "last_seen": events_list[-1]["time"] if len(events_list) > 0 else events_list[0]["time"]
        }

    return summary


def determine_severity(summary):
    severity_score = 0
    max_severity = "NISKIE"

    for ip, data in summary.items():
        for event_type in data["event_types"]:
            if event_type in MITRE_MAP:
                sev = MITRE_MAP[event_type]["severity"]
                if sev == "KRYTYCZNE":
                    severity_score += 100
                    max_severity = "KRYTYCZNE"
                elif sev == "WYSOKIE":
                    severity_score += 50
                    if max_severity != "KRYTYCZNE":
                        max_severity = "WYSOKIE"
                elif sev == "ŚREDNIE":
                    severity_score += 20
                    if max_severity not in ["KRYTYCZNE", "WYSOKIE"]:
                        max_severity = "ŚREDNIE"

    return max_severity, severity_score


def build_mitre(summary):
    mitre = []
    techniques_set = set()

    for ip, data in summary.items():
        for event_type in data["event_types"]:
            if event_type in MITRE_MAP:
                m = MITRE_MAP[event_type]
                technique_key = f"{m['technique']}_{m['tactic']}"
                if technique_key not in techniques_set:
                    techniques_set.add(technique_key)
                    mitre.append(
                        f"[{m['technique']}] {m['tactic']} - {m['name']}"
                    )

    return "\n".join(mitre)


def get_attack_timeline(summary):
    timeline = []
    for ip, data in summary.items():
        for event in data["events_detail"]:
            timeline.append({
                "time": event["time"],
                "ip": ip,
                "attack_type": event["event"],
                "url": event["url"],
                "status": event["status"]
            })
    
    # Sort by time
    timeline.sort(key=lambda x: parse_timestamp(x["time"]))
    return timeline


def get_statistics(df, summary):
    stats = {
        "total_suspicious_events": len(df),
        "unique_attacking_ips": len(summary),
        "event_distribution": {},
        "most_targeted_endpoint": None,
        "attack_pattern": None
    }

    # Event distribution
    all_events = []
    for data in summary.values():
        all_events.extend(data["event_types"].keys())
    
    event_counter = Counter(all_events)
    stats["event_distribution"] = dict(event_counter)

    # Most targeted endpoint
    urls = []
    for data in summary.values():
        for event in data["events_detail"]:
            urls.append(event["url"])
    
    if urls:
        url_counter = Counter(urls)
        stats["most_targeted_endpoint"] = url_counter.most_common(1)[0][0]

    # Attack pattern
    if "BRUTE_FORCE" in stats["event_distribution"]:
        stats["attack_pattern"] = "COORDINATED_BRUTE_FORCE"
    elif "LOG4SHELL" in stats["event_distribution"]:
        stats["attack_pattern"] = "CRITICAL_EXPLOITATION_ATTEMPT"
    elif "SQLI" in stats["event_distribution"]:
        stats["attack_pattern"] = "SQL_INJECTION_CAMPAIGN"
    elif "SCAN" in stats["event_distribution"]:
        stats["attack_pattern"] = "RECONNAISSANCE"

    return stats


# =========================
# REPORT GENERATION (LLM)
# =========================
def generate_report(severity, severity_score, summary, stats, mitre_text, timeline):
    # Build summary string safely
    summary_str = json.dumps({k: {**v, "events_detail": [str(e) for e in v["events_detail"]]} 
                              for k, v in summary.items()}, indent=2)
    
    timeline_str = "\n".join([
        f"[{t['time']}] {t['ip']} - {t['attack_type']}: {t['url']} (Status: {t['status']})"
        for t in timeline[:20]
    ])

    prompt_text = f"""You are an experienced SOC L3 analyst with 10 years of experience creating professional incident reports for C-level management and IT teams.

=== INCIDENT DATA ===

SEVERITY LEVEL: {severity} (Score: {severity_score}/100)
REPORT GENERATED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

STATISTICS:
- Total Suspicious Events: {stats['total_suspicious_events']}
- Unique Attacking IPs: {stats['unique_attacking_ips']}
- Attack Pattern: {stats['attack_pattern']}
- Most Targeted Endpoint: {stats['most_targeted_endpoint']}

EVENT DISTRIBUTION:
{json.dumps(stats['event_distribution'], indent=2)}

ATTACKING IPs & ACTIVITY:
{summary_str}

ATTACK TIMELINE (First 20 Events):
{timeline_str}

MITRE ATT&CK MAPPING:
{mitre_text}

=== TASK ===

Generate a professional SOC incident report with these sections:

1. EXECUTIVE SUMMARY
   - Concise threat description
   - Impact assessment
   - Recommended immediate action

2. TECHNICAL ANALYSIS
   - Attack vectors used
   - Compromised/targeted systems
   - Attack flow timeline

3. INDICATORS OF COMPROMISE (IOCs)
   - Malicious IPs
   - Suspicious URLs/endpoints
   - Attack signatures detected

4. MITRE ATT&CK FRAMEWORK
   - Techniques identified
   - Tactics employed by attacker

5. THREAT INTELLIGENCE
   - Attack sophistication level
   - Likely attacker profile
   - Any attribution if possible

6. RECOMMENDATIONS (PRIORITIZED)
   - Immediate remediation steps
   - Long-term security improvements
   - Detection/prevention rules to implement

7. APPENDIX
   - Full event timeline
   - Detailed IOCs reference

Important: Do NOT make up any information. Use ONLY the provided data. Be technical but clear for both technical and non-technical audiences."""

    from langchain_core.messages import HumanMessage, SystemMessage
    
    messages = [
        SystemMessage(content="You are an experienced SOC L3 analyst. Create professional incident reports using only the provided data. Do not make up information."),
        HumanMessage(content=prompt_text)
    ]
    
    response = model.invoke(messages)
    return response.content


# =========================
# PIPELINE
# =========================
def run(log_file, min_attempts=DEFAULT_MIN_ATTEMPTS,
        window_seconds=DEFAULT_WINDOW_SECONDS):
    init_database()
    
    print("\n" + "="*60)
    print("SOC INCIDENT REPORT GENERATOR")
    print("="*60)
    
    print("\n[1/6] Parsing server logs...")
    df = parse_logs(log_file, min_attempts, window_seconds)

    if isinstance(df, dict) and "error" in df:
        print(f"❌ Error: {df['error']}")
        return df["error"]

    print(f"     ✓ Found {len(df)} suspicious events")

    print("\n[2/6] Building attack map...")
    summary = build_attack_map(df)
    print(f"     ✓ Identified {len(summary)} attacking IPs")

    print("\n[3/6] Calculating statistics...")
    stats = get_statistics(df, summary)
    print(f"     ✓ Attack pattern: {stats['attack_pattern']}")

    print("\n[4/6] Assessing severity...")
    severity, severity_score = determine_severity(summary)
    print(f"     ✓ Severity: {severity} (Score: {severity_score}/100)")

    print("\n[5/6] Mapping MITRE ATT&CK framework...")
    mitre_text = build_mitre(summary)
    print(f"     ✓ Techniques identified")

    print("\n[6/6] Generating LLM-enhanced report...")
    timeline = get_attack_timeline(summary)
    report = generate_report(severity, severity_score, summary, stats, mitre_text, timeline)

    # Save report
    report_file = f"SOC_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("="*80 + "\n")
        f.write("SECURITY OPERATIONS CENTER - INCIDENT REPORT\n")
        f.write("="*80 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Severity: {severity}\n")
        f.write(f"Events Analyzed: {len(df)}\n")
        f.write("="*80 + "\n\n")
        f.write(report)
        f.write("\n\n" + "="*80 + "\n")
        f.write("DATABASE LOCATION: " + os.path.abspath(DB_FILE) + "\n")
        f.write("="*80 + "\n")

    print(f"\n✅ Report saved: {report_file}")
    print(f"📊 Events stored in database: {DB_FILE}")
    print("="*60 + "\n")
    
    return report


# =========================
# DATABASE QUERY UTILITIES
# =========================
def list_events_by_ip(ip=None):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    if ip:
        c.execute("SELECT * FROM events WHERE ip = ? ORDER BY timestamp", (ip,))
    else:
        c.execute("SELECT * FROM events ORDER BY timestamp")
    
    rows = c.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def get_events_by_type(event_type):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM events WHERE event_type = ? ORDER BY timestamp", (event_type,))
    rows = c.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def get_critical_events():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM events WHERE severity = 'KRYTYCZNE' ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate a SOC incident report")
    parser.add_argument("log_file", nargs="?", default="server.log")
    parser.add_argument("--min-attempts", type=int, default=DEFAULT_MIN_ATTEMPTS)
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    args = parser.parse_args()
    if not os.path.exists(args.log_file):
        parser.error(f"{args.log_file} not found")
    if args.min_attempts < 2 or args.window_seconds < 1:
        parser.error("Use at least 2 attempts and a positive window in seconds.")

    report = run(args.log_file, args.min_attempts, args.window_seconds)
    lines = report.splitlines()
    print("\n--- REPORT PREVIEW ---")
    print("\n".join(lines[:100]))
    if len(lines) > 100:
        print("\n... (see full report in output file)")
