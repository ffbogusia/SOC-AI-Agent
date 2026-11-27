# SOC Report Generator - AI Security Agent

A professional Security Operations Center (SOC) incident report generator that analyzes server logs, detects attacks, and generates comprehensive security reports with LLM-powered insights.

## Features

✅ **Advanced Log Parsing** - Detects multiple attack patterns:
- SQL Injection (SQLi)
- Log4Shell/JNDI Injection
- Brute Force attacks
- Active Scanning/Reconnaissance

✅ **SQLite Database** - Stores all detected events for:
- Historical analysis
- Compliance tracking
- Forensic investigation

✅ **MITRE ATT&CK Mapping** - Automatically maps detected techniques to MITRE framework:
- Tactics and techniques
- Kill chain analysis
- Threat intelligence

✅ **Professional Reports** - LLM-generated SOC reports include:
- Executive Summary
- Technical Analysis
- Indicators of Compromise (IOCs)
- MITRE ATT&CK Framework mapping
- Threat Intelligence assessment
- Prioritized Recommendations
- Full Timeline & Appendix

✅ **Severity Scoring** - Intelligent risk assessment:
- KRYTYCZNE (Critical)
- WYSOKIE (High)
- ŚREDNIE (Medium)
- NISKIE (Low)

## Architecture

```
loggenerator.py  →  server.log  →  agent.py  →  SOC_REPORT_*.txt
                                       ↓
                                  soc_events.db
                                       ↑
                                 query_database.py
```

## Setup

### 1. Create Virtual Environment
```bash
python -m venv venv
```

### 2. Activate Virtual Environment

**Windows:**
```bash
.\venv\Scripts\activate
```

**Linux/Mac:**
```bash
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

**Required packages:**
- pandas
- langchain
- langchain-ollama
- tabulate

### 4. Start Ollama LLM (if not running)

The optional SOC report workflow requires a local Ollama instance with the llama3.1 model. Incident Triage uses Python's standard library and SQLite.

```bash
ollama run llama3.1
```

Default connection: `http://localhost:11434`

## Usage

### Generate Server Logs with Simulated Attacks

```bash
python loggenerator.py
```

This generates `server.log` with:
- 85% legitimate traffic
- 5% Brute force attempts
- 5% SQL Injection / Log4Shell attempts
- 5% Scanning/Reconnaissance

You can customize:
```python
generate_realistic_logs(output_file="server.log", num_lines=500)  # More events
```

### Run SOC Report Generator

```bash
python agent.py server.log
```

Or with a custom log file:
```bash
python agent.py /path/to/custom/access.log
```

### Incident Triage without Ollama

Run the following from the repository root in Bash. The example writes a small
access log and database to a temporary directory.

```bash
demo="$(mktemp -d)"
for second in {0..9}; do
    printf '192.0.2.10 - - [11/Jun/2026:12:00:%02d +0200] "POST /admin/login HTTP/1.1" 401 0 "-" "Browser"\n' "$second"
done > "$demo/access.log"

python incident_triage.py --db "$demo/triage.sqlite3" scan "$demo/access.log"
python incident_triage.py --db "$demo/triage.sqlite3" list
case_id="$(python incident_triage.py --db "$demo/triage.sqlite3" list | python -c 'import json, sys; print(json.load(sys.stdin)[0]["id"])')"
python incident_triage.py --db "$demo/triage.sqlite3" set-status "$case_id" investigating --comment "Compare with authentication logs"
python incident_triage.py --db "$demo/triage.sqlite3" scan "$demo/access.log"
python incident_triage.py --db "$demo/triage.sqlite3" list
```

The first listing shows one case with status `new` and 10 attempts. The final
listing shows the same case ID, status `investigating` and the saved comment.
Each case includes its source path, IP, endpoint, UTC start and end, rationale,
and evidence with one-based source line numbers, UTC timestamps and HTTP statuses.
Supported statuses are `new`, `investigating`, `confirmed_threat`,
`false_positive` and `authorized_test`. Each update stores the latest comment.

```bash
python incident_triage.py scan /path/to/access.log --min-attempts 12 --window-seconds 240
python incident_triage.py list
```

Omitting `--db` uses `soc_events.db` in the current directory, including cases
created by `agent.py`. The report CLI accepts the same threshold options.
Running the standalone scan stores cases only. Case identity uses the resolved
source path and the case's evidence. Re-reading the same file with the same
settings preserves cases and review status. Changes to the file, its path, or
thresholds can yield another case if the source or evidence changes. This
version analyzes each file independently and keeps a single status and comment
per case.

To run the tests, install the report test dependencies in your virtual
environment and run:

```bash
python -m pip install pandas langchain-ollama tabulate
python -m unittest -v
```

The tests cover the offline triage CLI and exercise the report pipeline with a
test double. A real-model reporting check is an optional integration test.

### Query Stored Events

```bash
# Show all suspicious events
python query_database.py all

# Show critical severity events only
python query_database.py critical

# Show events from specific IP
python query_database.py ip 185.220.101.5

# Show events of specific attack type
python query_database.py type SQLI          # or LOG4SHELL, SCAN, BRUTE_FORCE

# Show database statistics
python query_database.py stats
```

## Output Files

### Generated Reports
- `SOC_REPORT_YYYYMMDD_HHMMSS.txt` - Professional incident report with all analysis

### Database
- `soc_events.db` - SQLite database with all detected events and metadata

### Logs
- `server.log` - Raw HTTP access log with simulated attacks

## Attack Detection Rules

### SQL Injection Detection
Patterns: `OR 1=1`, `UNION SELECT`, `' or '1'='1'`, Admin bypass attempts

### Log4Shell Detection
Pattern: `${jndi:` in User-Agent or URL (JNDI Injection)

### Brute Force Detection
The default heuristic marks at least 10 HTTP 401/403 responses from one IP
to the same login path within an inclusive 300-second window. Supported paths
are `/admin/login` and `/admin/login.php`. Query strings are ignored for grouping.
Overlapping qualifying windows form one case. Numeric timezone offsets are
normalized to UTC before sorting, so input rows can be out of order. The rule
indicates suspicious activity for review. HTTP 200 is ignored by the rule and
provides no confirmation of successful authentication.

### Scanning Detection
Patterns:
- Suspicious tool User-Agents (Nmap, Dirbuster, Nikto, SQLMap)
- Suspicious paths (/.env, /.git, /config.php, /etc/passwd, /wp-admin)
- 404/403 responses to reconnaissance attempts

## Report Sections

1. **EXECUTIVE SUMMARY**
   - Threat description
   - Impact assessment
   - Immediate actions

2. **TECHNICAL ANALYSIS**
   - Attack vectors
   - Targeted systems
   - Attack timeline

3. **INDICATORS OF COMPROMISE (IOCs)**
   - Malicious IP addresses
   - Suspicious endpoints
   - Attack signatures

4. **MITRE ATT&CK FRAMEWORK**
   - Technique IDs
   - Tactic mapping
   - Kill chain analysis

5. **THREAT INTELLIGENCE**
   - Sophistication level
   - Attacker profile
   - Attribution analysis

6. **RECOMMENDATIONS**
   - Immediate remediation
   - Long-term improvements
   - Detection rules

7. **APPENDIX**
   - Full event timeline
   - Detailed IOC reference

## Severity Scoring

- **KRYTYCZNE (Critical)**: 100+ points
  - Log4Shell detected
  - Multiple high-severity attacks

- **WYSOKIE (High)**: 50-99 points
  - SQL Injection attempts
  - Coordinated brute force

- **ŚREDNIE (Medium)**: 20-49 points
  - Active scanning
  - Single attack type

- **NISKIE (Low)**: <20 points
  - Isolated reconnaissance

## MITRE ATT&CK Techniques

| Attack Type | Technique | Tactic | Code |
|-------------|-----------|--------|------|
| SQL Injection | Exploit Public-Facing Application | Initial Access | T1190 |
| Log4Shell | Exploit Public-Facing Application | Initial Access | T1190 |
| Brute Force | Password Guessing | Credential Access | T1110.001 |
| Scanning | Active Scanning | Reconnaissance | T1595.002 |

## Database Schema

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    ip TEXT,
    method TEXT,
    url TEXT,
    status INTEGER,
    user_agent TEXT,
    event_type TEXT,
    severity TEXT
);
```

## Example: Full Workflow

```bash
# 1. Activate environment
.\venv\Scripts\activate

# 2. Generate attack simulation logs
python loggenerator.py

# 3. Generate comprehensive SOC report
python agent.py server.log

# 4. Query specific threats
python query_database.py critical
python query_database.py ip 91.240.118.44

# 5. View generated report
type SOC_REPORT_*.txt
```

## Configuration

### Modify Attack Patterns (in agent.py)

Edit `MITRE_MAP` dictionary to adjust severity scores:
```python
"LOG4SHELL": {
    "technique": "T1190",
    "tactic": "TA0001",
    "name": "Exploit Public-Facing Application",
    "severity": "KRYTYCZNE"  # CRITICAL - highest severity
}
```

### Modify Log Generation (in loggenerator.py)

Adjust attack distribution:
```python
if rand_type < 0.85:  # 85% legitimate
    # Normal traffic
elif rand_type < 0.90:  # 5% brute force
    # Brute force
elif rand_type < 0.95:  # 5% exploits
    # SQL Injection / Log4Shell
else:  # 5% scanning
    # Active scanning
```

## Troubleshooting

### "Ollama connection refused"
Ensure Ollama is running:
```bash
ollama run llama3.1
```

### "File not found: server.log"
Generate logs first:
```bash
python loggenerator.py
```

### "No suspicious activity detected"
Increase log generation volume:
```python
generate_realistic_logs(output_file="server.log", num_lines=1000)
```

### Database locked error
Close all other database connections and try again

## Performance Notes

- **Logs**: Processes 1000 events in ~2 seconds
- **Report Generation**: 30-60 seconds (depends on LLM response time)
- **Database**: SQLite suitable for <1M events

## Security Considerations

⚠️ **This is a demo/educational tool** - For production use:
- Use professional SIEM/SOC tools (Splunk, ELK, etc.)
- Implement proper log retention policies
- Deploy WAF/IDS solutions
- Conduct regular penetration testing
- Follow NCSC/NIST guidelines

## Future Enhancements

- [ ] CSV/JSON report export
- [ ] Email alert notifications
- [ ] Web dashboard interface
- [ ] Real-time log streaming
- [ ] Custom rule builder
- [ ] Threat feed integration
- [ ] Machine learning anomaly detection


