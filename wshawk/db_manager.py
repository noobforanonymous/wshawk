import sqlite3
import json
import uuid
import shlex
from datetime import datetime
from pathlib import Path

# Path to the sqlite database
DB_PATH = Path(__file__).parent / "wshawk.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            elapsed REAL,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            info_count INTEGER,
            findings_json TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def _generate_poc(finding, target):
    """Generate a quick curl or HTML snippet for PoC."""
    finding_type = finding.get("type", "")
    val = finding.get("value", "")
    url = finding.get("url", target)

    if not url:
        url = target

    safe_url = shlex.quote(url)
    
    # CSRF or XSS reflection can be standalone HTML
    if finding_type == "csrf":
        return f'<html><body><form action="{url}" method="POST"><input type="submit" value="Exploit CSRF"></form><script>document.forms[0].submit();</script></body></html>'
    elif "sql" in finding_type.lower() or "xss" in finding_type.lower() or "cmd" in finding_type.lower() or "lfi" in finding_type.lower() or "fuzz" in finding_type.lower():
        safe_val = shlex.quote(val)
        return f"curl -X POST {safe_url} -d {safe_val}"
    else:
        return f"curl -I {safe_url}"

def save_scan(target: str, report: dict) -> str:
    scan_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()
    elapsed = report.get("elapsed", 0.0)
    sev = report.get("severity_counts", {})
    
    findings = report.get("findings", [])
    
    # Inject PoC into each finding
    for f in findings:
        if "poc" not in f:
            f["poc"] = _generate_poc(f, target)
            
    findings_json = json.dumps(findings)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (id, target, timestamp, elapsed, high_count, medium_count, low_count, info_count, findings_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (scan_id, target, timestamp, elapsed, sev.get("High", 0), sev.get("Medium", 0), sev.get("Low", 0), sev.get("Info", 0), findings_json))
    
    conn.commit()
    conn.close()
    return scan_id

def get_all_scans():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT id, target, timestamp, elapsed, high_count, medium_count, low_count, info_count FROM scans ORDER BY timestamp DESC')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan(scan_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["findings"] = json.loads(d.pop("findings_json"))
        return d
    return None

def compare_scans(scan_a_id: str, scan_b_id: str):
    """Compute diff between two historical scans."""
    scan_a = get_scan(scan_a_id)
    scan_b = get_scan(scan_b_id)
    
    if not scan_a or not scan_b:
        return {"error": "Scan not found"}
        
    findings_a = {(f.get("type", ""), f.get("value", ""), f.get("url", "")) for f in scan_a.get("findings", [])}
    findings_b = {(f.get("type", ""), f.get("value", ""), f.get("url", "")) for f in scan_b.get("findings", [])}
    
    fixed = findings_a - findings_b
    new_vulns = findings_b - findings_a
    
    return {
        "fixed_count": len(fixed),
        "new_count": len(new_vulns),
        "fixed": [{"type": t, "value": v, "url": u} for t, v, u in fixed],
        "new_vulns": [{"type": t, "value": v, "url": u} for t, v, u in new_vulns]
    }
