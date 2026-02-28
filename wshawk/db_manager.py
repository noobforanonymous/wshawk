import sqlite3
import json
import uuid
import shlex
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

class WSHawkDatabase:
    """
    Unified WSHawk SQLite Database Manager.
    Handles persistence for both the Web GUI, Bridge, and CLI reports.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = Path(db_path)
        else:
            # Default to ~/.wshawk/wshawk_v3.db to avoid conflicts with legacy versions
            self.db_path = Path(os.path.expanduser('~')) / '.wshawk' / 'wshawk_v3.db'
            
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        
    def _get_conn(self) -> sqlite3.Connection:
        """Get a connection with modern SQLite defaults."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
        
    def _init_schema(self):
        """Merges schemas from app.py and legacy db_manager.py."""
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    options TEXT DEFAULT '{}',
                    status TEXT DEFAULT 'queued',
                    progress INTEGER DEFAULT 0,
                    findings_json TEXT DEFAULT '[]',
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    info_count INTEGER DEFAULT 0,
                    messages_sent INTEGER DEFAULT 0,
                    messages_received INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    duration REAL DEFAULT 0,
                    error TEXT
                );
                
                CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
                CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
            """)
            conn.commit()
        finally:
            conn.close()

    def create(self, target: str, options: Optional[Dict] = None) -> str:
        """Create a new scan entry, return scan ID."""
        scan_id = str(uuid.uuid4())
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO scans (id, target, options, status, created_at)
                   VALUES (?, ?, ?, 'queued', ?)""",
                (scan_id, target, json.dumps(options or {}), datetime.now().isoformat())
            )
            conn.commit()
        finally:
            conn.close()
        return scan_id

    def update(self, scan_id: str, **kwargs):
        """Update scan fields."""
        conn = self._get_conn()
        try:
            for key, value in kwargs.items():
                if key in ('findings_json', 'options'):
                    value = json.dumps(value)
                conn.execute(
                    f"UPDATE scans SET {key} = ? WHERE id = ?",
                    (value, scan_id)
                )
            conn.commit()
        finally:
            conn.close()

    def save_scan(self, target: str, report: Dict) -> str:
        """Compatibility method for legacy toolchains, converts report to schema."""
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        elapsed = report.get("elapsed", 0.0)
        sev = report.get("severity_counts", {})
        findings = report.get("findings", [])
        
        # Inject PoC into each finding
        for f in findings:
            if "poc" not in f:
                f["poc"] = self._generate_poc(f, target)
                
        conn = self._get_conn()
        try:
            conn.execute('''
                INSERT INTO scans (
                    id, target, created_at, started_at, completed_at, 
                    duration, high_count, medium_count, low_count, 
                    info_count, findings_json, status, progress
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', 100)
            ''', (
                scan_id, target, timestamp, timestamp, timestamp,
                elapsed, sev.get("High", 0), sev.get("Medium", 0), 
                sev.get("Low", 0), sev.get("Info", 0), json.dumps(findings)
            ))
            conn.commit()
        finally:
            conn.close()
        return scan_id

    def get(self, scan_id: str) -> Optional[Dict]:
        """Get scan by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row:
                return self._row_to_dict(row)
            return None
        finally:
            conn.close()

    def list_all(self, limit: int = 100) -> List[Dict]:
        """Get all scans, newest first."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def delete(self, scan_id: str) -> bool:
        """Delete a scan."""
        conn = self._get_conn()
        try:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def get_stats(self) -> Dict:
        """Get aggregate statistics."""
        conn = self._get_conn()
        try:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            completed = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE status = 'completed'"
            ).fetchone()[0]
            running = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE status IN ('queued', 'running')"
            ).fetchone()[0]
            return {
                'total_scans': total,
                'completed': completed,
                'running': running,
            }
        finally:
            conn.close()

    def compare_scans(self, scan_a_id: str, scan_b_id: str) -> Dict:
        """Compute diff between two historical scans."""
        scan_a = self.get(scan_a_id)
        scan_b = self.get(scan_b_id)
        
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

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert a sqlite3.Row to a dict with JSON parsing."""
        d = dict(row)
        if 'findings_json' in d:
            d['findings'] = json.loads(d.pop('findings_json') or '[]')
        if 'options' in d:
            d['options'] = json.loads(d['options'] or '{}')
        return d

    def _generate_poc(self, finding: Dict, target: str) -> str:
        """Generate a quick curl or HTML snippet for PoC."""
        finding_type = finding.get("type", "")
        val = finding.get("value", "")
        url = finding.get("url", target) or target

        safe_url = shlex.quote(url)
        
        if finding_type == "csrf":
            return f'<html><body><form action="{url}" method="POST"><input type="submit" value="Exploit CSRF"></form><script>document.forms[0].submit();</script></body></html>'
        elif any(k in finding_type.lower() for k in ("sql", "xss", "cmd", "lfi", "fuzz")):
            safe_val = shlex.quote(val)
            return f"curl -X POST {safe_url} -d {safe_val}"
        else:
            return f"curl -I {safe_url}"

# Integration functions for legacy functional usage
_db_instance = None

def _get_db() -> WSHawkDatabase:
    global _db_instance
    if _db_instance is None:
        _db_instance = WSHawkDatabase()
    return _db_instance

def init_db(): _get_db()
def save_scan(target, report): return _get_db().save_scan(target, report)
def get_all_scans(): return _get_db().list_all()
def get_scan(scan_id): return _get_db().get(scan_id)
def compare_scans(id1, id2): return _get_db().compare_scans(id1, id2)
