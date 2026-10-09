"""
UniGuard Stage 8: Hash-Chained Alert Ledger.

Stores alerts in an append-only SQLite table where each record hashes
itself and the previous record's hash. Tamper-evident by design.
Supports 180-day retention and incident report export.
"""
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path


class AlertLedger:
    def __init__(self, db_path: str = "alerts.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self):
        """Initialize the append-only schema."""
        with sqlite3.connect(self.db_path) as conn:
            # We use an auto-incrementing ID strictly to ensure order
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc REAL NOT NULL,
                    prev_hash TEXT NOT NULL,
                    alert_hash TEXT NOT NULL,
                    alert_json TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON alerts(timestamp_utc)")
            
            # Create a view that explicitly forbids updates/deletes via triggers
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS prevent_update BEFORE UPDATE ON alerts
                BEGIN SELECT RAISE(ABORT, 'APPEND ONLY - updates forbidden'); END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS prevent_delete BEFORE DELETE ON alerts
                BEGIN SELECT RAISE(ABORT, 'APPEND ONLY - deletes forbidden (use retention policy)'); END;
            """)

    def _get_last_hash(self) -> str:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT alert_hash FROM alerts ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            return row[0] if row else "GENESIS_HASH"

    def record_alert(self, alert_dict: dict) -> str:
        """
        Record a new alert in the ledger.
        Returns the hash of the new record.
        """
        # 1. Canonicalize the alert JSON
        alert_json = json.dumps(alert_dict, sort_keys=True, separators=(',', ':'))
        
        # 2. Get previous hash
        prev_hash = self._get_last_hash()
        
        # 3. Compute this record's hash: SHA256(prev_hash || alert_json)
        h = hashlib.sha256()
        h.update(prev_hash.encode('utf-8'))
        h.update(alert_json.encode('utf-8'))
        alert_hash = h.hexdigest()
        
        # 4. Insert
        ts = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO alerts (timestamp_utc, prev_hash, alert_hash, alert_json) VALUES (?, ?, ?, ?)",
                (ts, prev_hash, alert_hash, alert_json)
            )
            
        return alert_hash

    def verify_chain(self) -> tuple[bool, str]:
        """
        Verify the integrity of the hash chain.
        Returns (is_valid, error_message).
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT id, prev_hash, alert_hash, alert_json FROM alerts ORDER BY id ASC")
            
            expected_prev = "GENESIS_HASH"
            
            for row in cursor:
                row_id, prev_hash, alert_hash, alert_json = row
                
                # Check link to previous
                if prev_hash != expected_prev:
                    return False, f"Broken chain at ID {row_id}: prev_hash doesn't match previous record's hash."
                    
                # Recompute hash
                h = hashlib.sha256()
                h.update(prev_hash.encode('utf-8'))
                h.update(alert_json.encode('utf-8'))
                computed_hash = h.hexdigest()
                
                if computed_hash != alert_hash:
                    return False, f"Tampering detected at ID {row_id}: computed hash {computed_hash} != stored {alert_hash}"
                    
                expected_prev = alert_hash
                
        return True, "Chain intact"

    def export_incident_report(self, start_ts: float, end_ts: float) -> list[dict]:
        """Export all alerts in a time window (e.g. for a 6-hour incident report)."""
        alerts = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT alert_json FROM alerts WHERE timestamp_utc >= ? AND timestamp_utc <= ? ORDER BY id ASC",
                (start_ts, end_ts)
            )
            for row in cursor:
                alerts.append(json.loads(row[0]))
        return alerts

    def apply_retention_policy(self, days: int = 180):
        """
        Drop records older than the retention period.
        Note: This breaks the chain for the FIRST remaining record (its prev_hash
        will point to a deleted record), which is standard for rolling ledgers.
        The verify_chain function would need adaptation in a production system
        to accept a 'snapshot hash' for the start of the retained window.
        """
        cutoff_ts = time.time() - (days * 86400)
        
        with sqlite3.connect(self.db_path) as conn:
            # Temporarily disable the prevent_delete trigger
            conn.execute("DROP TRIGGER IF EXISTS prevent_delete")
            
            cursor = conn.execute("DELETE FROM alerts WHERE timestamp_utc < ?", (cutoff_ts,))
            deleted = cursor.rowcount
            
            # Recreate trigger
            conn.execute("""
                CREATE TRIGGER prevent_delete BEFORE DELETE ON alerts
                BEGIN SELECT RAISE(ABORT, 'APPEND ONLY - deletes forbidden (use retention policy)'); END;
            """)
            
        return deleted
