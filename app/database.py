import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "soc_alerts.db"

VALID_STATUSES = {"New", "Investigating", "Resolved"}


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                alert_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                source_ip TEXT,
                username TEXT,
                reasons TEXT NOT NULL,
                recommended_actions TEXT NOT NULL,
                analyst_review_required INTEGER NOT NULL,
                generated_at TEXT NOT NULL,
                full_result TEXT NOT NULL
            )
        """)

        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(alerts)"
            ).fetchall()
        }

        if "status" not in columns:
            conn.execute("""
                ALTER TABLE alerts
                ADD COLUMN status TEXT NOT NULL DEFAULT 'New'
            """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT 'system',
                occurred_at TEXT NOT NULL,
                details TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_alert_id
            ON audit_events(alert_id, event_id)
        """)



def _record_audit(conn, alert_id, action, details):
    """Record an audit event using the caller's active transaction."""
    conn.execute("""
        INSERT INTO audit_events (
            alert_id, action, actor, occurred_at, details
        ) VALUES (?, ?, ?, ?, ?)
    """, (
        alert_id,
        action,
        "system",
        datetime.now(timezone.utc).isoformat(),
        json.dumps(details),
    ))


def get_audit_events(alert_id, limit=100):
    """Return the newest audit events for one alert."""
    limit = max(1, min(int(limit), 500))

    with get_connection() as conn:
        rows = conn.execute("""
            SELECT event_id, alert_id, action, actor, occurred_at, details
            FROM audit_events
            WHERE alert_id = ?
            ORDER BY event_id DESC
            LIMIT ?
        """, (alert_id, limit)).fetchall()

    events = []
    for row in rows:
        event = dict(row)
        event["details"] = json.loads(event["details"])
        events.append(event)

    return events


def save_alert(result):
    result = dict(result)
    status = result.get("status", "New")

    if status not in VALID_STATUSES:
        status = "New"

    result["status"] = status

    with get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO alerts (
                alert_id, alert_name, severity, risk_score,
                source_ip, username, reasons, recommended_actions,
                analyst_review_required, generated_at, full_result,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result["alert_id"],
            result["alert_name"],
            result["severity"],
            result["risk_score"],
            result.get("source_ip"),
            result.get("username"),
            json.dumps(result.get("reasons", [])),
            json.dumps(result.get("recommended_actions", [])),
            int(result.get("analyst_review_required", True)),
            result["generated_at"],
            json.dumps(result),
            status,
        ))

        _record_audit(
            conn,
            result["alert_id"],
            "alert_saved",
            {
                "alert_name": result["alert_name"],
                "severity": result["severity"],
                "risk_score": result["risk_score"],
                "status": status,
            },
        )
def delete_alert(alert_id):
    """Delete one alert while preserving its audit history."""
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT alert_name, severity, risk_score
            FROM alerts
            WHERE alert_id = ?
            """,
            (alert_id,),
        ).fetchone()

        if row is None:
            return False

        _record_audit(
            conn,
            alert_id,
            "alert_deleted",
            {
                "alert_name": row["alert_name"],
                "severity": row["severity"],
                "risk_score": row["risk_score"],
            },
        )

        conn.execute(
            "DELETE FROM alerts WHERE alert_id = ?",
            (alert_id,),
        )

    return True

def get_alerts(limit=200):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT full_result, status FROM alerts "
            "ORDER BY generated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

    alerts = []

    for row in rows:
        alert = json.loads(row["full_result"])
        alert["status"] = row["status"]
        alerts.append(alert)

    return alerts


def update_alert_status(alert_id, status):
    if status not in VALID_STATUSES:
        raise ValueError("Invalid alert status")

    with get_connection() as conn:
        row = conn.execute(
            "SELECT status, full_result FROM alerts WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()

        if row is None:
            return False

        old_status = row["status"]
        result = json.loads(row["full_result"])
        result["status"] = status

        conn.execute(
            "UPDATE alerts SET status = ?, full_result = ? "
            "WHERE alert_id = ?",
            (status, json.dumps(result), alert_id),
        )

        if old_status != status:
            _record_audit(
                conn,
                alert_id,
                "status_changed",
                {"old_status": old_status, "new_status": status},
            )

    return True


def update_alert_analysis(alert_id, result):
    """Update an existing alert without creating a new queue entry."""
    result = dict(result)

    with get_connection() as conn:
        row = conn.execute(
            "SELECT status, severity, risk_score FROM alerts WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()

        if row is None:
            return False

        old_severity = row["severity"]
        old_risk_score = row["risk_score"]
        status = row["status"]
        result["alert_id"] = alert_id
        result["status"] = status

        conn.execute("""
            UPDATE alerts SET
                alert_name = ?,
                severity = ?,
                risk_score = ?,
                source_ip = ?,
                username = ?,
                reasons = ?,
                recommended_actions = ?,
                analyst_review_required = ?,
                generated_at = ?,
                full_result = ?
            WHERE alert_id = ?
        """, (
            result["alert_name"],
            result["severity"],
            result["risk_score"],
            result.get("source_ip"),
            result.get("username"),
            json.dumps(result.get("reasons", [])),
            json.dumps(result.get("recommended_actions", [])),
            int(result.get("analyst_review_required", True)),
            result["generated_at"],
            json.dumps(result),
            alert_id,
        ))

        _record_audit(
            conn,
            alert_id,
            "alert_reanalyzed",
            {
                "old_severity": old_severity,
                "new_severity": result["severity"],
                "old_risk_score": old_risk_score,
                "new_risk_score": result["risk_score"],
            },
        )

    return True
