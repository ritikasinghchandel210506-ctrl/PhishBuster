"""SQLite persistence layer. All queries are parameterized (no string-built SQL)."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_detector.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

def init_db(db_path: str = DB_PATH) -> None:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.commit()

@contextmanager
def get_connection(db_path: str = DB_PATH):
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def save_analysis(record: dict, db_path: str = DB_PATH) -> int:
    """Insert one analysis record. `record` keys must match the schema columns
    (suspicious_indicators is stored as a JSON string)."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO analyses (
                timestamp, filename, sender, subject, verdict, attack_type,
                risk_score, severity, ml_probability, sender_risk, url_risk,
                content_risk, attachment_risk, impersonation_risk,
                suspicious_indicators, ai_explanation, explanation_source,
                url_count, attachment_count, input_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["timestamp"], record.get("filename"), record.get("sender"),
                record.get("subject"), record["verdict"], record.get("attack_type"),
                record["risk_score"], record["severity"], record.get("ml_probability"),
                record.get("sender_risk"), record.get("url_risk"), record.get("content_risk"),
                record.get("attachment_risk"), record.get("impersonation_risk"),
                json.dumps(record.get("suspicious_indicators", [])),
                record.get("ai_explanation"), record.get("explanation_source"),
                record.get("url_count", 0), record.get("attachment_count", 0),
                record.get("input_source", "manual"),
            ),
        )
        conn.commit()
        return cur.lastrowid


def get_history(limit: int = 200, db_path: str = DB_PATH) -> list:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_analysis_by_id(analysis_id: int, db_path: str = DB_PATH) -> dict | None:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        return dict(row) if row else None


def get_dashboard_stats(db_path: str = DB_PATH) -> dict:
    with get_connection(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM analyses").fetchone()["c"]
        by_verdict = {r["verdict"]: r["c"] for r in conn.execute(
            "SELECT verdict, COUNT(*) AS c FROM analyses GROUP BY verdict"
        ).fetchall()}
        by_severity = {r["severity"]: r["c"] for r in conn.execute(
            "SELECT severity, COUNT(*) AS c FROM analyses GROUP BY severity"
        ).fetchall()}
        by_attack_type = {r["attack_type"]: r["c"] for r in conn.execute(
            "SELECT attack_type, COUNT(*) AS c FROM analyses WHERE attack_type IS NOT NULL "
            "AND attack_type != 'N/A' GROUP BY attack_type"
        ).fetchall()}
        avg_score_row = conn.execute("SELECT AVG(risk_score) AS avg_score FROM analyses").fetchone()
        avg_score = round(avg_score_row["avg_score"], 1) if avg_score_row["avg_score"] is not None else 0
        high_critical = conn.execute(
            "SELECT COUNT(*) AS c FROM analyses WHERE severity IN ('High', 'Critical')"
        ).fetchone()["c"]
        recent = conn.execute(
            "SELECT id, timestamp, sender, subject, verdict, risk_score, severity "
            "FROM analyses ORDER BY id DESC LIMIT 10"
        ).fetchall()

        return {
            "total": total,
            "by_verdict": by_verdict,
            "by_severity": by_severity,
            "by_attack_type": by_attack_type,
            "avg_score": avg_score,
            "high_critical": high_critical,
            "recent": [dict(r) for r in recent],
        }


def clear_history(db_path: str = DB_PATH) -> None:
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM analyses")
        conn.commit()
