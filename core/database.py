"""
CyberMint Database Management System
"""
import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path


DB_PATH = Path("database/cybermint.db")


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    conn = get_connection()
    cursor = conn.cursor()

    # Projects table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            target TEXT,
            status TEXT DEFAULT 'active',
            risk_level TEXT DEFAULT 'unknown',
            security_score INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Assets table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            name TEXT NOT NULL,
            asset_type TEXT,
            value TEXT,
            metadata TEXT,
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
    """)

    # Findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT DEFAULT 'info',
            category TEXT,
            target TEXT,
            recommendation TEXT,
            status TEXT DEFAULT 'open',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
    """)

    # IOC (Indicators of Compromise) table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            threat_level TEXT DEFAULT 'unknown',
            description TEXT,
            source TEXT,
            tags TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Scan history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            module TEXT NOT NULL,
            target TEXT,
            result_summary TEXT,
            result_data TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
    """)

    # Notes table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            title TEXT,
            content TEXT,
            tags TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
    """)

    # Reports table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            title TEXT NOT NULL,
            report_type TEXT,
            content TEXT,
            file_path TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
    """)

    conn.commit()
    conn.close()


# ─── Project Operations ───────────────────────────────────────────────────────

def create_project(name, description="", target=""):
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO projects (name, description, target) VALUES (?, ?, ?)",
            (name, description, target)
        )
        conn.commit()
        return True, "Project created successfully."
    except sqlite3.IntegrityError:
        return False, "Project with that name already exists."
    finally:
        conn.close()


def get_projects():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_project(project_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_project(project_id, **kwargs):
    if not kwargs:
        return
    kwargs["updated_at"] = datetime.now().isoformat()
    fields = ", ".join(f"{k} = ?" for k in kwargs)
    values = list(kwargs.values()) + [project_id]
    conn = get_connection()
    conn.execute(f"UPDATE projects SET {fields} WHERE id = ?", values)
    conn.commit()
    conn.close()


def delete_project(project_id):
    conn = get_connection()
    conn.execute("DELETE FROM findings WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM assets WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM scan_history WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM notes WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM reports WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.commit()
    conn.close()


# ─── Findings Operations ──────────────────────────────────────────────────────

def add_finding(project_id, title, description="", severity="info",
                category="", target="", recommendation=""):
    conn = get_connection()
    conn.execute(
        """INSERT INTO findings
           (project_id, title, description, severity, category, target, recommendation)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (project_id, title, description, severity, category, target, recommendation)
    )
    conn.commit()
    conn.close()


def get_findings(project_id=None, severity=None):
    conn = get_connection()
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if project_id:
        query += " AND project_id = ?"
        params.append(project_id)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    query += " ORDER BY created_at DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── IOC Operations ───────────────────────────────────────────────────────────

def add_ioc(ioc_type, value, threat_level="unknown", description="", source="", tags=""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO iocs (ioc_type, value, threat_level, description, source, tags) VALUES (?,?,?,?,?,?)",
        (ioc_type, value, threat_level, description, source, tags)
    )
    conn.commit()
    conn.close()


def get_iocs(ioc_type=None):
    conn = get_connection()
    if ioc_type:
        rows = conn.execute("SELECT * FROM iocs WHERE ioc_type = ? ORDER BY created_at DESC", (ioc_type,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM iocs ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Scan History ─────────────────────────────────────────────────────────────

def save_scan(project_id, module, target, summary, data=None):
    conn = get_connection()
    conn.execute(
        "INSERT INTO scan_history (project_id, module, target, result_summary, result_data) VALUES (?,?,?,?,?)",
        (project_id, module, target, summary, json.dumps(data) if data else None)
    )
    conn.commit()
    conn.close()


def get_scan_history(project_id=None, limit=20):
    conn = get_connection()
    if project_id:
        rows = conn.execute(
            "SELECT * FROM scan_history WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
            (project_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Notes ────────────────────────────────────────────────────────────────────

def add_note(project_id, title, content, tags=""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO notes (project_id, title, content, tags) VALUES (?,?,?,?)",
        (project_id, title, content, tags)
    )
    conn.commit()
    conn.close()


def get_notes(project_id=None):
    conn = get_connection()
    if project_id:
        rows = conn.execute("SELECT * FROM notes WHERE project_id = ? ORDER BY created_at DESC", (project_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM notes ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Asset Operations ─────────────────────────────────────────────────────────

def add_asset(project_id, name, asset_type="", value="", metadata=None, notes=""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO assets (project_id, name, asset_type, value, metadata, notes) VALUES (?,?,?,?,?,?)",
        (project_id, name, asset_type, value, json.dumps(metadata) if metadata else None, notes)
    )
    conn.commit()
    conn.close()


def get_assets(project_id):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM assets WHERE project_id = ? ORDER BY created_at DESC", (project_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Reports ──────────────────────────────────────────────────────────────────

def save_report(project_id, title, report_type, content, file_path=""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO reports (project_id, title, report_type, content, file_path) VALUES (?,?,?,?,?)",
        (project_id, title, report_type, content, file_path)
    )
    conn.commit()
    conn.close()


def get_reports(project_id=None):
    conn = get_connection()
    if project_id:
        rows = conn.execute("SELECT * FROM reports WHERE project_id = ? ORDER BY created_at DESC", (project_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM reports ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]
