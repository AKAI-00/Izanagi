import sqlite3
import os
 
DB_PATH = os.path.join(os.path.expanduser("~"), ".izanagi", "izanagi.db")
 
 
def get_connection() -> sqlite3.Connection:
    """
    LESSON: Connection objects
    sqlite3.connect() opens (or creates) the .db file.
    row_factory = sqlite3.Row lets us access columns by name (row["id"])
    instead of index (row[0]) — much more readable.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
 
 
def init_db():
    """
    LESSON: Schema initialisation
    CREATE TABLE IF NOT EXISTS = idempotent — safe to run on every startup.
    TEXT / INTEGER / REAL are SQLite's core types (it uses dynamic typing).
    PRIMARY KEY AUTOINCREMENT = SQLite auto-assigns a unique integer id.
    FOREIGN KEY links actions → sessions (referential integrity).
    """
    conn = get_connection()
    cur = conn.cursor()
 
    cur.executescript("""
        PRAGMA foreign_keys = ON;
 
        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            started_at  TEXT    NOT NULL,   -- ISO-8601 timestamp
            ended_at    TEXT,               -- NULL until session closed
            notes       TEXT
        );
 
        CREATE TABLE IF NOT EXISTS actions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      INTEGER NOT NULL,
            command         TEXT    NOT NULL,
            stdout          TEXT,
            stderr          TEXT,
            exit_code       INTEGER,
            executed_at     TEXT    NOT NULL,
            tactic          TEXT,           -- MITRE tactic name
            technique_id    TEXT,           -- e.g. T1033
            technique_name  TEXT,
            ai_summary      TEXT,
            ai_red_tip      TEXT,
            ai_blue_tip     TEXT,
            confidence      REAL,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );
    """)
 
    conn.commit()
    conn.close()
    return DB_PATH