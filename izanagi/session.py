


import sqlite3
import subprocess
import datetime
from typing import Optional
from izanagi.db import get_connection
from izanagi.mitre import map_command
 
 
def _now() -> str:
    """Return current UTC time as ISO-8601 string"""
    return datetime.datetime.utcnow().isoformat()
 
 
def _row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a sqlite3.Row to a plain python dict."""
    return dict(row)
 
 
def create_session(name: str, notes: str = "") -> dict:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO sessions(name,started_at,notes)VALUES(?,?,?)",
            (name, _now(), notes),
        )
        conn.commit()
        session_id = cur.lastrowid
        return get_session(session_id)          # BUG FIX 1: was get_connection(session_id)
    finally:
        conn.close()
 
 
def get_session(session_id: int) -> Optional[dict]:
    """Fetch a single session by id. Returns None if not found."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        row = cur.fetchone()
        return _row_to_dict(row) if row else None
    finally:
        conn.close()
 
 
def list_sessions() -> list[dict]:
    """Return all sessions ordered newest-first."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions ORDER BY id DESC")
        return [_row_to_dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
 
 
def end_session(session_id: int) -> Optional[dict]:   # BUG FIX 2: was end_sesion (typo)
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE sessions SET ended_at = ? WHERE id=? AND ended_at IS NULL",  # BUG FIX 3: was "UPDATE session" (missing 's')
            (_now(), session_id),
        )
        conn.commit()
        return get_session(session_id)              # BUG FIX 4: was get_connection(session_id)
    finally:
        conn.close()
 
 
def delete_session(session_id: int) -> bool:
    """Delete a session and all its actions (cascade)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM actions WHERE session_id = ?", (session_id,))
        cur.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()
 
 
def run_action(
    session_id: int,
    command: str,
    use_ai: bool = False,
    dry_run: bool = False,
) -> dict:
    session = get_session(session_id)
    if not session:
        raise ValueError(f"Session {session_id} not found.")
    if session["ended_at"]:
        raise ValueError(f"Session {session_id} is already closed.")
 
    stdout_text = ""
    stderr_text = ""
    exit_code = 0
 
    if not dry_run:
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            stdout_text = result.stdout.strip()
            stderr_text = result.stderr.strip()
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            stderr_text = "[izanagi] Command timed out after 30s"
            exit_code = -1
        except Exception as exc:
            stderr_text = f"[izanagi] Execution error: {exc}"
            exit_code = -2
 
    mapping = map_command(command)
    ai_data = _ai_enrich(command, mapping) if use_ai else {}
 
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO actions (
                session_id, command, stdout, stderr, exit_code,
                executed_at, tactic, technique_id, technique_name,
                ai_summary, ai_red_tip, ai_blue_tip, confidence
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                session_id,
                command,
                stdout_text,
                stderr_text,
                exit_code,
                _now(),
                mapping["tactic"] if mapping else None,
                mapping["technique_id"] if mapping else None,
                mapping["technique_name"] if mapping else None,
                ai_data.get("summary"),
                ai_data.get("red_tip"),
                ai_data.get("blue_tip"),
                mapping["confidence"] if mapping else None,
            ),
        )
        conn.commit()
        action_id = cur.lastrowid
        cur.execute("SELECT * FROM actions WHERE id = ?", (action_id,))
        return _row_to_dict(cur.fetchone())
    finally:
        conn.close()
 
 
def get_session_actions(session_id: int) -> list[dict]:
    """Return all actions for a session, ordered chronologically."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM actions WHERE session_id = ? ORDER BY id ASC",
            (session_id,),
        )
        return [_row_to_dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
 
 
def _ai_enrich(command: str, mapping: Optional[dict]) -> dict:
    tactic = mapping["tactic"] if mapping else "Unknown"
 
    tips = {
        "Discovery": {
            "summary": f"Reconnaissance command '{command}' used for environment mapping.",
            "red_tip": "Consider obfuscating recon commands or using living-off-the-land binaries (LOLBins).",
            "blue_tip": "Alert on rapid sequential discovery commands from the same process lineage.",
        },
        "Credential Access": {
            "summary": f"Credential harvesting attempted via '{command}'.",
            "red_tip": "Run from memory where possible to avoid AV signatures on disk.",
            "blue_tip": "Enable LSASS protection (PPL) and audit Credential Manager access.",
        },
        "Lateral Movement": {
            "summary": f"Lateral movement via '{command}'.",
            "red_tip": "Use stolen tokens/tickets instead of passwords to reduce credential exposure.",
            "blue_tip": "Monitor for unusual SMB/SSH auth patterns from non-admin workstations.",
        },
        "Privilege Escalation": {
            "summary": f"Privilege escalation attempt: '{command}'.",
            "red_tip": "Chain PrivEsc with persistence immediately to maintain elevated access.",
            "blue_tip": "Audit sudo rules and SUID binaries; alert on unexpected privilege changes.",
        },
        "Execution": {
            "summary": f"Code execution via '{command}'.",
            "red_tip": "Use AMSI bypass or in-memory execution to evade script-block logging.",
            "blue_tip": "Enable Script Block Logging (PowerShell) and process creation auditing.",
        },
        "Persistence": {
            "summary": f"Persistence mechanism established: '{command}'.",
            "red_tip": "Use multiple persistence methods to survive IR response.",
            "blue_tip": "Baseline scheduled tasks and startup entries; alert on new additions.",
        },
        "Defense Evasion": {
            "summary": f"Evasion technique: '{command}'.",
            "red_tip": "Clear logs selectively to avoid raising alerts from bulk deletion.",
            "blue_tip": "Forward logs to a remote SIEM immediately so local clearing is non-destructive.",
        },
        "Exfiltration": {
            "summary": f"Potential data exfiltration via '{command}'.",
            "red_tip": "Encrypt and compress data before exfil to reduce detection surface.",
            "blue_tip": "Monitor unusual outbound traffic volumes and connections to new external IPs.",
        },
    }
 
    default = {
        "summary": f"Command '{command}' executed. No MITRE mapping found.",
        "red_tip": "Ensure command blends with normal user/admin activity (living off the land).",
        "blue_tip": "Establish a baseline of normal command usage; alert on anomalies.",
    }
 
    return tips.get(tactic, default)