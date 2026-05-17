import datetime
from izanagi.session import get_session,get_session_actions

HIGH_CONF=0.90
MED_CONF=0.70

def _confidence_label(score: float) -> str:
    if score >= HIGH_CONF:
        return "🔴 HIGH"
    if score >= MED_CONF:
        return "🟡 MEDIUM"
    return "🟢 LOW"
 
 
def _format_timestamp(iso: str) -> str:
    """Make ISO timestamp human-readable."""
    try:
        dt = datetime.datetime.fromisoformat(iso)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return iso or "—"
 
 
def generate_markdown(session_id: int) -> str:
    """
    LESSON: Building structured documents programmatically
    We walk through the session data and emit Markdown sections.
 
    Report structure:
      1. Header / metadata
      2. Executive summary (counts, tactics hit)
      3. MITRE ATT&CK coverage table
      4. Full action timeline
      5. Blue-team recommendations
      6. Footer
    """
    session = get_session(session_id)
    if not session:
        return f"# Error\n\nSession `{session_id}` not found.\n"
 
    actions = get_session_actions(session_id)
    lines = []
 
    # ── 1. Header ────────────────────────────────────────────────────────────
    lines += [
        "# 🗡️ Izanagi Engagement Report",
        "",
        f"**Session:** {session['name']}  ",
        f"**Session ID:** `{session['id']}`  ",
        f"**Started:** {_format_timestamp(session['started_at'])}  ",
        f"**Ended:** {_format_timestamp(session['ended_at']) if session['ended_at'] else '⚠️ Still active'}  ",
        f"**Generated:** {_format_timestamp(datetime.datetime.utcnow().isoformat())}  ",
        "",
        "---",
        "",
    ]
 
    # ── 2. Executive Summary ─────────────────────────────────────────────────
    total = len(actions)
    mapped = [a for a in actions if a["technique_id"]]
    unmapped = total - len(mapped)
    tactics_hit = sorted({a["tactic"] for a in mapped if a["tactic"]})
 
    lines += [
        "## 📊 Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total commands | {total} |",
        f"| MITRE-mapped | {len(mapped)} |",
        f"| Unmapped | {unmapped} |",
        f"| Tactics observed | {len(tactics_hit)} |",
        f"| Coverage rate | {round(len(mapped)/total*100 if total else 0, 1)}% |",
        "",
    ]
 
    if tactics_hit:
        lines += ["**Tactics Observed:** " + " · ".join(f"`{t}`" for t in tactics_hit), ""]
 
    lines += ["---", ""]
 
    # ── 3. MITRE Coverage Table ───────────────────────────────────────────────
    if mapped:
        lines += [
            "## 🎯 MITRE ATT&CK Coverage",
            "",
            "| Technique ID | Name | Tactic | Confidence | Commands |",
            "|---|---|---|---|---|",
        ]
 
        # Group by technique
        tech_map: dict[str, dict] = {}
        for a in mapped:
            tid = a["technique_id"]
            if tid not in tech_map:
                tech_map[tid] = {
                    "id": tid,
                    "name": a["technique_name"],
                    "tactic": a["tactic"],
                    "confidence": a["confidence"],
                    "count": 0,
                }
            tech_map[tid]["count"] += 1
 
        for t in sorted(tech_map.values(), key=lambda x: x["tactic"]):
            conf = t["confidence"] or 0
            lines.append(
                f"| `{t['id']}` | {t['name']} | {t['tactic']} "
                f"| {_confidence_label(conf)} ({round(conf*100)}%) | {t['count']} |"
            )
 
        lines += ["", "---", ""]
 
    # ── 4. Action Timeline ────────────────────────────────────────────────────
    lines += [
        "## 📋 Action Timeline",
        "",
    ]
 
    for i, action in enumerate(actions, 1):
        conf_str = ""
        if action["confidence"] is not None:
            conf_str = f" · {_confidence_label(action['confidence'])}"
 
        mitre_str = ""
        if action["technique_id"]:
            mitre_str = f"\n> 🎯 **ATT&CK:** `{action['technique_id']}` — {action['technique_name']} ({action['tactic']}){conf_str}"
 
        lines += [
            f"### [{i}] `{action['command']}`",
            f"> ⏱ {_format_timestamp(action['executed_at'])} · Exit code: `{action['exit_code']}`",
            mitre_str,
            "",
        ]
 
        if action["stdout"]:
            # Truncate very long outputs in the report
            out = action["stdout"]
            if len(out) > 500:
                out = out[:500] + "\n... [truncated]"
            lines += [
                "**Output:**",
                "```",
                out,
                "```",
                "",
            ]
 
        if action["stderr"] and action["exit_code"] != 0:
            lines += [
                "**Errors:**",
                "```",
                action["stderr"][:300],
                "```",
                "",
            ]
 
        # AI tips
        if action["ai_summary"]:
            lines += [
                f"> 🤖 **AI Summary:** {action['ai_summary']}",
                "",
            ]
        if action["ai_red_tip"]:
            lines += [
                f"> 🔴 **Red Tip:** {action['ai_red_tip']}",
                "",
            ]
        if action["ai_blue_tip"]:
            lines += [
                f"> 🔵 **Blue Tip:** {action['ai_blue_tip']}",
                "",
            ]
 
        lines.append("---")
        lines.append("")
 
    # ── 5. Blue-Team Recommendations ─────────────────────────────────────────
    blue_tips = [a["ai_blue_tip"] for a in actions if a.get("ai_blue_tip")]
    if blue_tips:
        lines += [
            "## 🔵 Blue-Team Recommendations",
            "",
        ]
        seen = set()
        for tip in blue_tips:
            if tip not in seen:
                seen.add(tip)
                lines.append(f"- {tip}")
        lines += ["", "---", ""]
 
    # ── 6. Footer ─────────────────────────────────────────────────────────────
    lines += [
        "## ℹ️ About",
        "",
        "*Generated by [Izanagi](https://github.com/izanagi) — AI Purple-Team Assistant.*  ",
        "*For authorized security testing and educational purposes only.*",
        "",
        "> ⚠️ **Disclaimer:** This report documents a controlled security exercise. "
        "All activities were performed with explicit authorization.",
        "",
    ]
 
    return "\n".join(lines)
 
 
def save_report(session_id: int, output_path: str) -> str:
    """Write the Markdown report to a file and return the path."""
    content = generate_markdown(session_id)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path