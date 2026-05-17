 
import argparse
import sys
import os
 
from izanagi.db import init_db
from izanagi import session as sm
from izanagi import reporter
from izanagi import ui
from izanagi.mitre import get_coverage_stats
from izanagi.console import run_console
 
 
# ── Subcommand handlers ───────────────────────────────────────────────────────
 
def cmd_console(args):
    run_console(initial_session_id=getattr(args, "session_id", None))
 
 
def cmd_start_session(args):
    s = sm.create_session(args.name, notes=args.notes or "")
    ui.print_success(f"Session created: {ui.bold(s['name'])} (ID: {ui.cyan(str(s['id']))})")
    ui.print_info(f"Started at: {s['started_at'][:19].replace('T', ' ')} UTC")
    ui.print_info(f"Database: {ui.dim(os.path.expanduser('~/.izanagi/izanagi.db'))}")
 
 
def cmd_run(args):
    try:
        action = sm.run_action(
            session_id=args.session_id,
            command=args.command,
            use_ai=args.ai,
            dry_run=args.dry_run,
        )
        ui.print_action_result(action)
    except ValueError as e:
        ui.print_error(str(e))
        sys.exit(1)
 
 
def cmd_list_sessions(args):
    sessions = sm.list_sessions()
    ui.print_session_table(sessions)
 
 
def cmd_end_session(args):
    s = sm.end_session(args.session_id)
    if not s:
        ui.print_error(f"Session {args.session_id} not found or already ended.")
        sys.exit(1)
    ui.print_success(f"Session {ui.bold(s['name'])} (ID: {args.session_id}) closed.")
    ui.print_info(f"Ended at: {s['ended_at'][:19].replace('T', ' ')} UTC")
 
 
def cmd_session_report(args):
    output = args.output or f"session_{args.session_id}_report.md"
    try:
        path = reporter.save_report(args.session_id, output)
        ui.print_success(f"Report saved: {ui.cyan(path)}")
        # Show a preview
        with open(path) as f:
            preview = f.read(300)
        ui.print_info("Preview:")
        print(ui.dim(preview + "..."))
    except Exception as e:
        ui.print_error(f"Failed to generate report: {e}")
        sys.exit(1)
 
 
def cmd_mitre_stats(args):
    stats = get_coverage_stats()
    ui.print_section("MITRE ATT&CK Coverage (Rule Base)")
    print(f"  {ui.bold('Total rules:')}     {stats['total_rules']}")
    print(f"  {ui.bold('Tactics covered:')} {stats['tactics_covered']}")
    print()
    print(f"  {ui.bold('Tactics:')}")
    for t in stats["tactics"]:
        print(f"    • {ui.yellow(t)}")
    print()
 
 
def cmd_delete_session(args):
    confirm = input(f"  Delete session {args.session_id} and all its actions? [y/N] ").strip().lower()
    if confirm != "y":
        ui.print_info("Aborted.")
        return
    ok = sm.delete_session(args.session_id)
    if ok:
        ui.print_success(f"Session {args.session_id} deleted.")
    else:
        ui.print_error(f"Session {args.session_id} not found.")
        sys.exit(1)
 
 
# ── Parser setup ──────────────────────────────────────────────────────────────
 
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="izanagi",
        description="イザナギ — AI Purple-Team CLI Assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  izanagi start-session "lab-exercise-01" --notes "HackTheBox AD lab"
  izanagi run 1 "whoami" --ai
  izanagi run 1 "nmap -sV 10.10.10.1" --ai
  izanagi list-sessions
  izanagi session-report 1 -o report.md
  izanagi end-session 1
  izanagi mitre-stats
        """,
    )
 
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True
 
    # console
    p_con = sub.add_parser("console", help="Launch interactive console (like msfconsole)")
    p_con.add_argument("--session", dest="session_id", type=int, default=None,
                       help="Auto-attach to this session ID on launch")
    p_con.set_defaults(func=cmd_console)
 
    # start-session
    p_start = sub.add_parser("start-session", help="Start a new engagement session")
    p_start.add_argument("name", help="Session name (e.g. 'lab-01')")
    p_start.add_argument("--notes", default="", help="Optional notes / scope")
    p_start.set_defaults(func=cmd_start_session)
 
    # run
    p_run = sub.add_parser("run", help="Execute a command inside a session")
    p_run.add_argument("session_id", type=int, help="Session ID")
    p_run.add_argument("command", help='Command to run (quote it: "nmap -sV 10.0.0.1")')
    p_run.add_argument("--ai", action="store_true", help="Enable AI enrichment tips")
    p_run.add_argument("--dry-run", action="store_true", help="Log without executing the command")
    p_run.set_defaults(func=cmd_run)
 
    # list-sessions
    p_list = sub.add_parser("list-sessions", help="Show all sessions")
    p_list.set_defaults(func=cmd_list_sessions)
 
    # end-session
    p_end = sub.add_parser("end-session", help="Close a session")
    p_end.add_argument("session_id", type=int, help="Session ID to close")
    p_end.set_defaults(func=cmd_end_session)
 
    # session-report
    p_report = sub.add_parser("session-report", help="Export session as Markdown report")
    p_report.add_argument("session_id", type=int, help="Session ID")
    p_report.add_argument("-o", "--output", help="Output file (default: session_<id>_report.md)")
    p_report.set_defaults(func=cmd_session_report)
 
    # mitre-stats
    p_mitre = sub.add_parser("mitre-stats", help="Show MITRE ATT&CK rule coverage")
    p_mitre.set_defaults(func=cmd_mitre_stats)
 
    # delete-session
    p_del = sub.add_parser("delete-session", help="Delete a session and all its data")
    p_del.add_argument("session_id", type=int, help="Session ID to delete")
    p_del.set_defaults(func=cmd_delete_session)
 
    return parser
 
 
# ── Entry point ───────────────────────────────────────────────────────────────
 
def main():
    # Init DB on every run (idempotent)
    init_db()
 
    if len(sys.argv) == 1:
        ui.print_banner()
        build_parser().print_help()
        sys.exit(0)
 
    # Show banner unless piping output
    if sys.stdout.isatty():
        ui.print_banner()
 
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
 
 
if __name__ == "__main__":
    main()