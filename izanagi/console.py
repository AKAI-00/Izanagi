import os
import sys
import subprocess
import datetime
 
# readline gives us arrow-key history and line editing for free
try:
    import readline
    _READLINE = True
except ImportError:
    _READLINE = False   # Windows fallback — works, just no arrow keys
 
from izanagi.db import init_db
from izanagi import session as sm
from izanagi import reporter
from izanagi import ui
from izanagi.mitre import map_command, get_coverage_stats
 
HISTORY_FILE = os.path.join(os.path.expanduser("~"), ".izanagi", "console_history")
BANNER_CONSOLE = """
  ╔══════════════════════════════════════════════════════════╗
  ║          イザナギ  INTERACTIVE CONSOLE  v1.0             ║
  ║       AI Purple-Team Assistant — Authorized Use Only     ║
  ╚══════════════════════════════════════════════════════════╝
"""
 
 
# ── Console state ────────────────────────────────────────────────────────────
 
class ConsoleState:
    """
    LESSON: Why a class for state?
    We could use global variables, but a class keeps related state
    together and makes it easy to reset or inspect everything at once.
    """
    def __init__(self):
        self.session_id: int | None = None
        self.session_name: str = "no session"
        self.ai_enabled: bool = True
        self.dry_run: bool = False
        self.action_count: int = 0
        self.start_time = datetime.datetime.utcnow()
 
    @property
    def prompt(self) -> str:
        """
        LESSON: Dynamic prompts
        The prompt string is rebuilt on every input() call.
        We colour it based on whether a session is active.
        Metasploit does the same — msf6 exploit(ms17_010) > shows context.
        """
        ai_flag = ui.yellow(" [AI]") if self.ai_enabled else ""
        dr_flag = ui.dim(" [DRY]") if self.dry_run else ""
        if self.session_id:
            sess = ui.cyan(self.session_name[:28])
            return f"\n  {ui.bold(ui.magenta('izanagi'))} [{sess}]{ai_flag}{dr_flag} {ui.bold(ui.white('>'))} "
        else:
            return f"\n  {ui.bold(ui.magenta('izanagi'))} [{ui.dim('no session')}]{ai_flag}{dr_flag} {ui.bold(ui.white('>'))} "
 
 
# ── Built-in command handlers ────────────────────────────────────────────────
 
def _cmd_help(state: ConsoleState, args: list[str]):
    """Print all available console commands."""
    ui.print_section("Console Commands")
    cmds = [
        ("help",                    "Show this help"),
        ("sessions",                "List all sessions in the database"),
        ("use <id|name>",           "Activate a session by ID or name"),
        ("new <name> [notes]",      "Create and activate a new session"),
        ("end",                     "Close the active session"),
        ("show",                    "Show active session details + action count"),
        ("report [file.md]",        "Export active session to Markdown report"),
        ("ai on|off",               "Toggle AI tips after each command"),
        ("dry on|off",              "Toggle dry-run (log without executing)"),
        ("mitre <cmd>",             "Manually look up MITRE mapping for a command"),
        ("coverage",                "Show MITRE rule-base coverage stats"),
        ("history",                 "Show commands run this console session"),
        ("clear",                   "Clear the terminal screen"),
        ("exit / quit",             "Exit the console"),
        ("",                        ""),
        ("<any other command>",     "Execute it in shell, log + MITRE-map it"),
    ]
    for cmd, desc in cmds:
        if cmd:
            print(f"  {ui.cyan(f'{cmd:<28}')} {desc}")
        else:
            print()
    print()
 
 
def _cmd_sessions(state: ConsoleState, args: list[str]):
    """List all sessions."""
    sessions = sm.list_sessions()
    ui.print_session_table(sessions)
 
 
def _cmd_use(state: ConsoleState, args: list[str]):
    """Activate a session by ID or name prefix."""
    if not args:
        ui.print_error("Usage: use <session_id|name>")
        return
 
    query = " ".join(args)
    sessions = sm.list_sessions()
 
    # Try exact integer ID first
    target = None
    if query.isdigit():
        target = sm.get_session(int(query))
    else:
        # Fuzzy name match — find first session whose name starts with query
        for s in sessions:
            if s["name"].lower().startswith(query.lower()):
                target = s
                break
 
    if not target:
        ui.print_error(f"No session found matching '{query}'. Run 'sessions' to list them.")
        return
 
    if target["ended_at"]:
        ui.print_warn(f"Session '{target['name']}' is closed. Commands will not be logged.")
        ui.print_info("Create a new one with: new <name>")
        return
 
    state.session_id = target["id"]
    state.session_name = target["name"]
    actions = sm.get_session_actions(target["id"])
    state.action_count = len(actions)
    ui.print_success(f"Active session: {ui.bold(target['name'])} (ID: {target['id']})")
    ui.print_info(f"{len(actions)} actions already logged in this session.")
 
 
def _cmd_new(state: ConsoleState, args: list[str]):
    """Create a new session and activate it."""
    if not args:
        ui.print_error("Usage: new <name> [optional notes]")
        return
 
    name = args[0]
    notes = " ".join(args[1:]) if len(args) > 1 else ""
    s = sm.create_session(name, notes=notes)
    state.session_id = s["id"]
    state.session_name = s["name"]
    state.action_count = 0
    ui.print_success(f"Session created: {ui.bold(s['name'])} (ID: {ui.cyan(str(s['id']))})")
    ui.print_info(f"Started at: {s['started_at'][:19].replace('T', ' ')} UTC")
 
 
def _cmd_end(state: ConsoleState, args: list[str]):
    """Close the active session."""
    if not state.session_id:
        ui.print_error("No active session. Use 'use <id>' or 'new <name>' first.")
        return
 
    closed = sm.end_session(state.session_id)
    ui.print_success(f"Session '{state.session_name}' closed.")
    ui.print_info(f"Total actions logged: {state.action_count}")
    state.session_id = None
    state.session_name = "no session"
    state.action_count = 0
 
 
def _cmd_show(state: ConsoleState, args: list[str]):
    """Show current session details."""
    if not state.session_id:
        ui.print_warn("No active session.")
        ui.print_info("Run 'sessions' to list existing ones, or 'new <name>' to create one.")
        return
 
    s = sm.get_session(state.session_id)
    actions = sm.get_session_actions(state.session_id)
    tactics = sorted({a["tactic"] for a in actions if a.get("tactic")})
 
    ui.print_section(f"Session: {s['name']}")
    print(f"  {ui.bold('ID:')}           {s['id']}")
    print(f"  {ui.bold('Name:')}         {s['name']}")
    print(f"  {ui.bold('Started:')}      {s['started_at'][:19].replace('T', ' ')} UTC")
    print(f"  {ui.bold('Status:')}       {ui.green('OPEN') if not s['ended_at'] else ui.dim('CLOSED')}")
    print(f"  {ui.bold('Actions:')}      {len(actions)}")
    print(f"  {ui.bold('AI tips:')}      {ui.green('ON') if state.ai_enabled else ui.dim('OFF')}")
    print(f"  {ui.bold('Dry run:')}      {ui.yellow('ON') if state.dry_run else ui.dim('OFF')}")
 
    if tactics:
        print(f"  {ui.bold('Tactics hit:')} {' · '.join(ui.yellow(t) for t in tactics)}")
 
    # Last 5 actions
    if actions:
        print(f"\n  {ui.bold('Recent actions:')}")
        for a in actions[-5:]:
            mitre = f"→ {ui.cyan(a['technique_id'])}" if a.get("technique_id") else ui.dim("→ unmapped")
            status = ui.green("✔") if a["exit_code"] == 0 else ui.red("✘")
            print(f"    {status} {ui.dim(a['command'][:45])} {mitre}")
    print()
 
 
def _cmd_report(state: ConsoleState, args: list[str]):
    """Export session report to Markdown."""
    if not state.session_id:
        ui.print_error("No active session.")
        return
 
    s = sm.get_session(state.session_id)
    default_name = f"{s['name'].replace(' ', '_')}_report.md"
    output = args[0] if args else default_name
 
    try:
        path = reporter.save_report(state.session_id, output)
        ui.print_success(f"Report saved: {ui.cyan(os.path.abspath(path))}")
        ui.print_info("Open it in VS Code, Obsidian, or any Markdown viewer.")
    except Exception as e:
        ui.print_error(f"Failed: {e}")
 
 
def _cmd_ai(state: ConsoleState, args: list[str]):
    """Toggle AI enrichment tips."""
    if not args or args[0] not in ("on", "off"):
        ui.print_error("Usage: ai on|off")
        return
    state.ai_enabled = args[0] == "on"
    status = ui.green("ON") if state.ai_enabled else ui.dim("OFF")
    ui.print_success(f"AI tips: {status}")
 
 
def _cmd_dry(state: ConsoleState, args: list[str]):
    """Toggle dry-run mode."""
    if not args or args[0] not in ("on", "off"):
        ui.print_error("Usage: dry on|off")
        return
    state.dry_run = args[0] == "on"
    status = ui.yellow("ON — commands will be logged but NOT executed") if state.dry_run else ui.dim("OFF — commands execute for real")
    ui.print_success(f"Dry run: {status}")
 
 
def _cmd_mitre(state: ConsoleState, args: list[str]):
    """Manually look up MITRE mapping for any command string."""
    if not args:
        ui.print_error("Usage: mitre <command to look up>")
        return
 
    cmd = " ".join(args)
    result = map_command(cmd)
    if result:
        print(f"\n  {ui.bold(ui.magenta('MITRE ATT&CK mapping for:'))} {ui.cyan(cmd)}")
        print(f"  ├─ Tactic:     {ui.yellow(result['tactic'])}")
        print(f"  ├─ Technique:  {result['technique_id']} — {result['technique_name']}")
        conf = result["confidence"]
        conf_color = ui.green if conf >= 0.90 else ui.yellow if conf >= 0.70 else ui.blue
        print(f"  └─ Confidence: {conf_color(f'{round(conf*100)}%')}")
    else:
        print(f"\n  {ui.dim(f'No MITRE mapping found for: {cmd}')}")
    print()
 
 
def _cmd_coverage(state: ConsoleState, args: list[str]):
    """Show MITRE rule coverage statistics."""
    stats = get_coverage_stats()
    ui.print_section("MITRE ATT&CK Coverage")
    print(f"  {ui.bold('Rules:')}   {stats['total_rules']}")
    print(f"  {ui.bold('Tactics:')} {stats['tactics_covered']}")
    print()
    for t in stats["tactics"]:
        print(f"    {ui.yellow('•')} {t}")
    print()
 
 
def _cmd_history(state: ConsoleState, args: list[str]):
    """Show readline history for this console session."""
    if not _READLINE:
        ui.print_warn("readline not available — no history.")
        return
    length = readline.get_current_history_length()
    if length == 0:
        ui.print_info("No history yet.")
        return
    ui.print_section("Command History")
    start = max(1, length - 30)   # show last 30
    for i in range(start, length + 1):
        print(f"  {ui.dim(str(i).rjust(4))}  {readline.get_history_item(i)}")
    print()
 
 
def _cmd_clear(state: ConsoleState, args: list[str]):
    os.system("clear" if os.name != "nt" else "cls")
 
 
# ── Built-in command dispatch table ─────────────────────────────────────────
 
BUILTINS: dict = {
    "help":     _cmd_help,
    "?":        _cmd_help,
    "sessions": _cmd_sessions,
    "use":      _cmd_use,
    "new":      _cmd_new,
    "end":      _cmd_end,
    "show":     _cmd_show,
    "info":     _cmd_show,
    "report":   _cmd_report,
    "ai":       _cmd_ai,
    "dry":      _cmd_dry,
    "mitre":    _cmd_mitre,
    "coverage": _cmd_coverage,
    "history":  _cmd_history,
    "clear":    _cmd_clear,
    "cls":      _cmd_clear,
}
 
EXIT_CMDS = {"exit", "quit", "q", "bye"}
 
 
# ── Shell command executor ───────────────────────────────────────────────────
 
def _execute_shell_command(line: str, state: ConsoleState):
    """
    LESSON: The core loop action
    When the user types something that isn't a built-in, we:
      1. Map it to MITRE ATT&CK immediately (fast, local)
      2. Print the mapping so the operator sees it BEFORE execution
      3. Execute the command (unless dry_run)
      4. Stream output line-by-line as it arrives
      5. Log everything to the active session DB
      6. Optionally print AI tips
 
    This mirrors how msfconsole shows module info before running it.
    """
    if not state.session_id:
        ui.print_warn("No active session — command will execute but NOT be logged.")
        ui.print_info("Run 'new <name>' to start a session first.")
 
    # ── Step 1: MITRE mapping (instant) ──────────────────────────────────────
    mapping = map_command(line)
    if mapping:
        conf = mapping["confidence"]
        conf_color = ui.green if conf >= 0.90 else ui.yellow if conf >= 0.70 else ui.blue
        print(
            f"  {ui.magenta('MITRE')} "
            f"{ui.yellow(mapping['tactic'])} / "
            f"{ui.cyan(mapping['technique_id'])} — {mapping['technique_name']} "
            f"[{conf_color(f'{round(conf*100)}%')}]"
        )
    else:
        print(f"  {ui.dim('MITRE  no mapping found')}")
 
    # ── Step 2: Execute (or skip if dry_run) ─────────────────────────────────
    stdout_lines = []
    stderr_text = ""
    exit_code = 0
 
    if state.dry_run:
        print(f"  {ui.yellow('[DRY RUN]')} command not executed")
    else:
        print(f"  {ui.dim('executing...')}")
        try:
            proc = subprocess.Popen(
                line,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
 
            # LESSON: Real-time streaming output
            # We read stdout line-by-line as the process runs.
            # This is what makes the console feel live — you see
            # nmap output appearing as it scans, not all at once.
            print()
            for raw_line in proc.stdout:
                clean = raw_line.rstrip()
                print(f"  {ui.dim(clean)}")
                stdout_lines.append(clean)
 
            proc.wait(timeout=60)
            stderr_text = proc.stderr.read().strip()
            exit_code = proc.returncode
 
            if exit_code == 0:
                print(f"\n  {ui.green('✔')} exit:{exit_code}")
            else:
                print(f"\n  {ui.red('✘')} exit:{exit_code}")
                if stderr_text:
                    print(f"  {ui.red('stderr:')} {stderr_text[:200]}")
 
        except subprocess.TimeoutExpired:
            proc.kill()
            stderr_text = "[izanagi] Timed out after 60s"
            exit_code = -1
            print(f"  {ui.red('✘')} timed out")
        except Exception as exc:
            stderr_text = str(exc)
            exit_code = -2
            print(f"  {ui.red('✘')} {exc}")
 
    # ── Step 3: Log to database ───────────────────────────────────────────────
    if state.session_id:
        from izanagi.session import _ai_enrich
        ai_data = _ai_enrich(line, mapping) if (state.ai_enabled and mapping) else {}
 
        from izanagi.db import get_connection
        import datetime as _dt
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO actions
                   (session_id,command,stdout,stderr,exit_code,executed_at,
                    tactic,technique_id,technique_name,ai_summary,ai_red_tip,ai_blue_tip,confidence)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    state.session_id, line,
                    "\n".join(stdout_lines), stderr_text, exit_code,
                    _dt.datetime.utcnow().isoformat(),
                    mapping["tactic"] if mapping else None,
                    mapping["technique_id"] if mapping else None,
                    mapping["technique_name"] if mapping else None,
                    ai_data.get("summary"), ai_data.get("red_tip"), ai_data.get("blue_tip"),
                    mapping["confidence"] if mapping else None,
                ),
            )
            conn.commit()
            state.action_count += 1
        finally:
            conn.close()
 
        # ── Step 4: AI tips ────────────────────────────────────────────────
        if state.ai_enabled and mapping:
            ai_data = _ai_enrich(line, mapping)
            print()
            if ai_data.get("red_tip"):
                print(f"  {ui.red('🔴')} {ai_data['red_tip']}")
            if ai_data.get("blue_tip"):
                print(f"  {ui.blue('🔵')} {ai_data['blue_tip']}")
 
    print()
 
 
# ── Readline setup ────────────────────────────────────────────────────────────
 
def _setup_readline(state: ConsoleState):
    """
    LESSON: readline history persistence
    readline.read_history_file() loads previous sessions' history.
    readline.write_history_file() saves it when we exit.
    readline.set_history_length() caps it at N entries.
 
    Tab completion: we register a completer function that returns
    possible completions for the current word prefix.
    """
    if not _READLINE:
        return
 
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
 
    # Load previous history
    try:
        readline.read_history_file(HISTORY_FILE)
    except FileNotFoundError:
        pass
 
    readline.set_history_length(500)
 
    # Tab completion — completes built-in command names
    all_cmds = list(BUILTINS.keys()) + list(EXIT_CMDS) + ["ai on", "ai off", "dry on", "dry off"]
 
    def completer(text, state_idx):
        options = [c for c in all_cmds if c.startswith(text)]
        return options[state_idx] if state_idx < len(options) else None
 
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
 
 
def _save_readline():
    if _READLINE:
        try:
            readline.write_history_file(HISTORY_FILE)
        except Exception:
            pass
 
 
# ── Main console loop ─────────────────────────────────────────────────────────
 
def run_console(initial_session_id: int | None = None):
    """
    LESSON: The REPL loop
    The entire console is one while True loop:
      1. Print prompt, wait for input (input())
      2. Strip whitespace, skip blank lines
      3. Check for exit commands
      4. Check for built-in commands (split on first space)
      5. Fall through to shell execution
      6. Repeat
 
    KeyboardInterrupt (Ctrl+C) clears the current line.
    EOFError (Ctrl+D) exits cleanly.
    """
    init_db()
    state = ConsoleState()
    _setup_readline(state)
 
    # Auto-activate session if passed in
    if initial_session_id:
        s = sm.get_session(initial_session_id)
        if s and not s["ended_at"]:
            state.session_id = s["id"]
            state.session_name = s["name"]
            state.action_count = len(sm.get_session_actions(s["id"]))
 
    # Banner
    print(ui.cyan(BANNER_CONSOLE))
    print(ui.bold("  Quick start:"))
    print(f"  {ui.dim('new <name>')}      — create + activate a session")
    print(f"  {ui.dim('sessions')}         — list existing sessions")
    print(f"  {ui.dim('use <id|name>')}   — activate an existing session")
    print(f"  {ui.dim('help')}             — all commands")
    print(f"  {ui.dim('exit')}             — quit")
    print()
    print(f"  {ui.yellow('AI tips are ON.')} Type {ui.cyan('ai off')} to silence them.")
    print(f"  Commands execute {ui.green('LIVE')}. Type {ui.cyan('dry on')} to log-only mode.")
    print()
 
    if state.session_id:
        ui.print_success(f"Auto-attached to session: {ui.bold(state.session_name)}")
 
    while True:
        try:
            line = input(state.prompt).strip()
        except KeyboardInterrupt:
            # Ctrl+C = cancel current line, don't exit
            print(f"  {ui.dim('(Ctrl+C — type exit to quit)')}")
            continue
        except EOFError:
            # Ctrl+D = exit
            print()
            break
 
        if not line:
            continue
 
        # ── Exit ──────────────────────────────────────────────────────────────
        if line.lower() in EXIT_CMDS:
            break
 
        # ── Parse built-in ────────────────────────────────────────────────────
        parts = line.split()
        cmd_name = parts[0].lower()
        cmd_args = parts[1:]
 
        if cmd_name in BUILTINS:
            BUILTINS[cmd_name](state, cmd_args)
        else:
            # ── Shell command ─────────────────────────────────────────────────
            _execute_shell_command(line, state)
 
    # ── Exit cleanup ──────────────────────────────────────────────────────────
    _save_readline()
    elapsed = datetime.datetime.utcnow() - state.start_time
    mins = int(elapsed.total_seconds() // 60)
    print(f"\n  {ui.dim(f'Session time: {mins}m  •  Actions logged: {state.action_count}')}")
    print(f"  {ui.cyan('イザナギ')} {ui.dim('console closed.')}\n")