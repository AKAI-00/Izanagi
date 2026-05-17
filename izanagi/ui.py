import sys
import os
_USE_COLOR = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")=="1"

def _c(code:str,text:str) -> str:
    if _USE_COLOR:
        
        return f"\033[{code}m{text}\033[0m"
    return text

#color helpers
def red(t: str) -> str: return _c("91", t)
def green(t: str) -> str: return _c("92",t)
def yellow(t: str) -> str: return _c("93",t)
def blue(t: str) -> str: return _c("94",t)
def cyan(t: str) -> str: return _c("96",t)
def magenta(t: str) -> str: return _c("95",t)
def bold(t: str) -> str: return _c("1",t)
def dim(t: str) -> str: return _c("2",t)
def white(t: str) -> str: return _c("97",t)

BANNER = r"""
  ___  ________  ________  ________   ________  ________  ___     
 |\  \|\_____  \|\   __  \|\   ___  \|\   __  \|\   ____\|\  \    
 \ \  \\|___/  /\ \  \|\  \ \  \\ \  \ \  \|\  \ \  \___|\ \  \   
  \ \  \   /  / /\ \   __  \ \  \\ \  \ \   __  \ \  \  __\ \  \  
   \ \  \ /  /_/__\ \  \ \  \ \  \\ \  \ \  \ \  \ \  \|\  \ \  \ 
    \ \__\\________\ \__\ \__\ \__\\ \__\ \__\ \__\ \_______\ \__\
     \|__|\|_______|\|__|\|__|\|__| \|__|\|__|\|__|\|_______|\|__|
"""

def print_banner():
    print(cyan(BANNER))
    print(bold("  イザナギ  |  AI Purple-Team Assistant  |  v1.0.0"))
    print(dim("  For authorized security testing and research only.\n"))
   
def print_success(msg: str):
    print(f"  {green('✔')} {msg}")
 
def print_error(msg: str):
    print(f"  {red('✘')} {msg}", file=sys.stderr)
 
def print_info(msg: str):
    print(f"  {blue('ℹ')} {msg}")
 
def print_warn(msg: str):
    print(f"  {yellow('⚠')} {msg}")

 
def print_section(title: str):
    width = 60
    print(f"\n{bold(cyan('─' * width))}")
    print(f"  {bold(white(title))}")
    print(f"{bold(cyan('─' * width))}")
 
 
def print_session_table(sessions: list[dict]):
    """Pretty-print a list of sessions."""
    if not sessions:
        print_warn("No sessions found.")
        return
 
    print_section("Sessions")
    header = f"  {'ID':>4}  {'Name':<25}  {'Started':<22}  {'Status':<10}"
    print(bold(header))
    print(dim("  " + "─" * 68))
 
    for s in sessions:
        status = green("open") if not s["ended_at"] else dim("closed")
        started = s["started_at"][:19].replace("T", " ") if s["started_at"] else "—"
        name = s["name"][:25]
        print(f"  {s['id']:>4}  {name:<25}  {started:<22}  {status}")
 
    print()
 
 
def print_action_result(action: dict):
    """Display the result of a single action execution."""
    print_section(f"Action #{action['id']}")
 
    print(f"  {bold('Command:')} {cyan(action['command'])}")
    print(f"  {bold('Exit code:')} {green(str(action['exit_code'])) if action['exit_code'] == 0 else red(str(action['exit_code']))}")
    print(f"  {bold('Executed:')} {action['executed_at'][:19].replace('T', ' ')} UTC")
 
    # MITRE result
    if action["technique_id"]:
        conf = action["confidence"] or 0
        conf_color = green if conf >= 0.90 else yellow if conf >= 0.70 else blue
        print()
        print(f"  {bold(magenta('MITRE ATT&CK'))}")
        print(f"  ├─ Tactic:    {yellow(action['tactic'])}")
        print(f"  ├─ Technique: {action['technique_id']} — {action['technique_name']}")
        print(f"  └─ Confidence: {conf_color(f'{round(conf*100)}%')}")
    else:
        print(f"\n  {dim('No MITRE mapping found.')}")
 
    # Output
    if action["stdout"]:
        print(f"\n  {bold('Output:')}")
        for line in action["stdout"].split("\n")[:10]:
            print(f"  │ {dim(line)}")
        if action["stdout"].count("\n") > 10:
            print(f"  │ {dim('...(truncated)')}")
 
    if action["stderr"] and action["exit_code"] != 0:
        print(f"\n  {bold(red('Errors:'))}")
        for line in action["stderr"].split("\n")[:5]:
            print(f"  │ {red(line)}")
 
    # AI tips
    if action.get("ai_summary"):
        print(f"\n  {bold('🤖 AI Summary:')}")
        print(f"  {dim(action['ai_summary'])}")
    if action.get("ai_red_tip"):
        print(f"\n  {red('🔴 Red Tip:')} {action['ai_red_tip']}")
    if action.get("ai_blue_tip"):
        print(f"\n  {blue('🔵 Blue Tip:')} {action['ai_blue_tip']}")
 
    print()