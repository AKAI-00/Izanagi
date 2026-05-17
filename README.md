Izanagi (イザナギ)
AI Purple-Team CLI Assistant

Automates the mapping, analysis, and documentation of red team / cyber range activities in real-time.
Every command you run is instantly mapped to MITRE ATT&CK, enriched with AI tips, and logged to a structured database — generating professional engagement reports automatically.

  ___  ________  ________  ________   ________  ________  ___
 |\  \|\_____  \|\   __  \|\   ___  \|\   __  \|\   ____\|\  \
 \ \  \\|___/  /\ \  \|\  \ \  \\ \  \ \  \|\  \ \  \___|\ \  \
  \ \  \   /  / /\ \   __  \ \  \\ \  \ \   __  \ \  \  __\ \  \
   \ \  \ /  /_/__\ \  \ \  \ \  \\ \  \ \  \ \  \ \  \|\  \ \  \
    \ \__\\________\ \__\ \__\ \__\\ \__\ \__\ \__\ \_______\ \__\
     \|__|\|_______|\|__|\|__|\|__| \|__|\|__|\|__|\|_______|\|__|

  イザナギ  |  AI Purple-Team Assistant  |  v1.0.0
  For authorized security testing and research only.

What Izanagi does
During a red team engagement or CTF lab, you normally have to:

Manually note every command you ran
Look up MITRE ATT&CK techniques by hand after the fact
Write a report from scratch at the end

Izanagi does all of that automatically, in real-time, as you work.
You type commands into the Izanagi console exactly as you would in a normal terminal. Izanagi executes them, streams the live output, maps them to MITRE ATT&CK instantly, logs them to a local SQLite database, and optionally shows AI-generated red/blue team tips. At the end, one command generates a complete Markdown engagement report.

Features
CapabilityStatusInteractive console  v1.0Real-time command execution + output streaming MITRE ATT&CK auto-mapping (24 rules, 8 tactics)Confidence scoring per technique AI red/blue team tips (toggle on/off) Dry-run mode (log without executing)Session management (create, switch, close) SQLite local database (no server needed) Markdown engagement reports Arrow-key history + tab completion Zero external dependencies Linux / macOS / Windows compatible Real LLM AI analysis (OpenAI / Ollama) Phase 3PDF report export  Phase 4SIEM log correlation Phase 5

Installation
Requirements: Python 3.10 or newer. No pip packages needed.
bash# Clone or unzip the project
cd izanagi

# Option A — install as a system command
pip install -e .
izanagi console

# Option B — run directly (always works, no install needed)
python3 -m izanagi console
The database is created automatically at ~/.izanagi/izanagi.db on first run.

Project structure
izanagi/
├── izanagi/
│   ├── __init__.py       Package metadata
│   ├── __main__.py       CLI entry point (argparse)
│   ├── console.py        Interactive REPL console ← NEW
│   ├── db.py             SQLite schema & connection
│   ├── mitre.py          MITRE ATT&CK rule-based mapper
│   ├── session.py        Session + action business logic
│   ├── reporter.py       Markdown report generator
│   └── ui.py             ANSI terminal output helpers
├── tests/
│   └── test_izanagi.py   29-test suite (100% passing)
├── reports/              Generated .md reports
├── README.md
└── pyproject.toml

Quick start — Interactive Console
The console is the main way to use Izanagi. Launch it once and work from inside it.
bash  python3 -m izanagi console
You'll see:
 ___  ________  ________  ________   ________  ________  ___     
 |\  \|\_____  \|\   __  \|\   ___  \|\   __  \|\   ____\|\  \    
 \ \  \\|___/  /\ \  \|\  \ \  \\ \  \ \  \|\  \ \  \___|\ \  \   
  \ \  \   /  / /\ \   __  \ \  \\ \  \ \   __  \ \  \  __\ \  \  
   \ \  \ /  /_/__\ \  \ \  \ \  \\ \  \ \  \ \  \ \  \|\  \ \  \ 
    \ \__\\________\ \__\ \__\ \__\\ \__\ \__\ \__\ \_______\ \__\
     \|__|\|_______|\|__|\|__|\|__| \|__|\|__|\|__|\|_______|\|__|

  イザナギ  |  AI Purple-Team Assistant  |  v1.0.0
  For authorized security testing and research only.


  ╔══════════════════════════════════════════════════════════╗
  ║          イザナギ  INTERACTIVE CONSOLE  v1.0             ║
  ║       AI Purple-Team Assistant — Authorized Use Only     ║
  ╚══════════════════════════════════════════════════════════╝

  Quick start:
  new <name>      — create + activate a session
  sessions         — list existing sessions
  use <id|name>   — activate an existing session
  help             — all commands
  exit             — quit

  AI tips are ON. Type ai off to silence them.
  Commands execute LIVE. Type dry on to log-only mode.


  izanagi [no session] [AI] >
Step 1 — Create or attach a session
izanagi [no session] > new htb-active-directory
  ✔ Session created: htb-active-directory (ID: 1)

# Or attach to an existing session:
izanagi [no session] > use 1
izanagi [no session] > use htb          ← fuzzy name match works too
You can also auto-attach when launching:
bashpython3 -m izanagi console 1
Step 2 — Run commands normally
Just type any command. Izanagi executes it, streams output live, and shows the MITRE mapping instantly:
izanagi [htb-active-directory] [AI] > whoami
  MITRE  Discovery / T1033 — System Owner/User Discovery [99%]
  executing...

  root

  ✔ exit:0
  🔴 Consider obfuscating recon with LOLBins.
  🔵 Alert on rapid sequential discovery commands.

izanagi [htb-active-directory] [AI] > nmap -sC -sV 10.10.10.100
  MITRE  Discovery / T1046 — Network Service Discovery [97%]
  executing...

  Starting Nmap 7.94 ...
  PORT    STATE SERVICE VERSION
  88/tcp  open  kerberos-sec
  445/tcp open  microsoft-ds
  ...
  ✔ exit:0
Step 3 — Use dry-run for dangerous commands
Dry-run logs and maps the command without executing it. Essential for Windows-only commands on a Linux box, or genuinely dangerous operations you want documented:
izanagi [htb-active-directory] > dry on
  ✔ Dry run: ON — commands will be logged but NOT executed

izanagi [htb-active-directory] [AI] [DRY] > Invoke-Mimikatz -DumpCreds
  MITRE  Credential Access / T1003 — OS Credential Dumping [97%]
  [DRY RUN] command not executed
  🔴 Run from memory to avoid AV signatures on disk.
  🔵 Enable LSASS protection (PPL) and audit Credential Manager access.
Step 4 — Check your session status
izanagi [htb-active-directory] > show

  Session: htb-active-directory
  ID:           1
  Started:      2026-05-17 09:00:00 UTC
  Status:       OPEN
  Actions:      8
  AI tips:      ON
  Dry run:      OFF
  Tactics hit:  Credential Access · Discovery · Lateral Movement

  Recent actions:
    ✔ whoami                   → T1033
    ✔ nmap -sC -sV 10.10.10.100 → T1046
    ✔ net user administrator    → T1087
    ✔ Invoke-Mimikatz           → T1003
Step 5 — Generate the report
izanagi [htb-active-directory] > report
  ✔ Report saved: /home/akai/htb-active-directory_report.md

# Custom filename:
izanagi [htb-active-directory] > report reports/htb_ad_final.md
Step 6 — Close the session
izanagi [htb-active-directory] > end
  ✔ Session 'htb-active-directory' closed.
  ℹ Total actions logged: 12

izanagi [no session] > exit

  Session time: 47m  •  Actions logged: 12
  イザナギ console closed.

All console commands
CommandDescriptionnew <name> [notes]Create and activate a new sessionuse <id|name>Switch to an existing session (fuzzy name match)sessionsList all sessions in the databaseshowShow active session details, tactics hit, recent actionsendClose the active sessionreport [file.md]Export session as Markdown reportai on|offToggle AI red/blue tips after each commanddry on|offToggle dry-run mode (log without executing)mitre <cmd>Look up MITRE mapping for any command stringcoverageShow rule-base stats (tactics, technique count)historyShow command history for this console sessionclearClear the terminalhelpShow all commandsexit / quitExit the console<anything else>Execute in shell, map to MITRE, log to session
Keyboard shortcuts inside the console:

↑ / ↓ — scroll through command history
Tab — autocomplete built-in commands
Ctrl+C — cancel current line (doesn't exit)
Ctrl+D — exit cleanly


Classic CLI mode (without console)
The original subcommand-style interface still works if you prefer it:
bash# Manage sessions
python3 -m izanagi start-session "lab-01" --notes "HackTheBox AD"
python3 -m izanagi list-sessions
python3 -m izanagi end-session 1

# Run individual commands
python3 -m izanagi run 1 "whoami" --ai
python3 -m izanagi run 1 "nmap -sV 10.0.0.1" --ai
python3 -m izanagi run 1 "Invoke-Mimikatz" --ai --dry-run

# Reports and stats
python3 -m izanagi session-report 1 -o report.md
python3 -m izanagi mitre-stats
python3 -m izanagi delete-session 1

MITRE ATT&CK coverage
8 tactics, 24 techniques mapped via rule-based pattern matching. Confidence scores (0–100%) indicate certainty of the mapping.
TacticExample techniquesDiscoveryT1033 whoami · T1016 ipconfig · T1046 nmap · T1057 ps aux · T1082 unameCredential AccessT1003 mimikatz · T1003.002 hashdump · T1110 hydraLateral MovementT1021.002 psexec · T1021.004 ssh · T1021.001 rdpExecutionT1059.001 powershell · T1059.004 bash -c · T1059.006 python -cPrivilege EscalationT1548.003 sudo · T1548 linpeas/SUIDPersistenceT1053.003 crontab · T1547.001 registry run keysDefense EvasionT1070.003 history -c · T1070 shred/wevtutilExfiltrationT1041 netcat · T1041 curl/wget
bash# See full coverage breakdown
python3 -m izanagi console
> coverage

Report output
Every engagement report contains:

Header — session name, ID, start/end times, generated timestamp
Executive summary — total commands, MITRE-mapped count, coverage %, tactics observed
MITRE ATT&CK coverage table — techniques grouped with confidence scores and hit counts
Full action timeline — every command with timestamp, exit code, output, MITRE tag, and AI tips
Blue-team recommendations — deduplicated defensive tips from the session
Disclaimer footer

Reports are plain Markdown — open them in VS Code, Obsidian, GitHub, or convert to PDF with pandoc:
bashpandoc report.md -o report.pdf

Architecture
┌─────────────────────────┐
│   console.py  (REPL)    │  ← Interactive msfconsole-style loop
│   __main__.py (CLI)     │  ← Classic subcommand interface
└────────────┬────────────┘
             │
    ┌────────▼────────┐
    │   session.py    │  ← Business logic: create, run, log
    └────────┬────────┘
             │
   ┌─────────┴──────────┐
   │                    │
┌──▼──────┐    ┌────────▼──────┐    ┌──────────────┐
│ mitre.py│    │    db.py      │    │ reporter.py  │
│ Mapper  │    │ SQLite layer  │    │ Markdown gen │
└─────────┘    └───────────────┘    └──────────────┘
                      │
              ~/.izanagi/izanagi.db

Running tests
bashpython3 -m unittest tests/test_izanagi.py -v
# Ran 29 tests in 0.3s — OK

Roadmap
PhaseGoalStatusPhase 1Core CLI + SQLite DB CompletePhase 2MITRE mapping (24 rules, 8 tactics) CompletePhase 2.5Interactive console (msfconsole-style) CompletePhase 3Real LLM AI (OpenAI / local Ollama) NextPhase 4PDF report export PlannedPhase 5SIEM correlation, multi-operator support🔮 Future

Database
All data is stored locally in ~/.izanagi/izanagi.db. No network, no cloud, no accounts.
bash# Inspect raw data
sqlite3 ~/.izanagi/izanagi.db "SELECT id, name, started_at FROM sessions;"
sqlite3 ~/.izanagi/izanagi.db "SELECT command, tactic, technique_id, confidence FROM actions WHERE session_id=1;"
Two tables:

sessions — id, name, started_at, ended_at, notes
actions — id, session_id, command, stdout, stderr, exit_code, executed_at, tactic, technique_id, technique_name, ai_summary, ai_red_tip, ai_blue_tip, confidence


Disclaimer

Izanagi is designed for authorized security testing, CTF competitions, cyber range exercises, and security education. Always ensure you have explicit written permission before running any commands against systems you do not own. The authors accept no liability for misuse.


Izanagi (イザナギ) is the creator deity in Japanese mythology — the one who brings structure and order to chaos. Apt for a tool that brings structure to red team chaos.
