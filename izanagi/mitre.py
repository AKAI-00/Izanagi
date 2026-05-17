from typing import Optional
 
 
# ---------------------------------------------------------------------------
# Rule database — ordered from most-specific to least-specific
# More specific rules should come first so they win on ambiguous commands
# ---------------------------------------------------------------------------
RULES: list[dict] = [
 
    # ── Credential Access ───────────────────────────────────────────────────
    {
        "patterns": ["mimikatz", "invoke-mimikatz", "sekurlsa"],
        "tactic": "Credential Access",
        "id": "T1003",
        "name": "OS Credential Dumping",
        "confidence": 0.97,
    },
    {
        "patterns": ["hashdump", "lsadump", "ntds"],
        "tactic": "Credential Access",
        "id": "T1003.002",
        "name": "Security Account Manager",
        "confidence": 0.95,
    },
    {
        "patterns": ["hydra", "medusa", "crackmapexec", "spray"],
        "tactic": "Credential Access",
        "id": "T1110",
        "name": "Brute Force",
        "confidence": 0.90,
    },
 
    # ── Discovery ───────────────────────────────────────────────────────────
    {
        "patterns": ["whoami"],
        "tactic": "Discovery",
        "id": "T1033",
        "name": "System Owner/User Discovery",
        "confidence": 0.99,
    },
    {
        "patterns": ["ipconfig", "ifconfig", "ip addr", "ip a "],
        "tactic": "Discovery",
        "id": "T1016",
        "name": "System Network Configuration Discovery",
        "confidence": 0.98,
    },
    {
        "patterns": ["net user", "net localgroup", "get-localuser", "getent passwd"],
        "tactic": "Discovery",
        "id": "T1087",
        "name": "Account Discovery",
        "confidence": 0.95,
    },
    {
        "patterns": ["nmap", "masscan", "netdiscover", "arp-scan"],
        "tactic": "Discovery",
        "id": "T1046",
        "name": "Network Service Discovery",
        "confidence": 0.97,
    },
    {
        "patterns": ["ps aux", "tasklist", "get-process", "pgrep"],
        "tactic": "Discovery",
        "id": "T1057",
        "name": "Process Discovery",
        "confidence": 0.95,
    },
    {
        "patterns": ["uname -a", "systeminfo", "hostnamectl"],
        "tactic": "Discovery",
        "id": "T1082",
        "name": "System Information Discovery",
        "confidence": 0.95,
    },
    {
        "patterns": ["netstat", "ss -", "route print"],
        "tactic": "Discovery",
        "id": "T1049",
        "name": "System Network Connections Discovery",
        "confidence": 0.93,
    },
 
    # ── Lateral Movement ────────────────────────────────────────────────────
    {
        "patterns": ["psexec", "wmiexec", "smbexec"],
        "tactic": "Lateral Movement",
        "id": "T1021.002",
        "name": "SMB/Windows Admin Shares",
        "confidence": 0.96,
    },
    {
        "patterns": ["ssh ", "scp ", "sftp "],
        "tactic": "Lateral Movement",
        "id": "T1021.004",
        "name": "SSH",
        "confidence": 0.85,
    },
    {
        "patterns": ["rdp", "xfreerdp", "rdesktop"],
        "tactic": "Lateral Movement",
        "id": "T1021.001",
        "name": "Remote Desktop Protocol",
        "confidence": 0.90,
    },
 
    # ── Execution ───────────────────────────────────────────────────────────
    {
        "patterns": ["powershell", "pwsh"],
        "tactic": "Execution",
        "id": "T1059.001",
        "name": "PowerShell",
        "confidence": 0.88,
    },
    {
        "patterns": ["bash -c", "sh -c", "/bin/sh"],
        "tactic": "Execution",
        "id": "T1059.004",
        "name": "Unix Shell",
        "confidence": 0.85,
    },
    {
        "patterns": ["python -c", "python3 -c", "perl -e", "ruby -e"],
        "tactic": "Execution",
        "id": "T1059.006",
        "name": "Python / Script Interpreter",
        "confidence": 0.82,
    },
 
    # ── Privilege Escalation ────────────────────────────────────────────────
    {
        "patterns": ["sudo ", "su -", "sudo -l"],
        "tactic": "Privilege Escalation",
        "id": "T1548.003",
        "name": "Sudo and Sudo Caching",
        "confidence": 0.80,
    },
    {
        "patterns": ["suid", "find / -perm -4000", "linpeas", "winpeas"],
        "tactic": "Privilege Escalation",
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "confidence": 0.92,
    },
 
    # ── Persistence ─────────────────────────────────────────────────────────
    {
        "patterns": ["crontab", "cron.d", "at "],
        "tactic": "Persistence",
        "id": "T1053.003",
        "name": "Cron",
        "confidence": 0.88,
    },
    {
        "patterns": ["reg add", "hklm\\software\\microsoft\\windows\\currentversion\\run"],
        "tactic": "Persistence",
        "id": "T1547.001",
        "name": "Registry Run Keys / Startup Folder",
        "confidence": 0.95,
    },
 
    # ── Exfiltration ────────────────────────────────────────────────────────
    {
        "patterns": ["curl ", "wget ", "certutil"],
        "tactic": "Exfiltration",
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "confidence": 0.65,  # low — curl/wget are also legit
    },
    {
        "patterns": ["nc -", "ncat ", "netcat"],
        "tactic": "Exfiltration",
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "confidence": 0.80,
    },
 
    # ── Defense Evasion ─────────────────────────────────────────────────────
    {
        "patterns": ["history -c", "unset histfile", "export histsize=0"],
        "tactic": "Defense Evasion",
        "id": "T1070.003",
        "name": "Clear Command History",
        "confidence": 0.97,
    },
    {
        "patterns": ["shred ", "wevtutil cl", "clearev"],
        "tactic": "Defense Evasion",
        "id": "T1070",
        "name": "Indicator Removal",
        "confidence": 0.93,
    },
]
 
 
def map_command(command: str) -> Optional[dict]:
    """
    LESSON: The mapping algorithm
    1. Lowercase the command (case-insensitive matching)
    2. Walk rules in order (most-specific first)
    3. Check if ANY pattern for a rule appears in the command
    4. Return the first matching rule, or None if no match
 
    Returns a dict with keys: tactic, id, name, confidence
    """
    cmd_lower = command.lower()
 
    for rule in RULES:
        for pattern in rule["patterns"]:
            if pattern.lower() in cmd_lower:
                return {
                    "tactic": rule["tactic"],
                    "technique_id": rule["id"],
                    "technique_name": rule["name"],
                    "confidence": rule["confidence"],
                }
 
    return None  # unknown / unmapped command
 
 
def get_all_tactics() -> list[str]:
    """Return a deduplicated sorted list of all covered tactics."""
    return sorted({r["tactic"] for r in RULES})
 
 
def get_coverage_stats() -> dict:
    """Return basic stats about the rule base."""
    return {
        "total_rules": len(RULES),
        "tactics_covered": len(get_all_tactics()),
        "tactics": get_all_tactics(),
    }