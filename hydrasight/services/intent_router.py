"""
Intent router — maps freeform user text to pre-built tool-call dicts,
bypassing the AI for well-known security command patterns.
"""
import re
from typing import Optional

# Conversational input detector
_CONVO_RE = re.compile(
    r"^(hi|hello|hey|bye|goodbye|thanks|thank\s*you|how\s+are\s+you|"
    r"what\s+is\s+hydrasight|who\s+are\s+you|what\s+can\s+you\s+do|"
    r"help\s+me|good\s+morning|good\s+evening|ok|okay|sure|yes|no|"
    r"what\s+are\s+you|tell\s+me\s+about\s+yourself)$",
    re.IGNORECASE,
)

# Intent patterns → action names
_INTENT_ROUTES: list[tuple[re.Pattern, str]] = [
    (
        re.compile(
            r"ms17|eternalblue|eternal.blue|smb.vuln|smb.vulnerab",
            re.IGNORECASE,
        ),
        "nmap_smb_vuln",
    ),
    (
        re.compile(
            r"smb.shar|enum.*smb|smb.*enum|netbios|enum4linux",
            re.IGNORECASE,
        ),
        "smb_enum",
    ),
    (
        re.compile(
            r"smbclient",
            re.IGNORECASE,
        ),
        "smbclient_enum",
    ),
    (
        re.compile(
            r"check.*ssh|ssh.*check|ssh.*auth|ssh.*enum|ssh.*scan",
            re.IGNORECASE,
        ),
        "nmap_ssh",
    ),
    (
        re.compile(
            r"check.*ftp|ftp.*check|anon.*ftp|ftp.*anon|ftp.*vuln",
            re.IGNORECASE,
        ),
        "nmap_ftp",
    ),
    (
        re.compile(
            r"vuln.scan|nmap.vuln|script.vuln|vulnerabil.*scan|run.nmap.vuln",
            re.IGNORECASE,
        ),
        "nmap_vuln",
    ),
]


def is_conversational(text: str) -> bool:
    """Return True if *text* is small-talk / non-security input."""
    return bool(_CONVO_RE.match(text.strip().rstrip("?!.,")))


def route_intent(text: str, target: Optional[str]) -> Optional[dict]:
    """
    Match freeform input against security intent patterns.
    Returns a pre-built tool_call dict or None if no match.
    """
    if not target:
        return None
    for pattern, action in _INTENT_ROUTES:
        if pattern.search(text):
            if action == "nmap_smb_vuln":
                return {
                    "tool": "run_command",
                    "args": {
                        "command": (
                            f"nmap --script smb-vuln-ms17-010,"
                            f"smb-os-discovery -p 445 {target}"
                        ),
                    },
                }
            if action == "smb_enum":
                return {
                    "tool": "smb_enum",
                    "args": {"target": target},
                }
            if action == "smbclient_enum":
                return {
                    "tool": "run_command",
                    "args": {
                        "command": (
                            f"smbclient -L //{target} -N 2>&1 | head -40"
                        ),
                    },
                }
            if action == "nmap_ssh":
                return {
                    "tool": "run_command",
                    "args": {
                        "command": (
                            f"nmap --script ssh-auth-methods,"
                            f"ssh2-enum-algos -p 22 {target}"
                        ),
                    },
                }
            if action == "nmap_ftp":
                return {
                    "tool": "run_command",
                    "args": {
                        "command": (
                            f"nmap --script ftp-anon,ftp-vuln* "
                            f"-sV -p 21 {target}"
                        ),
                    },
                }
            if action == "nmap_vuln":
                return {
                    "tool": "run_command",
                    "args": {
                        "command": (
                            f"nmap -sV --script vuln -T4 -Pn "
                            f"--script-timeout 60s "
                            f"-p 21,22,80,135,139,445 {target}"
                        ),
                    },
                }
    return None
