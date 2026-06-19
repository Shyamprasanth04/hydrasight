"""
Default configuration values, colour palette, phase definitions
and all module-level constants for HydraSight.
"""
from typing import Any

# ── version ───────────────────────────────────────────────────────────────────
VERSION  = "4.0.0"
CODENAME = "OBSIDIAN"
APP_NAME = "HydraSight"


# ── colour palette ────────────────────────────────────────────────────────────
class P:
    """Rich hex colour constants."""

    PRIMARY = "#00D67D"
    BRIGHT  = "#00FF94"
    RED     = "#FF5C5C"
    AMBER   = "#FFA94D"
    YELLOW  = "#E8C547"
    BLUE    = "#7AB8E0"
    TEXT    = "#E0E0E8"
    MUTED   = "#9090A8"
    DIM     = "#8888A8"
    WHITE   = "#FFFFFF"
    GHOST   = "#1A1A24"
    DARK    = "#0D0D14"


# ── severity map ──────────────────────────────────────────────────────────────
SEV: dict[str, tuple[str, str]] = {
    "CRITICAL": (P.RED,    "CRIT"),
    "HIGH"    : (P.AMBER,  "HIGH"),
    "MEDIUM"  : (P.YELLOW, " MED"),
    "LOW"     : (P.BLUE,   " LOW"),
    "INFO"    : (P.MUTED,  "INFO"),
}

# ── tool → display label ──────────────────────────────────────────────────────
TOOL_LABELS: dict[str, str] = {
    "nmap_scan"     : "nmap",
    "gobuster_scan" : "gobuster",
    "nikto_scan"    : "nikto",
    "whatweb_scan"  : "whatweb",
    "post_exploit"  : "msfconsole",
    "smb_enum"      : "enum4linux",
    "ssh_brute"     : "hydra-ssh",
    "ftp_brute"     : "hydra-ftp",
    "run_command"   : "shell",
}

# ── phase definitions ─────────────────────────────────────────────────────────
PHASE_DEFS: dict[str, tuple[str, str]] = {
    "RECON"        : ("Reconnaissance",      P.BLUE),
    "DEEP_SCAN"    : ("Deep Port Scan",      P.BLUE),
    "FTP_CHECK"    : ("FTP Analysis",        P.BLUE),
    "SMB_CHECK"    : ("SMB Analysis",        P.RED),
    "SSH_CHECK"    : ("SSH Analysis",        P.AMBER),
    "WEB_FINGER"   : ("Web Fingerprinting",  P.YELLOW),
    "WEB_DIR"      : ("Directory Discovery", P.YELLOW),
    "WEB_VULN"     : ("Web Vulnerability",   P.AMBER),
    "VULN_SCAN"    : ("Vulnerability Scan",  P.AMBER),
    "EXPLOIT"      : ("Exploitation",        P.RED),
    "POST_EXPLOIT" : ("Post-Exploitation",   P.PRIMARY),
    "HASH_CRACK"   : ("Credential Recovery", P.PRIMARY),
}

# ── per-tool HTTP timeouts (seconds) ──────────────────────────────────────────
TOOL_TIMEOUTS: dict[str, int] = {
    "nmap_scan"     : 600,
    "nikto_scan"    : 220,
    "gobuster_scan" : 300,
    "post_exploit"  : 420,
    "smb_enum"      : 240,
    "ssh_brute"     : 600,
    "ftp_brute"     : 600,
    "whatweb_scan"  : 60,
    "run_command"   : 300,
}

NIKTO_MAXTIME = 180

# ── config schema ─────────────────────────────────────────────────────────────
_CONFIG_ALLOWED_KEYS = frozenset({
    "ollama_url", "kali_api_url", "model", "context_size", "max_retries",
    "retry_delay", "verbosity", "log_file", "output_dir", "lport",
    "token_budget", "auto_pdf", "auto_save", "scan_range",
    "deep_scan_range", "wordlist", "rockyou_path",
    "execution_mode",   # confirm | auto | never
})

DEFAULT_CONFIG: dict[str, Any] = {
    "ollama_url"      : "http://localhost:11434",
    "kali_api_url"    : "http://127.0.0.1:5000",
    "model"           : "qwen2.5:7b",
    "context_size"    : 8192,
    "max_retries"     : 3,
    "retry_delay"     : 2.0,
    "verbosity"       : 1,
    "log_file"        : "hydrasight.log",
    "output_dir"      : "hydrasight_output",
    "lport"           : 4444,
    "token_budget"    : 6000,
    "auto_pdf"        : True,
    "auto_save"       : True,
    "scan_range"      : "1-1000",
    "deep_scan_range" : "1-65535",
    "wordlist"        : "/usr/share/wordlists/dirb/common.txt",
    "rockyou_path"    : "/usr/share/wordlists/rockyou.txt",
    # Natural-language execution mode:
    #   confirm (default) — always ask before running a NL-initiated action
    #   auto             — high-confidence requests run without confirmation
    #   never            — NL never executes tools, only explains/suggests
    "execution_mode"  : "confirm",
}

# ── banner ────────────────────────────────────────────────────────────────────
BANNER = """\
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║      ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗                ║
    ║      ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗               ║
    ║      ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║               ║
    ║      ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║               ║
    ║      ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║               ║
    ║      ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝               ║
    ║         ███████╗██╗ ██████╗ ██╗  ██╗████████╗                ║
    ║         ██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝                ║
    ║         ███████╗██║██║  ███╗███████║   ██║                   ║
    ║         ╚════██║██║██║   ██║██╔══██║   ██║                   ║
    ║         ███████║██║╚██████╔╝██║  ██║   ██║                   ║
    ║         ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝                   ║
    ║                                                               ║
    ║         AI-Orchestrated Penetration Testing Framework         ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝"""

# ── AI system prompt ──────────────────────────────────────────────────────────
SYSTEM_PROMPT = """\
You are HydraSight, an AI penetration testing assistant.
Respond with ONE valid JSON tool call. No markdown. No explanation.

CRITICAL RULES:
1. ALWAYS use the exact target IP given in the task — never invent IPs
2. Respond with RAW JSON only — no code fences, no preamble
3. Use exactly one tool per response
4. For conversational messages respond with plain text — NOT a tool call
5. For SMB vulnerability checks use nmap_scan with smb-vuln scripts NOT nikto
6. For SSH checks use nmap_scan with ssh-auth-methods NOT nikto
7. For FTP checks use nmap_scan with ftp-anon scripts NOT nikto
8. For SMB share enumeration use run_command with enum4linux NOT gobuster

TOOLS:
  nmap_scan      {"tool":"nmap_scan","args":{"target":"IP","scan_type":"-sV -sC","ports":"1-1000","additional_args":"-T4 -Pn"}}
  gobuster_scan  {"tool":"gobuster_scan","args":{"url":"http://IP","wordlist":"/usr/share/wordlists/dirb/common.txt","extensions":""}}
  nikto_scan     {"tool":"nikto_scan","args":{"target":"IP","port":80}}
  whatweb_scan   {"tool":"whatweb_scan","args":{"url":"http://IP"}}
  post_exploit   {"tool":"post_exploit","args":{"target":"IP","module":"exploit/...","rport":PORT,"lport":4444,"payload":"...","commands":"cmd1;cmd2"}}
  run_command    {"tool":"run_command","args":{"command":"bash command here"}}

When analysing tool output use EXACTLY this format (plain text, no JSON):
PORTS: comma separated list or none
VULNS: list with severity or none
CREDS: any credentials found or none
SESSIONS: session info or none
NOTES: OS, versions, key observations
"""

# ── chat-only system prompt ───────────────────────────────────────────────────
# Used exclusively by ChatAIClient / ChatController.
# MUST NOT instruct the model to produce JSON tool calls.
CHAT_SYSTEM_PROMPT = """\
You are HydraSight, a knowledgeable cybersecurity assistant.
You help operators understand security concepts, interpret findings, and plan assessments.

STRICT RULES — YOU MUST FOLLOW THESE WITHOUT EXCEPTION:
1. You are in CONVERSATION MODE. You must NEVER produce JSON.
2. Never output phrases like "I cannot directly execute commands" or generic AI disclaimers.
3. Never mention unsupported tools like Nessus or OpenVAS.
4. If exploitation is not supported or not justified by findings, say so briefly and offer valid HydraSight next actions.
5. You may suggest supported HydraSight next steps (e.g. "I can enumerate SMB shares", "I can run a targeted scan").
6. Keep answers concise, operational, and firmly in your HydraSight persona.
7. Do not hallucinate tool output or scan results.
"""
