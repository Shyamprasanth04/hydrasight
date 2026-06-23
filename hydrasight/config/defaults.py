"""
Default configuration values, colour palette, phase definitions
and all module-level constants for HydraSight.
"""

from typing import Any

# ── version ───────────────────────────────────────────────────────────────────
VERSION = "4.0.0"
CODENAME = "OBSIDIAN"
APP_NAME = "HydraSight"


# ── colour palette ────────────────────────────────────────────────────────────
class P:
    """Rich hex colour constants."""

    PRIMARY = "#00D67D"
    BRIGHT = "#00FF94"
    RED = "#FF5C5C"
    AMBER = "#FFA94D"
    YELLOW = "#E8C547"
    BLUE = "#7AB8E0"
    TEXT = "#E0E0E8"
    MUTED = "#9090A8"
    DIM = "#8888A8"
    WHITE = "#FFFFFF"
    GHOST = "#1A1A24"
    DARK = "#0D0D14"


# ── severity map ──────────────────────────────────────────────────────────────
SEV: dict[str, tuple[str, str]] = {
    "CRITICAL": (P.RED, "CRIT"),
    "HIGH": (P.AMBER, "HIGH"),
    "MEDIUM": (P.YELLOW, " MED"),
    "LOW": (P.BLUE, " LOW"),
    "INFO": (P.MUTED, "INFO"),
}

# ── tool → display label ──────────────────────────────────────────────────────
TOOL_LABELS: dict[str, str] = {
    "nmap_scan": "nmap",
    "gobuster_scan": "gobuster",
    "nikto_scan": "nikto",
    "whatweb_scan": "whatweb",
    "post_exploit": "msfconsole",
    "smb_enum": "enum4linux",
    "ssh_brute": "hydra-ssh",
    "ftp_brute": "hydra-ftp",
    "run_command": "shell",
}

# ── phase definitions ─────────────────────────────────────────────────────────
PHASE_DEFS: dict[str, tuple[str, str]] = {
    "RECON": ("Reconnaissance", P.BLUE),
    "DEEP_SCAN": ("Deep Port Scan", P.BLUE),
    "FTP_CHECK": ("FTP Analysis", P.BLUE),
    "SMB_CHECK": ("SMB Analysis", P.RED),
    "SSH_CHECK": ("SSH Analysis", P.AMBER),
    "WEB_FINGER": ("Web Fingerprinting", P.YELLOW),
    "WEB_DIR": ("Directory Discovery", P.YELLOW),
    "WEB_VULN": ("Web Vulnerability", P.AMBER),
    "VULN_SCAN": ("Vulnerability Scan", P.AMBER),
    "EXPLOIT": ("Exploitation", P.RED),
    "POST_EXPLOIT": ("Post-Exploitation", P.PRIMARY),
    "HASH_CRACK": ("Credential Recovery", P.PRIMARY),
}

# ── per-tool HTTP timeouts (seconds) ──────────────────────────────────────────
TOOL_TIMEOUTS: dict[str, int] = {
    "nmap_scan": 600,
    "nikto_scan": 220,
    "gobuster_scan": 300,
    "post_exploit": 420,
    "smb_enum": 240,
    "ssh_brute": 600,
    "ftp_brute": 600,
    "whatweb_scan": 60,
    "run_command": 300,
}

NIKTO_MAXTIME = 180

# ── config schema ─────────────────────────────────────────────────────────────
_CONFIG_ALLOWED_KEYS = frozenset(
    {
        "ollama_url",
        "kali_api_url",
        "model",
        "context_size",
        "max_retries",
        "retry_delay",
        "verbosity",
        "log_file",
        "output_dir",
        "lport",
        "token_budget",
        "auto_pdf",
        "auto_save",
        "scan_range",
        "deep_scan_range",
        "wordlist",
        "rockyou_path",
        "execution_mode",  # confirm | auto | never
        "ollama_options_orchestrator",  # per-call Ollama options for tool orchestration
        "ollama_options_chat",          # per-call Ollama options for conversational path
    }
)

# ── Ollama runtime options ────────────────────────────────────────────────────
# Orchestration path: deterministic, schema-reliable, concise.
# think=false disables Qwen3 chain-of-thought server-side (cleaner JSON output).
_DEFAULT_OLLAMA_OPTIONS_ORCHESTRATOR: dict[str, Any] = {
    "temperature": 0.15,
    "top_p": 0.85,
    "top_k": 40,
    "repeat_penalty": 1.08,
    "num_ctx": 8192,
    "num_predict": 700,
    "think": False,  # disable Qwen3 thinking tokens on orchestration path
}

# Chat path: helpful, calm prose. Slightly warmer than orchestration.
_DEFAULT_OLLAMA_OPTIONS_CHAT: dict[str, Any] = {
    "temperature": 0.35,
    "top_p": 0.9,
    "top_k": 50,
    "repeat_penalty": 1.05,
    "num_ctx": 8192,
    "num_predict": 500,
}

DEFAULT_CONFIG: dict[str, Any] = {
    "ollama_url": "http://localhost:11434",
    "kali_api_url": "http://127.0.0.1:5000",
    "model": "qcwind/qwen3-8b-instruct-Q4-K-M:latest",
    "context_size": 8192,
    "max_retries": 3,
    "retry_delay": 2.0,
    "verbosity": 1,
    "log_file": "hydrasight.log",
    "output_dir": "hydrasight_output",
    "lport": 4444,
    "token_budget": 6000,
    "auto_pdf": True,
    "auto_save": True,
    "scan_range": "1-1000",
    "deep_scan_range": "1-65535",
    "wordlist": "/usr/share/wordlists/dirb/common.txt",
    "rockyou_path": "/usr/share/wordlists/rockyou.txt",
    # Natural-language execution mode:
    #   confirm (default) — always ask before running a NL-initiated action
    #   auto             — high-confidence requests run without confirmation
    #   never            — NL never executes tools, only explains/suggests
    "execution_mode": "confirm",
    "ollama_options_orchestrator": _DEFAULT_OLLAMA_OPTIONS_ORCHESTRATOR,
    "ollama_options_chat": _DEFAULT_OLLAMA_OPTIONS_CHAT,
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
Output ONE valid JSON tool call. No markdown fences. No preamble. No think tags.

RULES:
1. Use the exact target IP from the task. Never invent IPs.
2. Output RAW JSON only — no ```json, no <think>, no explanation before or after.
3. One tool per response.
4. For analysis requests respond in plain text (no JSON).
5. SMB vuln checks: nmap_scan with smb-vuln scripts — NOT nikto.
6. SSH checks: nmap_scan with ssh-auth-methods — NOT nikto.
7. FTP checks: nmap_scan with ftp-anon scripts — NOT nikto.
8. SMB share enumeration: run_command with enum4linux — NOT gobuster.

TOOLS:
  nmap_scan      {"tool":"nmap_scan","args":{"target":"IP","scan_type":"-sV -sC","ports":"1-1000","additional_args":"-T4 -Pn"}}
  gobuster_scan  {"tool":"gobuster_scan","args":{"url":"http://IP","wordlist":"/usr/share/wordlists/dirb/common.txt","extensions":""}}
  nikto_scan     {"tool":"nikto_scan","args":{"target":"IP","port":80}}
  whatweb_scan   {"tool":"whatweb_scan","args":{"url":"http://IP"}}
  post_exploit   {"tool":"post_exploit","args":{"target":"IP","module":"exploit/...","rport":PORT,"lport":4444,"payload":"...","commands":"cmd1;cmd2"}}
  run_command    {"tool":"run_command","args":{"command":"bash command here"}}

For tool output analysis use EXACTLY this plain-text format:
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
You are HydraSight, a cybersecurity operator assistant. You help interpret findings and plan next steps.

RULES:
1. CONVERSATION MODE only. Never produce JSON or tool calls.
2. Never say "I cannot directly execute commands" or similar AI disclaimers.
3. Never mention tools not supported by HydraSight (Nessus, OpenVAS, etc.).
4. Suggest only real HydraSight actions: autopwn, scan, verify, suggest, plan, conclusion.
5. If exploitation is not justified by findings, say so and suggest what to do instead.
6. Be concise and operational. Do not pad answers.
7. Never invent scan output, credentials, or tool results.
"""
