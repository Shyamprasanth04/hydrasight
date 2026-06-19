"""
IntentClassifier — deterministic, AI-free classification of user input.

Classifies natural language input into one of six intent labels:

  CHAT           — small talk, greetings, generic questions
  EXPLAIN        — knowledge / explanation requests
  CLARIFY        — ambiguous operational request — ask follow-up
  SUGGEST_ACTION — user wants recommendations, not immediate execution
  EXECUTE_ACTION — user clearly wants a tool run
  PLAN           — user wants a dry-run roadmap

Classification is PURELY rule-based and pattern-based. No AI calls are made
here. This guarantees fast, deterministic, predictable classification.

Each classification result includes:
  - intent label
  - confidence  (0.0–1.0)
  - extracted_ip
  - extracted_ports (string range, e.g. "1-500")
  - extracted_flags (list of nmap-style flags)
  - tool_hint (nmap_scan | smb_check | ftp_check | ssh_check | vuln_scan |
                dir_enum | autopwn | None)
  - requires_confirmation (bool, based on mode + confidence)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class Intent(Enum):
    CHAT           = "chat"
    EXPLAIN        = "explain"
    CLARIFY        = "clarify"
    SUGGEST_ACTION = "suggest_action"
    EXECUTE_ACTION = "execute_action"
    PLAN           = "plan"
    # Operational meta-intents — routed to internal HydraSight commands
    EXECUTE_PLAN   = "execute_plan"    # "do all planned stuff", "run the plan"
    VERIFY_FINDINGS= "verify_findings" # "verify findings", "verify vulns"
    SHOW_SUGGESTIONS = "show_suggestions" # "suggest next step", "what next"
    SHOW_CONCLUSION  = "show_conclusion"  # "conclusion", "summarize outcome"


@dataclass
class IntentResult:
    intent       : Intent
    confidence   : float                    # 0.0 – 1.0
    extracted_ip : Optional[str]   = None
    extracted_ports: Optional[str] = None  # e.g. "1-500", "80,443", "all"
    extracted_flags: list[str]     = field(default_factory=list)
    tool_hint    : Optional[str]   = None  # nmap_scan, smb_check, …
    summary      : str             = ""    # human-readable one-liner
    clarify_question: Optional[str] = None

    @property
    def has_target(self) -> bool:
        return bool(self.extracted_ip)

    @property
    def is_operational(self) -> bool:
        return self.intent in (
            Intent.EXECUTE_ACTION, Intent.SUGGEST_ACTION, Intent.CLARIFY
        )

    @property
    def is_safe(self) -> bool:
        """True if this result can NEVER lead to tool execution."""
        return self.intent in (Intent.CHAT, Intent.EXPLAIN, Intent.PLAN)


# ── regex helpers ─────────────────────────────────────────────────────────────

_IP_RE = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)
_PORT_RANGE_RE = re.compile(
    r"\b(?:ports?\s+)?"
    r"(\d{1,5})\s*(?:to|-)\s*(\d{1,5})\b",
    re.IGNORECASE,
)
_PORT_LIST_RE = re.compile(
    r"\b(?:port(?:s)?\s+)([\d,\s]+)\b",
    re.IGNORECASE,
)
_FLAG_RE = re.compile(r"\B(-s[SAUVFXNP]|-[OopPnA]|-p(?:\s+\S+)?)\b")
_NMAP_FLAG_WORDS = {
    "syn"        : "-sS",
    "syn scan"   : "-sS",
    "stealth"    : "-sS",
    "version"    : "-sV",
    "version detect": "-sV",
    "os detect"  : "-O",
    "os detection": "-O",
    "os"         : "-O",
    "aggressive" : "-A",
    "udp"        : "-sU",
    "no ping"    : "-Pn",
    "fast"       : "-T4",
}


# ── explain keyword sets ──────────────────────────────────────────────────────

_EXPLAIN_TRIGGERS = frozenset({
    "what is", "what are", "explain", "describe", "define", "tell me about",
    "how does", "how do", "why does", "why did", "why is", "why are",
    "what does", "what do", "what happened", "help me understand",
    "difference between", "compare", "meaning of", "definition",
    "how should i", "how can i", "what should i", "what would you recommend",
    "what are the implications", "what does it mean", "what does port",
    "should i", "is port", "what is the risk", "tell me",
    "can you explain", "could you explain",
})

_CHAT_TRIGGERS = frozenset({
    "hey", "hi", "hello", "yo", "sup", "good morning", "good evening",
    "good afternoon", "thanks", "thank you", "cheers", "bye", "goodbye",
    "ok", "okay", "sure", "cool", "nice", "great", "awesome",
    "how are you", "who are you", "what are you", "what can you do",
})

_PLAN_TRIGGERS = frozenset({
    "plan", "show plan", "dry run", "dry-run", "engagement plan",
    "what would you do", "what would hydrasight do", "roadmap",
    "show roadmap", "engagement roadmap",
})

# ── Operational meta-intent patterns (checked BEFORE tool/scan patterns) ──────

_EXECUTE_PLAN_RE = re.compile(
    r"\b("
    r"do all planned stuff|run the plan|execute the plan|continue engagement|"
    r"run all planned|run plan|start the plan|kick off the plan|"
    r"execute all|run everything|do everything planned|"
    r"do the planned|begin engagement|proceed with plan"
    r")\b",
    re.IGNORECASE,
)

_VERIFY_FINDINGS_RE = re.compile(
    r"\b("
    r"verify findings|verify finding|verify vulns|verify vulnerabilities|"
    r"verify results|check confirmations|validate findings|confirm findings|"
    r"re-verify|recheck findings|verify all"
    r")\b",
    re.IGNORECASE,
)

_SHOW_SUGGESTIONS_RE = re.compile(
    r"\b("
    r"suggest next step|suggest next|what should i do next|what next|"
    r"next move|next step|next action|what to do next|"
    r"recommend next|what would you recommend|show suggestions|"
    r"what are the options|best next action"
    r")\b",
    re.IGNORECASE,
)

_SHOW_CONCLUSION_RE = re.compile(
    r"^("
    r"conclusion|show conclusion|summarize outcome|engagement result|"
    r"engagement outcome|final summary|wrap up|what did we find|"
    r"what have we found|summarize findings|summarize results|what was found"
    r")$",
    re.IGNORECASE,
)

# SMB enumeration phrases — checked BEFORE generic smb/vuln patterns
_SMB_SHARE_ENUM_RE = re.compile(
    r"("
    r"smb\s+enum|smb\s+enumeration(?:\s+scan)?|enumerate\s+smb\s+shares?|"
    r"list\s+(?:smb\s+)?shares?|smb\s+share(?:s)?\s+list|scan\s+smb\s+shares?|"
    r"enum4linux|netbios\s+enum"
    r")",
    re.IGNORECASE,
)

# ── execution verb patterns ───────────────────────────────────────────────────

_EXEC_VERBS = re.compile(
    r"\b(run|execute|do|start|launch|kick off|perform|fire|initiate|begin|try)\b",
    re.IGNORECASE,
)
_ENUM_VERBS = re.compile(
    r"\b(enumerate|enum|check|probe|test|look at|look into|inspect|analyse|analyze)\b",
    re.IGNORECASE,
)
_SCAN_WORDS = re.compile(
    r"\b(scan|nmap|port\s*scan|host\s*discovery|recon|reconnaissance)\b",
    re.IGNORECASE,
)
_SMB_ENUM_WORDS = re.compile(r"\b(share|shares|enum|enumerate|netbios|enum4linux)\b", re.IGNORECASE)
_SMBCLIENT_WORDS = re.compile(r"\bsmbclient\b", re.IGNORECASE)
_SMB_WORDS  = re.compile(r"\b(smb|samba|port\s*445|ms17|eternalblue)\b", re.IGNORECASE)
_FTP_WORDS  = re.compile(r"\b(ftp|file\s*transfer|port\s*21)\b", re.IGNORECASE)
_SSH_WORDS  = re.compile(r"\b(ssh|secure\s*shell|port\s*22)\b", re.IGNORECASE)
_WEB_WORDS  = re.compile(r"\b(web|http|https|dir|directory|gobuster|nikto|port\s*80|port\s*443|port\s*8080)\b", re.IGNORECASE)
_VULN_WORDS = re.compile(r"\b(vuln|vulnerabilit|cve|exploit|metasploit)\b", re.IGNORECASE)
_PWND_WORDS = re.compile(r"\b(autopwn|exploit\s+host|full\s+engagement|compromise|pwn)\b", re.IGNORECASE)

# Ambiguous without IP or clear target reference
_AMBIGUOUS_RE = re.compile(
    r"^(scan it|check (it|this|that)|look at (it|this|that)|"
    r"enumerate (it|this|that)|do recon|check this box|check this host|"
    r"scan (this|the) host|look at smb|enum (it|this))$",
    re.IGNORECASE,
)


def _extract_ip(text: str) -> Optional[str]:
    m = _IP_RE.search(text)
    return m.group(1) if m else None


def _extract_ports(text: str) -> Optional[str]:
    # Try range first
    m = _PORT_RANGE_RE.search(text)
    if m:
        return f"{m.group(1)}-{m.group(2)}"
    # Try explicit list
    m2 = _PORT_LIST_RE.search(text)
    if m2:
        raw = m2.group(1).strip().rstrip(",")
        return raw.replace(" ", "")
    # Detect "all ports"
    if re.search(r"\ball\s+ports?\b", text, re.IGNORECASE):
        return "1-65535"
    return None


def _extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    # Explicit flags like -sS -sV -O
    for m in _FLAG_RE.finditer(text):
        f = m.group(1).strip()
        if f not in flags:
            flags.append(f)
    # Keyword → flag translation
    lower = text.lower()
    for kw, flag in _NMAP_FLAG_WORDS.items():
        if kw in lower and flag not in flags:
            flags.append(flag)
    return flags


def _tool_hint(text: str) -> Optional[str]:
    if _PWND_WORDS.search(text):      return "autopwn"

    # ── SMB: check for enumeration BEFORE generic vuln/smb check ─────────────
    # Priority: smbclient > share/list enumeration > generic smb_check
    if _SMBCLIENT_WORDS.search(text): return "smbclient_enum"
    if _SMB_SHARE_ENUM_RE.search(text): return "smb_enum"

    has_smb = bool(_SMB_WORDS.search(text))
    has_smb_enum = bool(_SMB_ENUM_WORDS.search(text))
    has_explicit_smb_tool = "enum4linux" in text.lower() or "netbios" in text.lower()

    if has_smb or has_explicit_smb_tool:
        if has_smb_enum or has_explicit_smb_tool:
            return "smb_enum"
        return "smb_check"

    # ── generic vuln scan (after SMB so 'smb vuln scan' doesn't drift) ────────
    if _VULN_WORDS.search(text):      return "vuln_scan"

    if _FTP_WORDS.search(text):    return "ftp_check"
    if _SSH_WORDS.search(text):    return "ssh_check"
    if _WEB_WORDS.search(text):    return "dir_enum"
    if _SCAN_WORDS.search(text):   return "nmap_scan"
    return None


def _starts_with_any(text: str, triggers: frozenset[str]) -> bool:
    lower = text.lower().strip()
    return any(lower.startswith(t) or lower == t for t in triggers)


def _contains_any(text: str, triggers: frozenset[str]) -> bool:
    lower = text.lower()
    return any(t in lower for t in triggers)


class IntentClassifier:
    """
    Classify a user input string into an IntentResult.

    No AI calls. No side effects. Thread-safe.
    """

    def classify(self, raw: str) -> IntentResult:
        """Classify *raw* user input. Never raises."""
        text = raw.strip()
        lower = text.lower()

        # ── 0. Empty ──────────────────────────────────────────────────────────
        if not text:
            return IntentResult(
                intent=Intent.CHAT, confidence=1.0, summary="empty input"
            )

        # ── 0.5. Guardrail for 'run command:' ─────────────────────────────────
        if lower.startswith("run command:"):
            hint = _tool_hint(text)
            if not hint:
                return IntentResult(
                    intent=Intent.CLARIFY, confidence=1.0,
                    clarify_question=(
                        "To actually execute commands, use `/run <action>` or a supported "
                        "security action such as SMB enumeration. I can propose and run "
                        "`enum4linux -S` or `smbclient` for you."
                    ),
                    summary="guardrail against arbitrary run command"
                )

        # ── 1. Operational meta-intents (checked before plan/chat/explain) ─────
        # These map to internal HydraSight commands, not generic chat.
        if _EXECUTE_PLAN_RE.search(text):
            return IntentResult(
                intent=Intent.EXECUTE_PLAN, confidence=1.0,
                summary="operator requests execution of planned engagement",
            )
        if _VERIFY_FINDINGS_RE.search(text):
            return IntentResult(
                intent=Intent.VERIFY_FINDINGS, confidence=1.0,
                summary="operator requests verification of findings",
            )
        if _SHOW_SUGGESTIONS_RE.search(text):
            return IntentResult(
                intent=Intent.SHOW_SUGGESTIONS, confidence=1.0,
                summary="operator requests next-step suggestions",
            )
        if _SHOW_CONCLUSION_RE.match(text):
            return IntentResult(
                intent=Intent.SHOW_CONCLUSION, confidence=1.0,
                summary="operator requests engagement conclusion summary",
            )

        # ── 2. Plan ───────────────────────────────────────────────────────────
        if _starts_with_any(text, _PLAN_TRIGGERS):
            return IntentResult(
                intent=Intent.PLAN, confidence=1.0,
                summary="engagement plan (dry run)",
            )

        # ── 2. Chat (small talk) ──────────────────────────────────────────────
        if _starts_with_any(text, _CHAT_TRIGGERS) and len(text.split()) <= 6:
            return IntentResult(
                intent=Intent.CHAT, confidence=0.95,
                summary="conversational input",
            )

        # ── 3. Explanation / knowledge ────────────────────────────────────────
        if _starts_with_any(text, _EXPLAIN_TRIGGERS):
            return IntentResult(
                intent=Intent.EXPLAIN, confidence=0.90,
                summary="knowledge / explanation request",
            )

        # ── 4. Extract operational context ────────────────────────────────────
        ip    = _extract_ip(text)
        ports = _extract_ports(text)
        flags = _extract_flags(text)
        hint  = _tool_hint(text)

        # ── 5. Ambiguous (known ambiguous pattern, no IP) ─────────────────────
        if _AMBIGUOUS_RE.match(text):
            question = (
                "What would you like to do?\n"
                "  1. Explain the technique\n"
                "  2. Suggest a command\n"
                "  3. Execute a scan\n"
                "Please clarify."
            )
            return IntentResult(
                intent=Intent.CLARIFY, confidence=0.85,
                extracted_ip=ip, tool_hint=hint,
                clarify_question=question,
                summary="ambiguous request — needs clarification",
            )

        # ── 6. Strong execution intent ────────────────────────────────────────
        has_exec_verb = bool(_EXEC_VERBS.search(text))
        has_enum_verb = bool(_ENUM_VERBS.search(text))
        has_scan_word = bool(_SCAN_WORDS.search(text))
        has_tool_word = hint is not None

        # High confidence execution: explicit verb + target/tool
        if has_exec_verb and has_tool_word:
            confidence = 0.90 if ip else 0.70
            return IntentResult(
                intent=Intent.EXECUTE_ACTION,
                confidence=confidence,
                extracted_ip=ip,
                extracted_ports=ports,
                extracted_flags=flags,
                tool_hint=hint,
                summary=f"execute {hint or 'scan'}" + (f" on {ip}" if ip else ""),
            )

        # High confidence execution: scan/enum verb + IP
        if (has_scan_word or has_enum_verb) and ip:
            confidence = 0.85
            return IntentResult(
                intent=Intent.EXECUTE_ACTION,
                confidence=confidence,
                extracted_ip=ip,
                extracted_ports=ports,
                extracted_flags=flags,
                tool_hint=hint or "nmap_scan",
                summary=f"execute {hint or 'nmap_scan'} on {ip}",
            )

        # SMB/FTP/SSH + IP (even without exec verb) — operational intent clear
        if hint in ("smb_check", "smb_enum", "ftp_check", "ssh_check") and ip:
            return IntentResult(
                intent=Intent.EXECUTE_ACTION,
                confidence=0.80,
                extracted_ip=ip,
                extracted_ports=ports,
                extracted_flags=flags,
                tool_hint=hint,
                summary=f"execute {hint} on {ip}",
            )

        # ── 7. Suggest / recommend ────────────────────────────────────────────
        if has_tool_word and not ip and not has_exec_verb:
            # Has a tool keyword but no target — suggest rather than execute
            q = (
                f"Do you want me to:\n"
                f"  1. Explain {hint.replace('_', ' ')}\n"
                f"  2. Suggest how to use it\n"
                f"  3. Execute it against a target (please provide an IP)\n"
                f"Which do you prefer?"
            )
            return IntentResult(
                intent=Intent.CLARIFY,
                confidence=0.75,
                tool_hint=hint,
                clarify_question=q,
                summary=f"tool hint ({hint}) but no target — clarifying",
            )

        # ── 8. Ambiguous operational (has tool word + IP but no clear verb) ───
        if has_tool_word and ip:
            return IntentResult(
                intent=Intent.EXECUTE_ACTION,
                confidence=0.70,
                extracted_ip=ip,
                extracted_ports=ports,
                extracted_flags=flags,
                tool_hint=hint,
                summary=f"{hint} intent with target {ip}",
            )

        # ── 9. Low-confidence explain fallback (has 'why', 'how', question?) ──
        if lower.endswith("?") or any(
            lower.startswith(w) for w in ("why", "how", "what", "when", "which", "who")
        ):
            return IntentResult(
                intent=Intent.EXPLAIN, confidence=0.75,
                summary="question — explanation expected",
            )

        # ── 10. Default → CHAT ────────────────────────────────────────────────
        return IntentResult(
            intent=Intent.CHAT, confidence=0.60,
            summary="unrecognised — treating as chat",
        )
