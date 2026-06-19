"""
ActionPlanner — converts an IntentResult into a structured PendingAction.

A PendingAction is a fully-specified, human-readable description of what
HydraSight would run, before it runs it.

The planner uses the tool_hint + extracted params to build:
  - the exact command that would be executed
  - a human-readable preview string for the confirmation prompt
  - a tool_call dict ready to be passed to Dispatcher.dispatch()

Design constraints:
  - NO network calls
  - NO AI calls
  - Pure, deterministic, testable
  - Always produces a command preview the operator can read before approving
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Optional

from hydrasight.services.intent_classifier import IntentResult, Intent


@dataclass
class PendingAction:
    """A proposed tool action awaiting operator confirmation."""

    tool_hint    : str            # nmap_scan | smb_check | ftp_check | ssh_check | …
    target       : str            # validated IP
    ports        : Optional[str]  # e.g. "1-500", "80,443"
    flags        : list[str]      # e.g. ["-sS", "-sV", "-O"]
    command_str  : str            # human-readable command preview
    tool_call    : dict           # ready for Dispatcher.dispatch()
    reason       : str            # why this action was chosen
    confidence   : float          # from IntentResult

    @property
    def display(self) -> str:
        return (
            f"  tool    : {self.tool_hint}\n"
            f"  target  : {self.target}\n"
            f"  command : {self.command_str}\n"
            f"  reason  : {self.reason}\n"
            f"  confidence: {self.confidence:.0%}"
        )


class ActionPlanner:
    """
    Convert an IntentResult into a PendingAction.

    Returns None if:
      - intent is not EXECUTE_ACTION
      - no valid target is available
      - tool_hint is unknown
    """

    # ── default nmap ports by hint ────────────────────────────────────────────
    _DEFAULT_PORTS = {
        "nmap_scan" : "1-1000",
        "smb_check" : "445",
        "smb_enum"  : "139,445",
        "smbclient_enum": "139,445",
        "ftp_check" : "21",
        "ssh_check" : "22",
        "vuln_scan" : "21,22,80,135,139,443,445,8080",
        "dir_enum"  : "80,443",
        "autopwn"   : None,  # full engagement — no port restriction
    }

    def plan(
        self,
        result  : IntentResult,
        fallback_target: Optional[str] = None,
        cfg     : Optional[dict] = None,
    ) -> Optional[PendingAction]:
        """
        Build a PendingAction from an IntentResult.

        *fallback_target* is the current findings.target (used if no IP
        was extracted from the text).

        Returns None if a valid action cannot be determined.
        """
        if result.intent != Intent.EXECUTE_ACTION:
            return None

        target = result.extracted_ip or fallback_target
        if not target:
            return None

        hint   = result.tool_hint or "nmap_scan"
        ports  = result.extracted_ports or self._DEFAULT_PORTS.get(hint)
        flags  = result.extracted_flags or []
        cfg    = cfg or {}

        builder = getattr(self, f"_build_{hint}", self._build_nmap_scan)
        try:
            return builder(target, ports, flags, result.confidence, result.summary, cfg)
        except Exception:  # noqa: BLE001
            return self._build_nmap_scan(
                target, ports, flags, result.confidence, result.summary, cfg
            )

    # ── per-hint builders ──────────────────────────────────────────────────────

    def _build_nmap_scan(
        self, target: str, ports: Optional[str], flags: list[str],
        confidence: float, reason: str, cfg: dict,
    ) -> PendingAction:
        effective_ports = ports or "1-1000"
        effective_flags = flags if flags else ["-sV", "-sC"]
        flags_str = " ".join(effective_flags)
        cmd = f"nmap {flags_str} -p {effective_ports} {target}"
        return PendingAction(
            tool_hint   = "nmap_scan",
            target      = target,
            ports       = effective_ports,
            flags       = effective_flags,
            command_str = cmd,
            tool_call   = {
                "tool": "nmap_scan",
                "args": {
                    "target"         : target,
                    "scan_type"      : flags_str,
                    "ports"          : effective_ports,
                    "additional_args": "-T4 -Pn",
                },
            },
            reason     = reason,
            confidence = confidence,
        )

    def _build_smb_check(
        self, target: str, ports: Optional[str], flags: list[str],
        confidence: float, reason: str, cfg: dict,
    ) -> PendingAction:
        cmd = f"nmap --script smb-vuln-ms17-010,smb-os-discovery -p 445 {target}"
        return PendingAction(
            tool_hint   = "smb_check",
            target      = target,
            ports       = "445",
            flags       = [],
            command_str = cmd,
            tool_call   = {
                "tool": "run_command",
                "args": {"command": cmd},
            },
            reason     = reason,
            confidence = confidence,
        )

    def _build_smb_enum(
        self, target: str, ports: Optional[str], flags: list[str],
        confidence: float, reason: str, cfg: dict,
    ) -> PendingAction:
        cmd = f"enum4linux -a {target}"
        return PendingAction(
            tool_hint   = "smb_enum",
            target      = target,
            ports       = "139,445",
            flags       = [],
            command_str = cmd,
            tool_call   = {
                "tool": "smb_enum",
                "args": {"target": target},
            },
            reason     = reason,
            confidence = confidence,
        )

    def _build_smbclient_enum(
        self, target: str, ports: Optional[str], flags: list[str],
        confidence: float, reason: str, cfg: dict,
    ) -> PendingAction:
        cmd = f"smbclient -L //{target} -N 2>&1 | head -40"
        return PendingAction(
            tool_hint   = "smbclient_enum",
            target      = target,
            ports       = "139,445",
            flags       = [],
            command_str = cmd,
            tool_call   = {
                "tool": "run_command",
                "args": {"command": cmd},
            },
            reason     = reason,
            confidence = confidence,
        )

    def _build_ftp_check(
        self, target: str, ports: Optional[str], flags: list[str],
        confidence: float, reason: str, cfg: dict,
    ) -> PendingAction:
        cmd = f"nmap --script ftp-anon,ftp-vuln* -sV -p 21 {target}"
        return PendingAction(
            tool_hint   = "ftp_check",
            target      = target,
            ports       = "21",
            flags       = [],
            command_str = cmd,
            tool_call   = {
                "tool": "run_command",
                "args": {"command": cmd},
            },
            reason     = reason,
            confidence = confidence,
        )

    def _build_ssh_check(
        self, target: str, ports: Optional[str], flags: list[str],
        confidence: float, reason: str, cfg: dict,
    ) -> PendingAction:
        cmd = f"nmap --script ssh-auth-methods,ssh2-enum-algos -p 22 {target}"
        return PendingAction(
            tool_hint   = "ssh_check",
            target      = target,
            ports       = "22",
            flags       = [],
            command_str = cmd,
            tool_call   = {
                "tool": "run_command",
                "args": {"command": cmd},
            },
            reason     = reason,
            confidence = confidence,
        )

    def _build_vuln_scan(
        self, target: str, ports: Optional[str], flags: list[str],
        confidence: float, reason: str, cfg: dict,
    ) -> PendingAction:
        p   = ports or "21,22,80,135,139,443,445,8080"
        cmd = f"nmap -sV --script vuln -T4 -Pn --script-timeout 60s -p {p} {target}"
        return PendingAction(
            tool_hint   = "vuln_scan",
            target      = target,
            ports       = p,
            flags       = [],
            command_str = cmd,
            tool_call   = {
                "tool": "run_command",
                "args": {"command": cmd},
            },
            reason     = reason,
            confidence = confidence,
        )

    def _build_dir_enum(
        self, target: str, ports: Optional[str], flags: list[str],
        confidence: float, reason: str, cfg: dict,
    ) -> PendingAction:
        wordlist = cfg.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        url  = f"http://{target}"
        cmd  = f"gobuster dir -u {url} -w {wordlist}"
        return PendingAction(
            tool_hint   = "dir_enum",
            target      = target,
            ports       = "80",
            flags       = [],
            command_str = cmd,
            tool_call   = {
                "tool"  : "gobuster_scan",
                "args"  : {"url": url, "wordlist": wordlist, "extensions": ""},
            },
            reason     = reason,
            confidence = confidence,
        )

    def _build_autopwn(
        self, target: str, ports: Optional[str], flags: list[str],
        confidence: float, reason: str, cfg: dict,
    ) -> PendingAction:
        cmd = f"autopwn {target}  (full adaptive engagement)"
        return PendingAction(
            tool_hint   = "autopwn",
            target      = target,
            ports       = None,
            flags       = [],
            command_str = cmd,
            tool_call   = {},     # handled specially by shell — not via dispatch
            reason     = reason,
            confidence = confidence,
        )
