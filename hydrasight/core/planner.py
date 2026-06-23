"""
Engagement planner — dry-run planning and suggestion display.

Used by the `suggest` and `plan` shell commands to show what
HydraSight would do without executing anything.

This module is pure logic — no I/O, no Kali calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from hydrasight.integrations.exploit_suggestion import (
    ExecutionMode,
    ExploitSuggestion,
    ExploitSuggestionProvider,
)

if TYPE_CHECKING:
    from hydrasight.models.findings import Findings
    from hydrasight.models.planner_state import PlannerState
    from hydrasight.models.roe import RulesOfEngagement


# ── engagement branch enum ─────────────────────────────────────────────────────


class EngagementBranch(str, Enum):
    RECON_ONLY = "recon-only"
    VALIDATION_ONLY = "validation-only"
    CREDENTIAL_LED = "credential-led"
    WEB_LED = "web-led"
    EXPLOIT_LED = "exploit-led"
    POST_ACCESS = "post-access"


# ── plan item ─────────────────────────────────────────────────────────────────


@dataclass
class PlanItem:
    """A single phase in the proposed engagement plan."""

    phase_id: str
    label: str
    reason: str
    blocked: bool = False
    block_reason: str = ""
    gated: bool = False  # requires operator approval


@dataclass
class EngagementPlan:
    """
    Full dry-run engagement plan.

    Includes:
    - selected branch (why this path was chosen)
    - ordered list of phases with block/gate flags
    - ranked access suggestions (from ExploitSuggestionProvider)
    - summary text for display
    """

    branch: EngagementBranch
    branch_reason: str
    phases: list[PlanItem]
    suggestions: list[ExploitSuggestion]
    has_target: bool
    target: str
    warnings: list[str]

    # ── computed ──────────────────────────────────────────────────────────────

    @property
    def actionable_phases(self) -> list[PlanItem]:
        return [p for p in self.phases if not p.blocked]

    @property
    def blocked_phases(self) -> list[PlanItem]:
        return [p for p in self.phases if p.blocked]

    @property
    def actionable_suggestions(self) -> list[ExploitSuggestion]:
        return [s for s in self.suggestions if s.execution_mode != ExecutionMode.MANUAL_CHECK]

    @property
    def manual_suggestions(self) -> list[ExploitSuggestion]:
        return [s for s in self.suggestions if s.execution_mode == ExecutionMode.MANUAL_CHECK]

    def summary_lines(self) -> list[str]:
        """Human-readable summary lines for display."""
        lines = [
            f"branch       {self.branch.value}",
            f"reason       {self.branch_reason}",
            f"phases       {len(self.actionable_phases)} planned"
            + (f"  ({len(self.blocked_phases)} blocked)" if self.blocked_phases else ""),
            f"suggestions  {len(self.actionable_suggestions)} active"
            + (f"  ({len(self.manual_suggestions)} manual)" if self.manual_suggestions else ""),
        ]
        if self.warnings:
            for w in self.warnings:
                lines.append(f"warning      {w}")
        return lines


# ── planner ───────────────────────────────────────────────────────────────────


class EngagementPlanner:
    """
    Pure dry-run planner — produces an EngagementPlan without executing anything.

    Mirrors the logic in engine._plan_phases() but returns a structured
    object suitable for display or testing.
    """

    # Phase label lookup
    _PHASE_LABELS: dict[str, str] = {
        "RECON": "Initial recon (nmap -sV -sC)",
        "DEEP_SCAN": "Deep port scan (1-65535)",
        "FTP_CHECK": "FTP service probe",
        "SMB_CHECK": "SMB/EternalBlue probe",
        "SSH_CHECK": "SSH auth methods probe",
        "WEB_FINGER": "Web fingerprint (whatweb)",
        "WEB_DIR": "Web directory brute (gobuster)",
        "WEB_VULN": "Web vulnerability scan (nikto)",
        "VULN_SCAN": "Vulnerability scan (nmap --script vuln)",
        "EXPLOIT": "Access attempt (ExploitSuggestionProvider)",
        "POST_EXPLOIT": "Post-access enumeration (PostAccessHandler)",
        "HASH_CRACK": "Credential recovery (john)",
    }

    @classmethod
    def build(
        cls,
        findings: Findings,
        roe: RulesOfEngagement,
        planner_state: PlannerState | None = None,
        target: str = "",
    ) -> EngagementPlan:
        """
        Produce a full EngagementPlan from current findings state.

        Safe to call at any point — before or after recon.
        """
        warnings: list[str] = []
        port_set = {p["port"] for p in findings.ports}
        services = {p["service"].lower() for p in findings.ports}
        has_web = any(s in services for s in ("http", "https", "http-alt"))
        has_smb = 445 in port_set or 139 in port_set
        has_ssh = 22 in port_set
        has_ftp = 21 in port_set
        has_creds = bool(findings.credentials)
        has_vulns = bool(findings.vulns)
        has_ports = bool(findings.ports)
        exploit_gated = roe.requires_approval("EXPLOIT")

        # ── gather suggestions ─────────────────────────────────────────────
        suggestions = ExploitSuggestionProvider.from_findings(findings, planner_state=planner_state)
        manual = ExploitSuggestionProvider.manual_suggestions(findings)
        all_suggestions = suggestions + [m for m in manual if m not in suggestions]
        has_exploit_suggestions = any(
            s.execution_mode != ExecutionMode.MANUAL_CHECK for s in suggestions
        )

        # ── determine branch ───────────────────────────────────────────────
        if not has_ports:
            branch = EngagementBranch.RECON_ONLY
            branch_reason = "No open ports discovered yet — recon required first"
        elif has_creds:
            branch = EngagementBranch.CREDENTIAL_LED
            branch_reason = (
                f"Captured {len(findings.credentials)} credential(s) — "
                "reuse paths will be attempted before exploits"
            )
        elif has_exploit_suggestions:
            branch = EngagementBranch.EXPLOIT_LED
            branch_reason = f"{len(suggestions)} exploit/access candidate(s) identified" + (
                " (approval required)" if exploit_gated else ""
            )
        elif has_web:
            branch = EngagementBranch.WEB_LED
            branch_reason = (
                "Web service(s) detected — fingerprint and directory enumeration planned"
            )
        elif has_vulns:
            branch = EngagementBranch.VALIDATION_ONLY
            branch_reason = (
                "Vulnerabilities found but no exploit path available — "
                "engagement concludes with validated evidence"
            )
        else:
            branch = EngagementBranch.RECON_ONLY
            branch_reason = "No actionable paths found — recon-only conclusion"

        # ── build phase list ───────────────────────────────────────────────
        phase_ids: list[str] = []

        if not has_ports:
            phase_ids = ["RECON", "DEEP_SCAN"]
        else:
            if has_ftp:
                phase_ids.append("FTP_CHECK")
            if has_smb:
                phase_ids.append("SMB_CHECK")
            if has_ssh:
                phase_ids.append("SSH_CHECK")
            if has_web:
                phase_ids.extend(["WEB_FINGER", "WEB_DIR", "WEB_VULN"])
            phase_ids.append("VULN_SCAN")

            if branch in (
                EngagementBranch.CREDENTIAL_LED,
                EngagementBranch.EXPLOIT_LED,
            ):
                phase_ids.extend(["EXPLOIT", "POST_EXPLOIT", "HASH_CRACK"])

        if has_creds or has_vulns or has_exploit_suggestions:
            if "HASH_CRACK" not in phase_ids:
                phase_ids.append("HASH_CRACK")

        # ── annotate each phase with block/gate info ───────────────────────
        phases: list[PlanItem] = []
        for ph in phase_ids:
            label = cls._PHASE_LABELS.get(ph, ph)
            blocked = False
            block_reason = ""
            gated = roe.requires_approval(ph)

            # Check planner memory
            if planner_state:
                skip, skip_reason = planner_state.should_skip_phase(ph)
                if skip:
                    blocked = True
                    block_reason = f"planner: {skip_reason}"

            # Check ROE kill switch
            if roe.kill_switch:
                blocked = True
                block_reason = "ROE kill switch active"

            # Check runtime
            if roe.is_runtime_exceeded():
                blocked = True
                block_reason = "ROE max runtime exceeded"

            # Determine display reason
            if ph == "RECON":
                reason = "Always runs first"
            elif ph == "DEEP_SCAN":
                reason = "Fallback if initial recon finds nothing"
            elif ph == "EXPLOIT":
                if has_creds:
                    reason = "Credential reuse paths + Metasploit candidates"
                else:
                    reason = f"{len(suggestions)} candidate(s) available"
            elif ph == "POST_EXPLOIT":
                reason = "Only runs if session established"
            elif ph == "HASH_CRACK":
                reason = "Opportunistic — runs if hashes captured"
            else:
                reason = f"Service detected on port {cls._port_for_phase(ph, port_set)}"

            phases.append(
                PlanItem(
                    phase_id=ph,
                    label=label,
                    reason=reason,
                    blocked=blocked,
                    block_reason=block_reason,
                    gated=gated,
                )
            )

        # ── ROE warnings ───────────────────────────────────────────────────
        if roe.kill_switch:
            warnings.append("ROE kill switch is ACTIVE — all phases blocked")
        if roe.blocked_ports:
            warnings.append(f"ROE blocks ports: {roe.blocked_ports}")
        if roe.blocked_modules:
            warnings.append(f"ROE blocks modules: {roe.blocked_modules}")
        if roe.require_approval_for:
            warnings.append(f"Approval required for: {roe.require_approval_for}")
        if roe.max_runtime_minutes < 9999:
            warnings.append(f"Max runtime: {roe.max_runtime_minutes} min")

        return EngagementPlan(
            branch=branch,
            branch_reason=branch_reason,
            phases=phases,
            suggestions=all_suggestions,
            has_target=bool(target or findings.target),
            target=target or findings.target,
            warnings=warnings,
        )

    @staticmethod
    def _port_for_phase(phase_id: str, port_set: set[int]) -> str:
        """Map phase to likely port for display."""
        mapping = {
            "FTP_CHECK": 21,
            "SMB_CHECK": 445,
            "SSH_CHECK": 22,
            "WEB_FINGER": 80,
            "WEB_DIR": 80,
            "WEB_VULN": 80,
        }
        port = mapping.get(phase_id)
        if port and port in port_set:
            return str(port)
        # Try to find a matching port
        if port:
            return str(port)
        return "?"
