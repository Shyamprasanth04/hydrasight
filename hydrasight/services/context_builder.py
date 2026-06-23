"""
ContextBuilder — compact, state-aware context summary for the chat model.

Builds a text block from:
  - Current target and risk level
  - Execution mode
  - Discovered ports (top N)
  - Vulnerabilities (count + top item + verified status)
  - High-confidence FindingRecords
  - Credentials / hashes / sessions
  - PlannerState dead paths (failed phases, empty tools, tried credentials)
  - Next-step hints

This module is intentionally dependency-free from Shell/Handlers so it can
be instantiated and tested without a full REPL setup.

SAFETY: ContextBuilder is read-only. It never modifies any state.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hydrasight.models.findings import Findings
    from hydrasight.models.planner_state import PlannerState

# Maximum character length of the generated context block
_MAX_CONTEXT_CHARS = 2000

# How many ports to show before truncating
_MAX_PORTS_SHOWN = 8

# How many high-confidence findings to list
_MAX_HIGH_CONF_SHOWN = 4


class ContextBuilder:
    """
    Build a compact context summary from engagement state.

    Usage::

        ctx = ContextBuilder.build(findings, planner_state, cfg)
        chat_controller.chat(user_input, context=ctx)
    """

    @staticmethod
    def build(
        findings: Findings,
        state: PlannerState | None,
        cfg: dict,
        canonical_target: str | None = None,
    ) -> str:
        """
        Return a compact plain-text context block.

        Args:
            findings:         Current engagement findings.
            state:            PlannerState (may be None before first engagement).
            cfg:              Runtime config dict (for execution_mode).
            canonical_target: Dispatcher.canonical_target fallback for target name.
        """
        lines: list[str] = ["=== HydraSight Engagement Context ==="]

        # ── target + risk + mode ──────────────────────────────────────────────
        target = findings.target or canonical_target or ""
        mode = cfg.get("execution_mode", "confirm")
        if target:
            risk = findings.overall_risk if findings.has_data else "NONE"
            lines.append(f"Target     : {target}  |  Risk: {risk}  |  Mode: {mode}")
        else:
            lines.append(f"Target     : none (no engagement started yet)  |  Mode: {mode}")

        # ── open ports ────────────────────────────────────────────────────────
        if findings.ports:
            top = findings.ports[:_MAX_PORTS_SHOWN]
            port_strs = [f"{p['port']}/{p.get('service', '?')}" for p in top]
            suffix = "..." if len(findings.ports) > _MAX_PORTS_SHOWN else ""
            lines.append(
                f"Open ports : {len(findings.ports)} — {', '.join(port_strs)}{suffix}"
            )
        else:
            lines.append("Open ports : none discovered")

        # ── vulnerabilities ───────────────────────────────────────────────────
        if findings.vulns:
            top_v = findings.vulns[0]
            verified_note = ""
            # Check if this vuln is also a verified FindingRecord
            top_name = top_v.get("name", "")
            for rec in findings.finding_records:
                if rec.name == top_name and rec.verified:
                    verified_note = " (verified)"
                    break
            lines.append(
                f"Vulns      : {len(findings.vulns)} finding(s) — "
                f"top: {top_name} [{top_v.get('severity', '?')}]{verified_note}"
            )
            v_count = findings.verified_count
            u_count = findings.unverified_count
            if v_count or u_count:
                lines.append(f"Verified   : {v_count} confirmed  {u_count} unconfirmed")
        else:
            lines.append("Vulns      : none identified")

        # ── high-confidence findings ──────────────────────────────────────────
        high_conf = findings.high_confidence_findings[:_MAX_HIGH_CONF_SHOWN]
        if high_conf:
            hc_parts = [
                f"{r.name} ({r.severity.value}, {r.confidence:.0%})"
                for r in high_conf
            ]
            lines.append(f"High-conf  : {', '.join(hc_parts)}")

        # ── credentials / hashes / sessions ──────────────────────────────────
        if findings.credentials:
            lines.append(f"Credentials: {len(findings.credentials)} captured")
        if findings.hashes:
            lines.append(f"Hashes     : {len(findings.hashes)} captured")
        if findings.sessions:
            lines.append(f"Sessions   : {len(findings.sessions)} active")

        # ── PlannerState dead paths ───────────────────────────────────────────
        if state is not None:
            dead_parts: list[str] = []
            for ph in state.all_failed_phases():
                res = state.phase_results.get(ph)
                reason = f" ({res.reason})" if res and res.reason else ""
                dead_parts.append(f"{ph} failed{reason}")
            for tool in sorted(state.empty_tools):
                if tool not in state.working_tools:
                    dead_parts.append(f"{tool} empty")
            if state.tried_credentials:
                dead_parts.append(f"{len(state.tried_credentials)} credential pair(s) tried")
            if dead_parts:
                # Cap to avoid bloating
                shown = dead_parts[:5]
                suffix = f" (+{len(dead_parts) - 5} more)" if len(dead_parts) > 5 else ""
                lines.append(f"Dead paths : {', '.join(shown)}{suffix}")

        # ── next step hints ───────────────────────────────────────────────────
        if target and findings.has_data:
            lines.append("Next steps : 'plan' for roadmap | 'suggest' for ranked candidates")
        elif not target:
            lines.append("Next steps : 'autopwn <ip>' or 'scan <ip>' to begin")

        # ── safety rules (always appended) ───────────────────────────────────
        lines += [
            "======================================",
            "RULES: You are the HydraSight operator assistant.",
            "- NEVER invent scan output, credentials, or tool results.",
            "- NEVER claim you are running or have run a tool.",
            "- Only describe what is shown above. Suggest real HydraSight actions.",
            "- Supported commands: autopwn <ip>, scan <ip>, verify, suggest, plan, conclusion.",
        ]

        result = "\n".join(lines)
        # Hard cap to prevent excessively long prompts
        if len(result) > _MAX_CONTEXT_CHARS:
            result = result[:_MAX_CONTEXT_CHARS] + "\n[context truncated]"
        return result
