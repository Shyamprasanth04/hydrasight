"""
Shell renderers — Rich output formatting for the HydraSight REPL.

Extracted from shell.py to keep the REPL boundary thin.
Every function here is a pure display concern: it reads state and
renders Rich output, but never mutates engagement state or triggers
tool execution.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.padding import Padding

from hydrasight.cli.display import (
    console,
    div,
    info,
    label,
    make_table,
    ok,
    warn,
)
from hydrasight.config.defaults import P

if TYPE_CHECKING:
    from hydrasight.integrations.kali_api import KaliAPI
    from hydrasight.models.findings import Findings
    from hydrasight.models.planner_state import PlannerState
    from hydrasight.models.roe import RulesOfEngagement
    from hydrasight.services.action_planner import PendingAction
    from hydrasight.services.ai_client import AIClient

_FILTER_TYPES = frozenset({"ports", "vulns", "creds", "hashes", "sessions"})


# ── system status ─────────────────────────────────────────────────────────────


def render_status(
    kali: KaliAPI,
    ai: AIClient,
    cfg: dict,
) -> None:
    """Display system connectivity and configuration status."""
    kali_ok, kali_msg = kali.health()
    ai_ok, ai_msg = ai.health()
    lhost = kali.local_ip("8.8.8.8")
    div("system status")
    console.print()
    label(
        "kali api",
        (
            f"[{P.PRIMARY}]online[/]"
            if kali_ok
            else f"[{P.RED}]offline[/]  [{P.MUTED}]{kali_msg}[/]"
        ),
        16,
    )
    label(
        "ollama",
        (
            f"[{P.PRIMARY}]online[/]  [{P.MUTED}]{ai_msg}[/]"
            if ai_ok
            else f"[{P.RED}]offline[/]  [{P.MUTED}]{ai_msg}[/]"
        ),
        16,
    )
    label("model", f"[{P.TEXT}]{cfg['model']}[/]", 16)
    label("lhost", f"[{P.TEXT}]{lhost}[/]", 16)
    label("lport", f"[{P.TEXT}]{cfg['lport']}[/]", 16)
    label("output dir", f"[{P.TEXT}]{cfg['output_dir']}[/]", 16)
    label(
        "verbosity",
        f"[{P.TEXT}]{cfg['verbosity']}[/]  "
        f"[{P.DIM}]"
        f"({['quiet', 'normal', 'verbose', 'debug'][min(cfg['verbosity'], 3)]})"
        f"[/]",
        16,
    )

    exec_mode = cfg.get("execution_mode", "confirm")
    mode_desc = {
        "confirm": "ask before running NL actions",
        "auto": "auto-run high-confidence NL actions",
        "never": "never execute from NL input",
    }.get(exec_mode, "")

    label(
        "execution mode",
        f"[{P.TEXT}]{exec_mode}[/]  [{P.DIM}]({mode_desc})[/]",
        16,
    )

    console.print()
    div()


# ── findings display ──────────────────────────────────────────────────────────


def render_findings(findings: Findings, filter_type: str | None = None) -> None:
    """Display engagement findings, optionally filtered by type."""
    f = findings
    ft = filter_type if filter_type in _FILTER_TYPES else None
    div(f"findings — {f.target}" if f.target else "findings")
    if not f.has_data:
        console.print()
        info("no findings yet — run [bold]autopwn <ip>[/] to begin")
        console.print()
        div()
        return

    if ft in (None, "ports") and f.ports:
        console.print(f"\n  [{P.MUTED}]OPEN PORTS[/]  [{P.DIM}]({len(f.ports)})[/]")
        t = make_table(
            ("port", P.PRIMARY, 7),
            ("proto", P.DIM, 5),
            ("service", P.TEXT, 16),
            ("version", P.MUTED, 0),
        )
        t.columns[0].justify = "right"
        for p in sorted(f.ports, key=lambda x: x["port"]):
            t.add_row(
                str(p["port"]),
                p["proto"],
                p["service"],
                p.get("version", ""),
            )
        console.print(Padding(t, (0, 0, 0, 4)))

    if ft in (None, "vulns") and f.vulns:
        from hydrasight.config.defaults import SEV

        console.print(f"\n  [{P.MUTED}]VULNERABILITIES[/]  [{P.DIM}]({len(f.vulns)})[/]")
        t = make_table(
            ("sev", "", 6),
            ("name", P.TEXT, 40),
            ("cve", P.DIM, 18),
            ("description", P.MUTED, 0),
        )
        sev_order = list(SEV.keys())
        for v in sorted(
            f.vulns,
            key=lambda x: sev_order.index(x["severity"]),
        ):
            color, short = SEV[v["severity"]]
            t.add_row(
                f"[{color}]{short}[/]",
                v["name"],
                v.get("cve", ""),
                v.get("description", "")[:55],
            )
        console.print(Padding(t, (0, 0, 0, 4)))

    if ft in (None, "hashes") and f.hashes:
        console.print(f"\n  [{P.MUTED}]HASHES[/]  [{P.DIM}]({len(f.hashes)})[/]")
        t = make_table(
            ("username", P.TEXT, 22),
            ("ntlm", P.PRIMARY, 36),
            ("cracked", P.BRIGHT, 20),
        )
        for h in f.hashes:
            t.add_row(h["username"], h["ntlm"], h.get("cracked", "—"))
        console.print(Padding(t, (0, 0, 0, 4)))

    if ft in (None, "creds") and f.credentials:
        console.print(f"\n  [{P.MUTED}]CREDENTIALS[/]  [{P.DIM}]({len(f.credentials)})[/]")
        t = make_table(
            ("type", P.DIM, 16),
            ("username", P.TEXT, 22),
            ("secret", P.PRIMARY, 36),
            ("source", P.MUTED, 0),
        )
        for c in f.credentials:
            t.add_row(
                c["kind"],
                c["username"],
                c["secret"][:34],
                c.get("source", ""),
            )
        console.print(Padding(t, (0, 0, 0, 4)))

    if ft is None and f.dirs:
        console.print(f"\n  [{P.MUTED}]WEB PATHS[/]  [{P.DIM}]({len(f.dirs)})[/]")
        t = make_table(
            ("path", P.TEXT, 48),
            ("status", "", 8),
        )
        for d in sorted(f.dirs, key=lambda x: x.get("status", 0)):
            path = d["path"] if isinstance(d, dict) else d
            status = d.get("status", "?") if isinstance(d, dict) else "?"
            sc = (
                P.PRIMARY
                if str(status) == "200"
                else P.AMBER
                if str(status).startswith("3")
                else P.DIM
            )
            t.add_row(path, f"[{sc}]{status}[/]")
        console.print(Padding(t, (0, 0, 0, 4)))

    if ft in (None, "sessions") and f.sessions:
        console.print(f"\n  [{P.MUTED}]SESSIONS[/]  [{P.DIM}]({len(f.sessions)})[/]")
        t = make_table(
            ("id", P.PRIMARY, 4),
            ("target", P.TEXT, 18),
            ("access", P.BRIGHT, 28),
            ("method", P.MUTED, 0),
        )
        for s in f.sessions:
            t.add_row(
                str(s.get("id", "?")),
                s.get("target", ""),
                s.get("uid", ""),
                s.get("exploit", s.get("payload", "")),
            )
        console.print(Padding(t, (0, 0, 0, 4)))

    if ft is None and f.timeline:
        console.print(f"\n  [{P.MUTED}]TIMELINE[/]  [{P.DIM}]({len(f.timeline)})[/]")
        for ev in f.timeline:
            console.print(
                f"    [{P.DIM}]{ev['ts']}[/]  "
                f"[{P.PRIMARY}]{ev['phase']:<14}[/]  "
                f"[{P.TEXT}]{ev['event']}[/]"
            )
    console.print()
    div()


# ── ROE display ───────────────────────────────────────────────────────────────


def render_roe(roe: RulesOfEngagement, roe_file: str) -> None:
    """Display current rules of engagement."""
    from pathlib import Path

    div("rules of engagement")
    console.print()
    label("allowed targets", str(roe.allowed_targets), 22)
    label("blocked ports", str(roe.blocked_ports), 22)
    label("blocked modules", str(roe.blocked_modules), 22)
    label("approval required", str(roe.require_approval_for), 22)
    label("max runtime", f"{roe.max_runtime_minutes}m", 22)
    label("max threads", str(roe.max_threads), 22)
    label("kill switch", f"[{P.RED}]ACTIVE[/]" if roe.kill_switch else "off", 22)
    console.print()
    roe_path = Path(roe_file)
    if roe_path.exists():
        info(f"loaded from {roe_file}")
    else:
        info(
            f"no {roe_file} found — using permissive defaults  "
            f"(create it to enforce scope)"
        )
    console.print()
    div()


# ── stats display ─────────────────────────────────────────────────────────────


def render_stats(
    findings: Findings,
    ai: AIClient,
    start_time: float,
    tool_count: int,
) -> None:
    """Display session statistics."""
    elapsed = time.time() - start_time
    div("session statistics")
    console.print()
    label("duration", f"{elapsed:.0f}s  ({elapsed / 60:.1f} min)", 16)
    label("tools run", str(tool_count), 16)
    label("ai calls", str(ai.call_count), 16)
    label("messages", str(len(ai.messages)), 16)
    label("tokens", f"{ai.total_tokens:,}", 16)
    label("model", ai.model, 16)
    label(
        "findings",
        f"ports:{len(findings.ports)} "
        f"vulns:{len(findings.vulns)} "
        f"creds:{len(findings.credentials)}",
        16,
    )
    console.print()
    div()


# ── history display ───────────────────────────────────────────────────────────


def render_history(ai: AIClient) -> None:
    """Display AI conversation history."""
    div("ai conversation history")
    console.print()
    for i, msg in enumerate(ai.messages):
        role = msg["role"]
        content = str(msg.get("content", ""))[:100]
        color = P.PRIMARY if role == "assistant" else P.AMBER if role == "system" else P.MUTED
        console.print(f"  [{P.DIM}]{i:>3}[/]  [{color}]{role:<10}[/]  [{P.TEXT}]{content}[/]")
    console.print()
    div()


# ── config display ────────────────────────────────────────────────────────────


def render_config(cfg: dict) -> None:
    """Display current configuration."""
    div("current configuration")
    console.print()
    for key, val in sorted(cfg.items()):
        if key == "execution_mode":
            label(key, f"[{P.TEXT}]{val}[/]  [{P.DIM}](confirm | auto | never)[/]", 18)
        else:
            label(key, str(val), 18)
    console.print()
    info("config file: hydrasight.json  |  env prefix: HYDRA_")
    console.print()
    div()


# ── help display ──────────────────────────────────────────────────────────────


def render_help() -> None:
    """Display command reference."""
    div("command reference")
    console.print()
    sections = [
        (
            "ENGAGEMENT",
            [
                ("autopwn <ip>", "adaptive full-spectrum assessment"),
                ("scan <ip>", "deep port scan only"),
                ("abort", "abort current engagement"),
                ("verify", "run targeted verification on findings"),
            ],
        ),
        (
            "PLANNING",
            [
                ("plan", "show dry-run engagement plan  [no tools executed]"),
                ("suggest", "show ranked access/exploit candidates"),
                ("conclusion", "show engagement outcome summary"),
            ],
        ),
        (
            "NATURAL LANGUAGE",
            [
                ("<any request>", "classified automatically — explains, proposes, or confirms"),
                ("/ask <question>", "force chat mode — never executes tools"),
                ("/run <action>", "force tool routing, e.g. /run check smb on <ip>"),
                ("yes / confirm", "confirm a proposed action"),
                ("no / cancel", "cancel a proposed action"),
            ],
        ),
        (
            "EXECUTION MODE",
            [
                ("mode confirm", "always confirm before NL-initiated execution (default)"),
                ("mode auto", "high-confidence requests execute automatically"),
                ("mode never", "NL never executes tools, only explains/suggests"),
            ],
        ),
        (
            "DATA",
            [
                ("findings", "show all discovered data"),
                ("ports", "show open ports only"),
                ("vulns", "show vulnerabilities only"),
                ("creds", "show credentials only"),
                ("hashes", "show captured hashes"),
                ("sessions", "show access sessions"),
            ],
        ),
        (
            "OUTPUT",
            [
                ("save [file]", "save findings to json"),
                ("report <ip>", "generate pdf report"),
            ],
        ),
        (
            "SYSTEM",
            [
                ("status", "system health check"),
                ("stats", "session statistics"),
                ("config", "show current config"),
                ("history", "orchestration ai conversation log"),
                ("verbose 0-3", "set output level"),
                ("clear", "reset session state"),
                ("help", "this reference"),
                ("exit", "save and quit"),
            ],
        ),
    ]
    for section_name, rows in sections:
        console.print(f"  [{P.MUTED}]{section_name}[/]")
        for cmd, desc in rows:
            console.print(f"    [{P.PRIMARY}]{cmd:<18}[/]  [{P.DIM}]│[/]  [{P.MUTED}]{desc}[/]")
        console.print()
    div()


# ── action proposal ───────────────────────────────────────────────────────────


def render_proposed_action(action: PendingAction) -> None:
    """Display action preview for confirmation prompt."""
    console.print()
    div("proposed action")
    console.print()
    console.print(f"  [{P.MUTED}]I can run:[/]")
    console.print()
    console.print(f"  [{P.PRIMARY}]{action.command_str}[/]")
    console.print()
    console.print(f"  [{P.DIM}]tool      :[/] [{P.TEXT}]{action.tool_hint}[/]")
    console.print(f"  [{P.DIM}]target    :[/] [{P.TEXT}]{action.target}[/]")
    if action.ports:
        console.print(f"  [{P.DIM}]ports     :[/] [{P.TEXT}]{action.ports}[/]")
    if action.flags:
        console.print(f"  [{P.DIM}]flags     :[/] [{P.TEXT}]{' '.join(action.flags)}[/]")
    console.print(f"  [{P.DIM}]confidence:[/] [{P.AMBER}]{action.confidence:.0%}[/]")
    console.print()
    console.print(f"  [{P.RED}]This will send network traffic to the target.[/]")
    console.print()
    console.print(
        f"  [{P.AMBER}]Confirm?[/]  [{P.PRIMARY}]yes[/]  [{P.DIM}]/[/]  [{P.RED}]no[/]"
    )
    console.print()
    div()


# ── conclusion display ───────────────────────────────────────────────────────

def render_conclusion(findings: Findings) -> None:
    """Display engagement outcome and conclusion type."""
    from hydrasight.models.report_model import ReportModel

    f = findings
    div("engagement conclusion")
    console.print()

    if not f.has_data:
        warn("no engagement data — run autopwn or scan first")
        console.print()
        div()
        return

    report = ReportModel.from_findings(f)

    # Determine outcome prioritizing verified evidence
    if report.sessions:
        outcome, outcome_color = "POST-ACCESS", P.BRIGHT
        outcome_desc = "Active session(s) established"
    elif report.credentials:
        outcome, outcome_color = "CREDENTIAL-LED", P.PRIMARY
        outcome_desc = "Credentials recovered without session"
    elif report.exploited_findings:
        outcome, outcome_color = "EXPLOIT-CONFIRMED", P.BRIGHT
        outcome_desc = "Vulnerabilities explicitly exploited"
    elif report.verified_findings:
        outcome, outcome_color = "VALIDATION", P.AMBER
        outcome_desc = "Vulnerabilities independently verified"
    elif report.supported_candidates or report.no_strategy_candidates or report.attempted_not_confirmed_findings:
        outcome, outcome_color = "VULNERABILITY-CANDIDATES", P.AMBER
        outcome_desc = "Candidate vulnerabilities identified"
    elif report.ports:
        outcome, outcome_color = "RECON-ONLY", P.DIM
        outcome_desc = "Port/service discovery completed"
    else:
        outcome, outcome_color = "NO-FINDINGS", P.DIM
        outcome_desc = "No actionable data collected"

    console.print(f"  [{P.MUTED}]outcome[/]   [bold {outcome_color}]{outcome}[/]")
    console.print(f"  [{P.MUTED}]summary[/]   [{P.DIM}]{outcome_desc}[/]")
    console.print()

    label("ports", str(len(report.ports)), 16)

    cv = report.verification_coverage
    if cv.total > 0:
        parts = []
        if cv.exploited > 0:
            parts.append(f"[{P.BRIGHT}]{cv.exploited} exploited[/]")
        if cv.verified > 0:
            parts.append(f"[{P.PRIMARY}]{cv.verified} verified[/]")

        if report.supported_candidate_count > 0:
            parts.append(f"[{P.AMBER}]{report.supported_candidate_count} supported candidates[/]")

        if report.attempted_not_confirmed_count > 0:
            parts.append(f"[{P.RED}]{report.attempted_not_confirmed_count} not confirmed[/]")

        sum_str = "  |  ".join(parts) if parts else ""

        if report.no_strategy_candidate_count > 0:
            ns_str = f"[{P.DIM}]{report.no_strategy_candidate_count} lack verification strategy[/]"
            if sum_str:
                sum_str += f"  |  {ns_str}"
            else:
                sum_str = ns_str

        label("findings", sum_str, 16)

    label("credentials", str(len(report.credentials)), 16)
    label("hashes", str(len(f.hashes)), 16)
    label("sessions", str(len(report.sessions)), 16)
    label("web paths", str(len(report.dirs)), 16)

    if report.confirmed_risk != "NONE" or report.potential_risk != "NONE":
        label("confirmed risk", f"[{P.TEXT}]{report.confirmed_risk}[/]", 16)
        label("potential risk", f"[{P.DIM}]{report.potential_risk}[/]", 16)

    console.print()

    if report.exploited_findings:
        console.print(f"  [{P.MUTED}]EXPLOITED FINDINGS[/]")
        for r in report.exploited_findings:
            console.print(
                f"    [{P.BRIGHT}]✓[/]  "
                f"[{P.TEXT}]{r.display_title:<40}[/]  "
                f"[{P.MUTED}]{r.severity}  EXPLOITED[/]"
            )
        console.print()

    if report.verified_findings:
        console.print(f"  [{P.MUTED}]VERIFIED FINDINGS[/]")
        for r in report.verified_findings:
            console.print(
                f"    [{P.PRIMARY}]✓[/]  "
                f"[{P.TEXT}]{r.display_title:<40}[/]  "
                f"[{P.MUTED}]{r.severity}  VERIFIED[/]"
            )
        console.print()

    if report.sessions:
        console.print(f"  [{P.MUTED}]SESSIONS[/]")
        for s in report.sessions:
            console.print(
                f"    [{P.BRIGHT}]✓[/]  "
                f"[{P.TEXT}]{s.get('uid', '?'):<20}[/]  "
                f"via [{P.DIM}]{s.get('exploit', s.get('payload', '?'))}[/]"
            )
        console.print()

    div()


# ── suggest display ───────────────────────────────────────────────────────────


def render_suggest(
    findings: Findings, roe: RulesOfEngagement, engine_state: PlannerState | None
) -> None:
    """Display ranked access/exploit suggestions."""
    from hydrasight.integrations.exploit_suggestion import (
        ExecutionMode,
        ExploitSuggestionProvider,
    )

    div("access suggestions (dry run)")

    if not findings.ports:
        console.print()
        warn("no port data — run autopwn or scan first")
        info("suggestions are generated from discovered services")
        console.print()
        div()
        return

    suggestions = ExploitSuggestionProvider.from_findings(findings, planner_state=engine_state)
    manual_items = ExploitSuggestionProvider.manual_suggestions(findings)

    active = [s for s in suggestions if s.execution_mode != ExecutionMode.MANUAL_CHECK]
    console.print()
    if not active:
        warn("no active exploit/access paths found for current services")
    else:
        console.print(f"  [{P.MUTED}]RANKED ACCESS CANDIDATES[/]  [{P.DIM}]({len(active)})[/]")
        t = make_table(
            ("#", P.DIM, 3),
            ("mode", P.AMBER, 18),
            ("title", P.TEXT, 36),
            ("conf", P.PRIMARY, 7),
            ("safe", P.DIM, 5),
            ("cve", P.MUTED, 0),
        )
        t.columns[0].justify = "right"
        t.columns[3].justify = "right"
        for i, s in enumerate(active, 1):
            roe_blocked = (
                roe.is_module_blocked(s.msf_module) if s.msf_module else False
            ) or (roe.is_port_blocked(s.rport) if s.rport else False)
            title = s.title
            if roe_blocked:
                title = f"[{P.RED}][ROE BLOCKED][/] {title}"
            safe_lbl = f"[{P.PRIMARY}]✓[/]" if s.safe_by_default else f"[{P.RED}]×[/]"
            t.add_row(
                str(i),
                s.execution_mode.value,
                title,
                f"{s.confidence:.0%}",
                safe_lbl,
                s.cve or "—",
            )
        console.print(Padding(t, (0, 0, 0, 4)))

        console.print(f"\n  [{P.MUTED}]RATIONALE[/]")
        for s in active[:3]:
            prereqs = "  ".join(s.prerequisites)
            console.print(
                f"    [{P.DIM}]·[/]  [{P.TEXT}]{s.title}[/]\n"
                f"       [{P.MUTED}]{s.rationale}[/]\n"
                f"       [{P.DIM}]prereqs: {prereqs}[/]"
            )

    if manual_items:
        console.print(
            f"\n  [{P.MUTED}]MANUAL REVIEW PATHS[/]  [{P.DIM}]({len(manual_items)})[/]"
        )
        for m in manual_items:
            console.print(
                f"    [{P.DIM}]·[/]  [{P.TEXT}]{m.title}[/]  [{P.MUTED}]{m.rationale}[/]"
            )

    console.print()
    info("use [bold]plan[/] to see the full engagement roadmap")
    console.print()
    div()


# ── plan display ──────────────────────────────────────────────────────────────


def render_plan(
    findings: Findings,
    roe: RulesOfEngagement,
    engine_state: PlannerState | None,
) -> None:
    """Display dry-run engagement plan."""
    from hydrasight.core.planner import EngagementPlanner

    target = findings.target or ""
    plan = EngagementPlanner.build(findings, roe, planner_state=engine_state, target=target)

    div("engagement plan (dry run)")
    console.print()

    branch_color = {
        "recon-only": P.DIM,
        "validation-only": P.AMBER,
        "credential-led": P.PRIMARY,
        "web-led": P.BLUE if hasattr(P, "BLUE") else P.TEXT,
        "exploit-led": P.BRIGHT,
        "post-access": P.RED,
    }.get(plan.branch.value, P.TEXT)

    console.print(
        f"  [{P.MUTED}]branch[/]    [bold {branch_color}]{plan.branch.value.upper()}[/]"
    )
    console.print(f"  [{P.MUTED}]reason[/]    [{P.DIM}]{plan.branch_reason}[/]")
    if plan.target:
        console.print(f"  [{P.MUTED}]target[/]    [{P.TEXT}]{plan.target}[/]")
    console.print()

    console.print(f"  [{P.MUTED}]PHASES[/]")
    t = make_table(
        ("#", P.DIM, 3),
        ("phase", P.TEXT, 14),
        ("action", P.MUTED, 38),
        ("state", P.DIM, 9),
        ("reason", P.DIM, 0),
    )
    t.columns[0].justify = "right"
    for i, ph in enumerate(plan.phases, 1):
        if ph.blocked:
            state_lbl = f"[{P.RED}]BLOCKED[/]"
            reason = ph.block_reason
        elif ph.gated:
            state_lbl = f"[{P.AMBER}]GATED[/]"
            reason = ph.reason + "  [approval]"
        else:
            state_lbl = f"[{P.PRIMARY}]PLANNED[/]"
            reason = ph.reason
        t.add_row(str(i), ph.phase_id, ph.label, state_lbl, reason)
    console.print(Padding(t, (0, 0, 0, 4)))

    if plan.actionable_suggestions:
        console.print(
            f"\n  [{P.MUTED}]TOP CANDIDATES[/]  "
            f"[{P.DIM}]({len(plan.actionable_suggestions)})[/]"
        )
        for s in plan.actionable_suggestions[:5]:
            console.print(
                f"    [{P.DIM}]·[/]  [{P.TEXT}]{s.title:<34}[/]  "
                f"[{P.MUTED}]{s.execution_mode.value:<18}[/]  "
                f"conf [{P.PRIMARY}]{s.confidence:.0%}[/]"
            )

    if plan.warnings:
        console.print(f"\n  [{P.AMBER}]ROE CONSTRAINTS[/]")
        for w in plan.warnings:
            console.print(f"    [{P.AMBER}]⚠[/]  [{P.MUTED}]{w}[/]")

    console.print()
    info("use [bold]suggest[/] for ranked candidate detail")
    info("use [bold]autopwn <ip>[/] to execute this plan")
    console.print()
    div()


# ── verify display ────────────────────────────────────────────────────────────


def render_verify_results(results: list) -> None:
    """Display verification results."""
    div("verification results")
    console.print()
    for r in results:
        if r.verified:
            ok(f"VERIFIED     [{r.finding_name}]  conf {r.confidence:.0%}")
        else:
            info(f"unconfirmed  [{r.finding_name}]  {r.note}")
    console.print()
    div()


# ── NL policy decision rendering ──────────────────────────────────────────────


def render_clarification(message: str | None) -> None:
    """Display a clarification request."""
    console.print()
    div("clarification needed")
    console.print()
    for line in (message or "").splitlines():
        console.print(f"  [{P.TEXT}]{line}[/]")
    console.print()
    div()


def render_suggestion(message: str | None, pending: PendingAction | None) -> None:
    """Display a suggestion (mode=never or low confidence)."""
    console.print()
    div("suggestion")
    console.print()
    if message:
        for line in message.splitlines():
            console.print(f"  [{P.TEXT}]{line}[/]")
    elif pending:
        console.print(
            f"  [{P.MUTED}]I would run:[/] [{P.PRIMARY}]{pending.command_str}[/]"
        )
        console.print(
            f"  [{P.MUTED}]To execute it use:[/] "
            f"[{P.PRIMARY}]autopwn {pending.target}[/]  "
            f"[{P.DIM}]or[/]  [{P.PRIMARY}]scan {pending.target}[/]"
        )
    console.print()
    div()


# ── session display ───────────────────────────────────────────────────────────


def render_session_list(summaries: list) -> None:
    """Render a compact table of recent sessions."""
    div("recent engagements")
    console.print()

    if not summaries:
        info("no previous sessions found")
        console.print()
        div()
        return

    import time

    from hydrasight.cli.display import make_table

    t = make_table(
        ("id", P.PRIMARY, 14),
        ("target", P.TEXT, 20),
        ("status", P.DIM, 12),
        ("risk", P.AMBER, 8),
        ("V/E/C", P.MUTED, 12),
        ("ago", P.DIM, 0),
    )

    now = time.time()
    for s in summaries:
        # Determine risk color
        r_col = {
            "CRITICAL": P.RED,
            "HIGH": P.AMBER,
            "MEDIUM": P.YELLOW,
            "LOW": P.BLUE,
            "NONE": P.DIM,
        }.get(s.risk, P.DIM)

        # Calculate time ago
        diff = now - s.last_activity
        if diff < 60:
            ago = f"{int(diff)}s"
        elif diff < 3600:
            ago = f"{int(diff/60)}m"
        elif diff < 86400:
            ago = f"{int(diff/3600)}h"
        else:
            ago = f"{int(diff/86400)}d"

        # Stats string: Verified / Exploited / Candidates
        stats = f"{s.verified_count}/{s.exploited_count}/{s.findings_count}"

        # State color
        st_col = P.DIM
        if s.state == "in progress":
            st_col = P.PRIMARY
        elif s.state == "completed":
            st_col = P.MUTED

        t.add_row(
            f"[{P.PRIMARY}]{s.session_id}[/]",
            f"[{P.TEXT}]{s.target}[/]",
            f"[{st_col}]{s.state}[/]",
            f"[{r_col}]{s.risk}[/]",
            f"[{P.MUTED}]{stats}[/]",
            f"[{P.DIM}]{ago}[/]",
        )

    console.print(t)
    console.print()
    info("use [bold]sessions <id>[/] to view details")
    info("use [bold]resume <id>[/] to continue an engagement")
    console.print()
    div()


def render_session_detail(findings: Findings, state: PlannerState | None, session_id: str) -> None:
    """Render a full view of a single session, combining metadata and timeline."""
    div(f"session details: {session_id}")
    console.print()

    label("target", findings.target)
    label("started", findings.started_at)
    if state:
        label("duration", f"{state.elapsed_minutes():.1f} minutes")

    rc = findings.overall_risk
    rc_color = {
        "CRITICAL": P.RED,
        "HIGH": P.AMBER,
        "MEDIUM": P.YELLOW,
        "LOW": P.BLUE,
        "NONE": P.DIM,
    }.get(rc, P.DIM)
    label("risk", f"[{rc_color}]{rc}[/]")
    console.print()

    # Show canonical finding buckets using the new Pass 4.1 report model
    from hydrasight.models.report_model import ReportModel
    report = ReportModel.from_findings(findings)

    if report.exploited_findings:
        label("exploited", f"[{P.BRIGHT}]{len(report.exploited_findings)}[/] findings")
    if report.verified_findings:
        label("verified", f"[{P.TEXT}]{len(report.verified_findings)}[/] findings")
    if report.supported_candidates:
        label("candidates", f"[{P.MUTED}]{len(report.supported_candidates)}[/] unverified")

    if findings.timeline:
        console.print()
        console.print(f"  [{P.MUTED}]TIMELINE[/]")
        from hydrasight.cli.display import make_table
        t = make_table(
            ("phase", P.DIM, 14),
            ("tool", P.PRIMARY, 16),
            ("outcome", P.TEXT, 10),
            ("event", P.MUTED, 0)
        )
        for ev in findings.timeline:
            phase = ev.get("phase", "")
            tool = ev.get("tool", "")
            outcome = ev.get("outcome", "")
            event = ev.get("event", "")

            # Legacy fallback
            if not tool:
                event_str = str(event)
                if " — " in event_str:
                    tool, desc = event_str.split(" — ", 1)
                    event = desc
                else:
                    tool = "unknown"

            t.add_row(
                f"[{P.DIM}]{phase}[/]",
                f"[{P.PRIMARY}]{tool}[/]",
                f"[{P.TEXT}]{outcome}[/]",
                f"[{P.MUTED}]{event}[/]",
            )
        console.print(t)

    console.print()
    info(f"use [bold]resume {session_id}[/] to continue this engagement")
    console.print()
    div()
