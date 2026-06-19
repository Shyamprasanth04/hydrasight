"""
Interactive REPL shell for HydraSight.

MODE SEPARATION (enforced by CommandRouter)
============================================
  BUILTIN  — explicit command keyword  → built-in handler (no AI)
  /ask ... — conversational prefix     → ChatController (no tools ever)
  /run ... — operator action prefix    → tool routing (explicit intent only)
  bare text — anything else            → ChatController (no tools ever)

Design contract:
  Plain English input ("hey", "explain smb", "why no ports") NEVER
  dispatches nmap, msfconsole, nikto, gobuster, or any shell command.
"""
import datetime
import json
import logging
import signal
import time
from pathlib import Path
from typing import Optional

from rich.padding import Padding

from hydrasight.config.defaults import P, PHASE_DEFS, TOOL_LABELS, BANNER, VERSION, CODENAME
from hydrasight.config.loader import load_config
from hydrasight.models.findings import Findings
from hydrasight.models.roe import RulesOfEngagement
from hydrasight.integrations.kali_api import KaliAPI
from hydrasight.integrations.exploit_db import ExploitDB
from hydrasight.services.ai_client import AIClient
from hydrasight.services.dispatcher import Dispatcher
from hydrasight.services.command_router import CommandRouter, InputClass
from hydrasight.services.chat_controller import ChatController
from hydrasight.services.intent_router import route_intent   # used ONLY by _on_run()
from hydrasight.services.intent_classifier import IntentClassifier, Intent
from hydrasight.services.action_planner import ActionPlanner
from hydrasight.services.confirmation_manager import ConfirmationManager
from hydrasight.services.execution_policy import ExecutionPolicy, VALID_MODES
from hydrasight.core.engine import Engine
from hydrasight.parsers import Parser
from hydrasight.reporting.json_reporter import save_json
from hydrasight.reporting.pdf_reporter import generate_pdf
from hydrasight.utils.ip_utils import is_valid_ip
from hydrasight.utils.time_utils import ts
from hydrasight.cli.display import (
    console,
    div, ok, warn, info, err, hit, label,
    spinner, task_line, result_line,
    analysis_panel, raw_output, stats_line, make_table,
)

try:
    import readline as _rl
    _READLINE_OK = True
except ImportError:
    _READLINE_OK = False

# ── command list for tab completion ───────────────────────────────────────────
COMMANDS = [
    "autopwn", "scan", "findings", "stats", "save", "report",
    "clear", "history", "status", "verbose", "help",
    "exit", "quit", "abort", "config", "roe", "verify",
    "suggest", "plan", "conclusion",
    "ports", "vulns", "creds", "hashes", "sessions",
]
_FILTER_TYPES = frozenset({"ports", "vulns", "creds", "hashes", "sessions"})


def _setup_log(log_file: str, verbosity: int) -> logging.Logger:
    level = {0: logging.ERROR, 1: logging.INFO,
             2: logging.INFO,  3: logging.DEBUG}.get(verbosity, logging.INFO)
    logger = logging.getLogger("hydrasight")
    logger.setLevel(level)
    if not logger.handlers:
        try:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)-7s] %(message)s"
            ))
            logger.addHandler(fh)
        except (PermissionError, OSError) as exc:
            print(f"[!] Cannot write log file {log_file}: {exc}")
    return logger


def _completer(text: str, state: int) -> Optional[str]:
    opts = [c for c in COMMANDS if c.startswith(text)]
    return opts[state] if state < len(opts) else None


if _READLINE_OK:
    _rl.set_completer(_completer)
    _rl.parse_and_bind("tab: complete")


class Shell:
    """Interactive REPL for HydraSight."""

    HIST     = ".hydrasight_history"
    ROE_FILE = "hydrasight.roe.json"

    def __init__(self, cfg: dict) -> None:
        self.cfg        = cfg
        self.verbosity  = cfg["verbosity"]
        self.log        = _setup_log(cfg["log_file"], cfg["verbosity"])
        self.findings   = Findings()
        self.kali       = KaliAPI(cfg["kali_api_url"], self.log)
        # Orchestration AI — has tool-call system prompt, used by Engine only
        self.ai         = AIClient(
            cfg["ollama_url"], cfg["model"], cfg["context_size"], self.log
        )
        self.dispatcher = Dispatcher(self.kali, self.log, cfg)
        self.roe        = self._load_roe()
        self.engine     = Engine(
            self.ai, self.kali, self.dispatcher,
            self.findings, cfg, self.log,
            roe=self.roe,
        )
        # Chat AI — separate client, separate history, no tool-call extraction
        self._chat = ChatController(
            cfg["ollama_url"], cfg["model"], cfg["context_size"], self.log
        )
        # Deterministic input classifier — no AI, no side effects
        self._router    = CommandRouter()
        # Natural-language intelligence layer
        self._intent    = IntentClassifier()
        self._planner   = ActionPlanner()
        self._confirm   = ConfirmationManager()
        self._policy    = ExecutionPolicy()
        self.start_time = time.time()
        self.tool_count = 0
        self._rl_init()
        signal.signal(signal.SIGINT, self._sigint)

    def _load_roe(self) -> RulesOfEngagement:
        """Load ROE from hydrasight.roe.json if present; else use permissive defaults."""
        p = Path(self.ROE_FILE)
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                roe  = RulesOfEngagement.from_dict(data)
                return roe
            except Exception as exc:  # noqa: BLE001
                print(f"[!] roe load error: {exc} — using permissive defaults")
        return RulesOfEngagement.permissive()

    # ── readline ──────────────────────────────────────────────────────────────

    def _rl_init(self) -> None:
        if not _READLINE_OK:
            return
        Path(self.HIST).touch(exist_ok=True)
        try:
            _rl.read_history_file(self.HIST)
        except Exception:  # noqa: BLE001
            pass
        _rl.set_history_length(1000)

    def _rl_save(self) -> None:
        if not _READLINE_OK:
            return
        try:
            _rl.write_history_file(self.HIST)
        except Exception:  # noqa: BLE001
            pass

    # ── signal handling ───────────────────────────────────────────────────────

    def _sigint(self, *_: object) -> None:
        self.engine.abort()
        warn("ctrl-c received — type 'exit' to quit cleanly")

    # ── output directory ──────────────────────────────────────────────────────

    def _out(self) -> Path:
        d = Path(self.cfg["output_dir"])
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ── prompt ────────────────────────────────────────────────────────────────

    def _prompt(self) -> str:
        stats_line(self.findings)
        try:
            return console.input(
                f"\n  [bold {P.PRIMARY}]hydra[/][{P.DIM}]·[/]"
                f"[bold {P.PRIMARY}]sight[/]  [{P.DIM}]›[/] "
            ).strip()
        except EOFError:
            return "exit"

    # ── save helpers ──────────────────────────────────────────────────────────

    def _save_json(self, path: str) -> bool:
        if save_json(self.findings, path):
            ok(f"saved   {path}")
            return True
        err(f"save failed: {path}")
        return False

    def _save_pdf(self, target: str, path: str) -> bool:
        info("generating pdf report")
        if generate_pdf(target, self.findings, path):
            ok(f"pdf     {path}")
            return True
        return False

    # ── display commands ──────────────────────────────────────────────────────

    def _show_status(self) -> None:
        kali_ok, kali_msg = self.kali.health()
        ai_ok,   ai_msg   = self.ai.health()
        lhost             = self.kali.local_ip("8.8.8.8")
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
        label("model",      f"[{P.TEXT}]{self.cfg['model']}[/]",      16)
        label("lhost",      f"[{P.TEXT}]{lhost}[/]",                  16)
        label("lport",      f"[{P.TEXT}]{self.cfg['lport']}[/]",      16)
        label("output dir", f"[{P.TEXT}]{self.cfg['output_dir']}[/]", 16)
        label(
            "verbosity",
            f"[{P.TEXT}]{self.cfg['verbosity']}[/]  "
            f"[{P.DIM}]"
            f"({['quiet','normal','verbose','debug'][min(self.cfg['verbosity'],3)]})"
            f"[/]",
            16,
        )
        
        exec_mode = self.cfg.get('execution_mode', 'confirm')
        mode_desc = {
            "confirm": "ask before running NL actions",
            "auto": "auto-run high-confidence NL actions",
            "never": "never execute from NL input"
        }.get(exec_mode, "")
        
        label(
            "execution mode",
            f"[{P.TEXT}]{exec_mode}[/]  [{P.DIM}]({mode_desc})[/]",
            16,
        )

        console.print()
        div()

    def _show_findings(self, filter_type: Optional[str] = None) -> None:
        f  = self.findings
        ft = filter_type if filter_type in _FILTER_TYPES else None
        div(f"findings — {f.target}" if f.target else "findings")
        if not f.has_data:
            console.print()
            info("no findings yet — run [bold]autopwn <ip>[/] to begin")
            console.print()
            div()
            return

        if ft in (None, "ports") and f.ports:
            console.print(
                f"\n  [{P.MUTED}]OPEN PORTS[/]  "
                f"[{P.DIM}]({len(f.ports)})[/]"
            )
            t = make_table(
                ("port",    P.PRIMARY, 7),
                ("proto",   P.DIM,     5),
                ("service", P.TEXT,   16),
                ("version", P.MUTED,   0),
            )
            t.columns[0].justify = "right"
            for p in sorted(f.ports, key=lambda x: x["port"]):
                t.add_row(
                    str(p["port"]), p["proto"],
                    p["service"], p.get("version", ""),
                )
            console.print(Padding(t, (0, 0, 0, 4)))

        if ft in (None, "vulns") and f.vulns:
            from hydrasight.config.defaults import SEV
            console.print(
                f"\n  [{P.MUTED}]VULNERABILITIES[/]  "
                f"[{P.DIM}]({len(f.vulns)})[/]"
            )
            t = make_table(
                ("sev",         "",       6),
                ("name",        P.TEXT,  40),
                ("cve",         P.DIM,   18),
                ("description", P.MUTED,  0),
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
            console.print(
                f"\n  [{P.MUTED}]HASHES[/]  [{P.DIM}]({len(f.hashes)})[/]"
            )
            t = make_table(
                ("username", P.TEXT,    22),
                ("ntlm",     P.PRIMARY, 36),
                ("cracked",  P.BRIGHT,  20),
            )
            for h in f.hashes:
                t.add_row(h["username"], h["ntlm"], h.get("cracked", "—"))
            console.print(Padding(t, (0, 0, 0, 4)))

        if ft in (None, "creds") and f.credentials:
            console.print(
                f"\n  [{P.MUTED}]CREDENTIALS[/]  "
                f"[{P.DIM}]({len(f.credentials)})[/]"
            )
            t = make_table(
                ("type",     P.DIM,     16),
                ("username", P.TEXT,    22),
                ("secret",   P.PRIMARY, 36),
                ("source",   P.MUTED,    0),
            )
            for c in f.credentials:
                t.add_row(
                    c["kind"], c["username"],
                    c["secret"][:34], c.get("source", ""),
                )
            console.print(Padding(t, (0, 0, 0, 4)))

        if ft is None and f.dirs:
            console.print(
                f"\n  [{P.MUTED}]WEB PATHS[/]  "
                f"[{P.DIM}]({len(f.dirs)})[/]"
            )
            t = make_table(
                ("path",   P.TEXT, 48),
                ("status", "",      8),
            )
            for d in sorted(f.dirs, key=lambda x: x.get("status", 0)):
                path   = d["path"]           if isinstance(d, dict) else d
                status = d.get("status", "?") if isinstance(d, dict) else "?"
                sc = (
                    P.PRIMARY if str(status) == "200"
                    else P.AMBER if str(status).startswith("3")
                    else P.DIM
                )
                t.add_row(path, f"[{sc}]{status}[/]")
            console.print(Padding(t, (0, 0, 0, 4)))

        if ft in (None, "sessions") and f.sessions:
            console.print(
                f"\n  [{P.MUTED}]SESSIONS[/]  "
                f"[{P.DIM}]({len(f.sessions)})[/]"
            )
            t = make_table(
                ("id",      P.PRIMARY, 4),
                ("target",  P.TEXT,   18),
                ("access",  P.BRIGHT, 28),
                ("method",  P.MUTED,   0),
            )
            for s in f.sessions:
                t.add_row(
                    str(s.get("id", "?")),
                    s.get("target",  ""),
                    s.get("uid",     ""),
                    s.get("exploit", s.get("payload", "")),
                )
            console.print(Padding(t, (0, 0, 0, 4)))

        if ft is None and f.timeline:
            console.print(
                f"\n  [{P.MUTED}]TIMELINE[/]  "
                f"[{P.DIM}]({len(f.timeline)})[/]"
            )
            for ev in f.timeline:
                console.print(
                    f"    [{P.DIM}]{ev['ts']}[/]  "
                    f"[{P.PRIMARY}]{ev['phase']:<14}[/]  "
                    f"[{P.TEXT}]{ev['event']}[/]"
                )
        console.print()
        div()

    def _show_roe(self) -> None:
        """Display current rules of engagement."""
        div("rules of engagement")
        console.print()
        label("allowed targets",    str(self.roe.allowed_targets),       22)
        label("blocked ports",      str(self.roe.blocked_ports),         22)
        label("blocked modules",    str(self.roe.blocked_modules),       22)
        label("approval required",  str(self.roe.require_approval_for),  22)
        label("max runtime",        f"{self.roe.max_runtime_minutes}m",  22)
        label("max threads",        str(self.roe.max_threads),           22)
        label("kill switch",
              f"[{P.RED}]ACTIVE[/]" if self.roe.kill_switch else "off",
              22)
        console.print()
        roe_path = Path(self.ROE_FILE)
        if roe_path.exists():
            info(f"loaded from {self.ROE_FILE}")
        else:
            info(
                f"no {self.ROE_FILE} found — using permissive defaults  "
                f"(create it to enforce scope)"
            )
        console.print()
        div()

    def _run_verify(self) -> None:
        """Run verifier against all unverified CRITICAL/HIGH findings."""
        from hydrasight.services.verifier import VerifierService
        if not self.findings.finding_records:
            warn("no typed finding records yet — run autopwn or scan first")
            return
        target = (
            self.findings.target
            or self.dispatcher.canonical_target
            or ""
        )
        if not target:
            warn("no target set — run autopwn or scan first")
            return
        kali_ok, msg = self.kali.health()
        if not kali_ok:
            err(f"kali-server offline: {msg}")
            return
        verifier = VerifierService(self.kali, self.log, target)
        info(f"verifying findings against {target}")
        results = verifier.verify_findings(
            self.findings, only_high_and_above=False
        )
        if not results:
            info("all findings already verified or no strategy available")
            return
        div("verification results")
        console.print()
        for r in results:
            if r.verified:
                hit(f"VERIFIED     [{r.finding_name}]  conf {r.confidence:.0%}")
            else:
                icon = ok if r.confidence > 0.3 else warn
                info(f"unconfirmed  [{r.finding_name}]  {r.note}")
        console.print()
        div()

    # ── suggest command ──────────────────────────────────────────────────

    def _show_suggest(self) -> None:
        """
        Display ranked access/exploit suggestions without executing anything.
        Uses ExploitSuggestionProvider on current findings.
        """
        from hydrasight.integrations.exploit_suggestion import (
            ExploitSuggestionProvider, ExecutionMode,
        )
        from hydrasight.config.defaults import SEV

        div("access suggestions (dry run)")

        if not self.findings.ports:
            console.print()
            warn("no port data — run autopwn or scan first")
            info("suggestions are generated from discovered services")
            console.print()
            div()
            return

        state       = getattr(self.engine, "_state", None)
        suggestions = ExploitSuggestionProvider.from_findings(
            self.findings, planner_state=state
        )
        manual_items = ExploitSuggestionProvider.manual_suggestions(self.findings)

        # ── active suggestions ─────────────────────────────────────────────
        active = [s for s in suggestions if s.execution_mode != ExecutionMode.MANUAL_CHECK]
        console.print()
        if not active:
            warn("no active exploit/access paths found for current services")
        else:
            console.print(
                f"  [{P.MUTED}]RANKED ACCESS CANDIDATES[/]  "
                f"[{P.DIM}]({len(active)})[/]"
            )
            t = make_table(
                ("#",     P.DIM,     3),
                ("mode",  P.AMBER,  18),
                ("title", P.TEXT,   36),
                ("conf",  P.PRIMARY, 7),
                ("safe",  P.DIM,     5),
                ("cve",   P.MUTED,   0),
            )
            t.columns[0].justify = "right"
            t.columns[3].justify = "right"
            for i, s in enumerate(active, 1):
                # Check ROE block
                roe_blocked = (
                    self.roe.is_module_blocked(s.msf_module)
                    if s.msf_module else False
                ) or (
                    self.roe.is_port_blocked(s.rport)
                    if s.rport else False
                )
                title = s.title
                if roe_blocked:
                    title = f"[{P.RED}][ROE BLOCKED][/] {title}"
                safe_lbl = (
                    f"[{P.PRIMARY}]✓[/]"
                    if s.safe_by_default
                    else f"[{P.RED}]×[/]"
                )
                t.add_row(
                    str(i),
                    s.execution_mode.value,
                    title,
                    f"{s.confidence:.0%}",
                    safe_lbl,
                    s.cve or "—",
                )
            console.print(Padding(t, (0, 0, 0, 4)))

            # Show rationale for top 3
            console.print(f"\n  [{P.MUTED}]RATIONALE[/]")
            for s in active[:3]:
                prereqs = "  ".join(s.prerequisites)
                console.print(
                    f"    [{P.DIM}]·[/]  [{P.TEXT}]{s.title}[/]\n"
                    f"       [{P.MUTED}]{s.rationale}[/]\n"
                    f"       [{P.DIM}]prereqs: {prereqs}[/]"
                )

        # ── manual checks ──────────────────────────────────────────────────
        if manual_items:
            console.print(
                f"\n  [{P.MUTED}]MANUAL REVIEW PATHS[/]  "
                f"[{P.DIM}]({len(manual_items)})[/]"
            )
            for m in manual_items:
                console.print(
                    f"    [{P.DIM}]·[/]  [{P.TEXT}]{m.title}[/]"
                    f"  [{P.MUTED}]{m.rationale}[/]"
                )

        console.print()
        info("use [bold]plan[/] to see the full engagement roadmap")
        console.print()
        div()

    # ── plan command ───────────────────────────────────────────────────────

    def _show_plan(self) -> None:
        """Display a full dry-run engagement plan."""
        from hydrasight.core.planner import EngagementPlanner

        state  = getattr(self.engine, "_state", None)
        target = self.findings.target or ""
        plan   = EngagementPlanner.build(
            self.findings, self.roe, planner_state=state, target=target
        )

        div("engagement plan (dry run)")
        console.print()

        # ── branch header ──────────────────────────────────────────────────
        branch_color = {
            "recon-only"     : P.DIM,
            "validation-only": P.AMBER,
            "credential-led" : P.PRIMARY,
            "web-led"        : P.BLUE if hasattr(P, "BLUE") else P.TEXT,
            "exploit-led"    : P.BRIGHT,
            "post-access"    : P.RED,
        }.get(plan.branch.value, P.TEXT)

        console.print(
            f"  [{P.MUTED}]branch[/]    "
            f"[bold {branch_color}]{plan.branch.value.upper()}[/]"
        )
        console.print(
            f"  [{P.MUTED}]reason[/]    [{P.DIM}]{plan.branch_reason}[/]"
        )
        if plan.target:
            console.print(
                f"  [{P.MUTED}]target[/]    [{P.TEXT}]{plan.target}[/]"
            )
        console.print()

        # ── phase table ────────────────────────────────────────────────────
        console.print(f"  [{P.MUTED}]PHASES[/]")
        t = make_table(
            ("#",      P.DIM,     3),
            ("phase",  P.TEXT,   14),
            ("action", P.MUTED,  38),
            ("state",  P.DIM,     9),
            ("reason", P.DIM,     0),
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
            t.add_row(
                str(i), ph.phase_id, ph.label, state_lbl, reason
            )
        console.print(Padding(t, (0, 0, 0, 4)))

        # ── suggestions summary ────────────────────────────────────────────
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

        # ── warnings ───────────────────────────────────────────────────────
        if plan.warnings:
            console.print(f"\n  [{P.AMBER}]ROE CONSTRAINTS[/]")
            for w in plan.warnings:
                console.print(f"    [{P.AMBER}]⚠[/]  [{P.MUTED}]{w}[/]")

        console.print()
        info("use [bold]suggest[/] for ranked candidate detail")
        info("use [bold]autopwn <ip>[/] to execute this plan")
        console.print()
        div()

    # ── conclusion command ────────────────────────────────────────────────

    def _show_conclusion(self) -> None:
        """Display engagement outcome and conclusion type."""
        from hydrasight.core.planner import EngagementBranch

        f = self.findings
        div("engagement conclusion")
        console.print()

        if not f.has_data:
            warn("no engagement data — run autopwn or scan first")
            console.print()
            div()
            return

        # ── determine outcome ──────────────────────────────────────────────
        if f.sessions:
            outcome      = "POST-ACCESS"
            outcome_color = P.BRIGHT
            outcome_desc  = "Active session(s) established"
        elif f.credentials:
            outcome      = "CREDENTIAL-LED"
            outcome_color = P.PRIMARY
            outcome_desc  = "Credentials recovered without session"
        elif f.verified_count > 0:
            outcome      = "VALIDATION"
            outcome_color = P.AMBER
            outcome_desc  = "Vulnerabilities independently verified"
        elif f.vulns:
            outcome      = "VULNERABILITY-IDENTIFIED"
            outcome_color = P.AMBER
            outcome_desc  = "Vulnerabilities identified (unverified)"
        elif f.ports:
            outcome      = "RECON-ONLY"
            outcome_color = P.DIM
            outcome_desc  = "Port/service discovery completed"
        else:
            outcome      = "NO-FINDINGS"
            outcome_color = P.DIM
            outcome_desc  = "No data collected"

        console.print(
            f"  [{P.MUTED}]outcome[/]   "
            f"[bold {outcome_color}]{outcome}[/]"
        )
        console.print(
            f"  [{P.MUTED}]summary[/]   [{P.DIM}]{outcome_desc}[/]"
        )
        console.print()

        # ── finding summary ────────────────────────────────────────────────
        label("ports",         str(len(f.ports)),         16)
        label(
            "vulns",
            f"{len(f.vulns)}  "
            f"(C:{f.critical_count} H:{f.high_count} "
            f"M:{f.medium_count} L:{f.low_count})",
            16,
        )
        if f.finding_records:
            label(
                "verified",
                f"{f.verified_count} confirmed  "
                f"{f.unverified_count} not confirmed  "
                f"{len(f.finding_records)-f.verified_count-f.unverified_count} pending",
                16,
            )
        label("credentials",   str(len(f.credentials)),   16)
        label("hashes",        str(len(f.hashes)),         16)
        label("sessions",      str(len(f.sessions)),       16)
        label("web paths",     str(len(f.dirs)),           16)
        label("risk level",    f.overall_risk,             16)
        console.print()

        # ── verified finding highlights ────────────────────────────────────
        verified = [r for r in f.finding_records if r.verified]
        if verified:
            console.print(f"  [{P.MUTED}]VERIFIED FINDINGS[/]")
            for r in sorted(verified, key=lambda x: x.severity_rank):
                console.print(
                    f"    [{P.PRIMARY}]✓[/]  "
                    f"[{P.TEXT}]{r.name:<40}[/]  "
                    f"[{P.MUTED}]{r.severity.value}  {r.confidence:.0%}[/]"
                )
            console.print()

        # ── session highlights ─────────────────────────────────────────────
        if f.sessions:
            console.print(f"  [{P.MUTED}]SESSIONS[/]")
            for s in f.sessions:
                console.print(
                    f"    [{P.BRIGHT}]✓[/]  "
                    f"[{P.TEXT}]{s.get('uid','?'):<20}[/]  "
                    f"via [{P.DIM}]{s.get('exploit', s.get('payload','?'))}[/]"
                )
            console.print()

        div()

    def _show_help(self) -> None:
        div("command reference")
        console.print()
        sections = [
            ("ENGAGEMENT", [
                ("autopwn <ip>",  "adaptive full-spectrum assessment"),
                ("scan <ip>",     "deep port scan only"),
                ("abort",         "abort current engagement"),
                ("verify",        "run targeted verification on findings"),
            ]),
            ("PLANNING", [
                ("plan",           "show dry-run engagement plan  [no tools executed]"),
                ("suggest",        "show ranked access/exploit candidates"),
                ("conclusion",     "show engagement outcome summary"),
            ]),
            ("NATURAL LANGUAGE", [
                ("<any request>",  "classified automatically — explains, proposes, or confirms"),
                ("/ask <question>","force chat mode — never executes tools"),
                ("/run <action>",  "force tool routing, e.g. /run check smb on <ip>"),
                ("yes / confirm",  "confirm a proposed action"),
                ("no / cancel",    "cancel a proposed action"),
            ]),
            ("EXECUTION MODE", [
                ("mode confirm",  "always confirm before NL-initiated execution (default)"),
                ("mode auto",     "high-confidence requests execute automatically"),
                ("mode never",    "NL never executes tools, only explains/suggests"),
            ]),
            ("DATA", [
                ("findings",  "show all discovered data"),
                ("ports",     "show open ports only"),
                ("vulns",     "show vulnerabilities only"),
                ("creds",     "show credentials only"),
                ("hashes",    "show captured hashes"),
                ("sessions",  "show access sessions"),
            ]),
            ("OUTPUT", [
                ("save [file]",  "save findings to json"),
                ("report <ip>",  "generate pdf report"),
            ]),
            ("SYSTEM", [
                ("roe",         "show rules of engagement"),
                ("status",      "system health check"),
                ("stats",       "session statistics"),
                ("config",      "show current config"),
                ("history",     "orchestration ai conversation log"),
                ("verbose 0-3", "set output level"),
                ("clear",       "reset session state"),
                ("help",        "this reference"),
                ("exit",        "save and quit"),
            ]),
        ]
        for section_name, rows in sections:
            console.print(f"  [{P.MUTED}]{section_name}[/]")
            for cmd, desc in rows:
                console.print(
                    f"    [{P.PRIMARY}]{cmd:<18}[/]  "
                    f"[{P.DIM}]│[/]  [{P.MUTED}]{desc}[/]"
                )
            console.print()
        div()

    def _show_stats(self) -> None:
        elapsed = time.time() - self.start_time
        div("session statistics")
        console.print()
        label("duration",  f"{elapsed:.0f}s  ({elapsed / 60:.1f} min)", 16)
        label("tools run", str(self.tool_count),             16)
        label("ai calls",  str(self.ai.call_count),          16)
        label("messages",  str(len(self.ai.messages)),       16)
        label("tokens",    f"{self.ai.total_tokens:,}",      16)
        label("model",     self.ai.model,                    16)
        label(
            "findings",
            f"ports:{len(self.findings.ports)} "
            f"vulns:{len(self.findings.vulns)} "
            f"creds:{len(self.findings.credentials)}",
            16,
        )
        console.print()
        div()

    def _show_history(self) -> None:
        div("ai conversation history")
        console.print()
        for i, msg in enumerate(self.ai.messages):
            role    = msg["role"]
            content = str(msg.get("content", ""))[:100]
            color   = (
                P.PRIMARY if role == "assistant"
                else P.AMBER if role == "system"
                else P.MUTED
            )
            console.print(
                f"  [{P.DIM}]{i:>3}[/]  [{color}]{role:<10}[/]  "
                f"[{P.TEXT}]{content}[/]"
            )
        console.print()
        div()

    def _show_config(self) -> None:
        div("current configuration")
        console.print()
        for key, val in sorted(self.cfg.items()):
            if key == "execution_mode":
                label(key, f"[{P.TEXT}]{val}[/]  [{P.DIM}](confirm | auto | never)[/]", 18)
            else:
                label(key, str(val), 18)
        console.print()
        info("config file: hydrasight.json  |  env prefix: HYDRA_")
        console.print()
        div()

    # ── NL intent pipeline (replaces rigid chat-only _on_bare_text) ────────────

    def _on_bare_text(self, user_input: str) -> None:
        """
        Smart natural-language handler.

        Pipeline:
          1. Check ConfirmationManager (is this a yes/no reply?)
          2. IntentClassifier  — classify intent deterministically
          3. ExecutionPolicy   — apply execution_mode
          4. Dispatch to: chat / explain / clarify / propose / execute / plan

        SAFETY CONTRACT:
          - CHAT and EXPLAIN intents NEVER dispatch tools
          - plan NEVER dispatches tools
          - CLARIFY NEVER dispatches tools
          - mode='never' NEVER dispatches tools from NL
          - only PolicyDecision.action == 'execute' or 'confirm+yes' dispatches
        """
        text = user_input.strip()
        if not text:
            return

        # ── Step 1: check if this is a yes/no reply to a pending action ──────
        if self._confirm.has_pending and self._confirm.is_yes_no(text):
            resolution, action = self._confirm.try_resolve(text)
            if resolution == "yes" and action:
                self._dispatch_pending_action(action)
            elif resolution == "no":
                ok("action cancelled")
            return

        # ── Step 2: classify intent ───────────────────────────────────
        result = self._intent.classify(text)

        # A new substantive request replaces any pending action
        if not self._confirm.is_yes_no(text) and result.intent not in (
            Intent.CHAT, Intent.EXPLAIN
        ):
            self._confirm.clear()

        # ── Step 3: build action plan if needed ────────────────────────
        pending = None
        if result.intent == Intent.EXECUTE_ACTION:
            pending = self._planner.plan(
                result,
                fallback_target=self.findings.target,
                cfg=self.cfg,
            )

        # ── Step 4: apply execution policy ───────────────────────────
        mode     = self.cfg.get("execution_mode", "confirm")
        decision = self._policy.decide(result, pending, mode)

        # -- Step 5: dispatch decision ------------------------------------------
        # -- 5a. Operational meta-intents -- bypass chat entirely ---------------
        if result.intent == Intent.EXECUTE_PLAN:
            target = self.findings.target or self.dispatcher.canonical_target
            if not target:
                warn("no target set -- run autopwn or scan first to establish a target")
                info("use [bold]autopwn <ip>[/] to begin a full engagement")
            else:
                info(f"resuming engagement for {target}")
                try:
                    self.engine.run(target)
                except Exception:  # noqa: BLE001
                    console.print_exception(show_locals=False)
                finally:
                    self.dispatcher.canonical_target = None
            return

        if result.intent == Intent.VERIFY_FINDINGS:
            self._run_verify()
            return

        if result.intent == Intent.SHOW_SUGGESTIONS:
            self._show_suggest()
            return

        if result.intent == Intent.SHOW_CONCLUSION:
            self._show_conclusion()
            return

        # -- 5b. Normal policy decisions ----------------------------------------
        if decision.action == "chat" or (
            decision.action == "clarify" and not decision.message
        ):
            # Pure conversation -- delegate to ChatController with full state context
            context = self._chat_context()
            self._chat.chat(text, context=context)

        elif decision.action == "explain":
            context = self._chat_context()
            self._chat.chat(text, context=context)

        elif decision.action == "plan":
            self._show_plan()

        elif decision.action == "clarify":
            console.print()
            div("clarification needed")
            console.print()
            for line in (decision.message or "").splitlines():
                console.print(f"  [{P.TEXT}]{line}[/]")
            console.print()
            div()

        elif decision.action == "suggest":
            console.print()
            div("suggestion")
            console.print()
            if decision.message:
                for line in decision.message.splitlines():
                    console.print(f"  [{P.TEXT}]{line}[/]")
            elif decision.pending:
                console.print(
                    f"  [{P.MUTED}]I would run:[/] "
                    f"[{P.PRIMARY}]{decision.pending.command_str}[/]"
                )
                console.print(
                    f"  [{P.MUTED}]To execute it use:[/] "
                    f"[{P.PRIMARY}]autopwn {decision.pending.target}[/]  "
                    f"[{P.DIM}]or[/]  [{P.PRIMARY}]scan {decision.pending.target}[/]"
                )
            console.print()
            div()

        elif decision.action == "confirm":
            self._propose_action(decision.pending)

        elif decision.action == "execute":
            self._dispatch_pending_action(decision.pending)


    # ── action proposal (confirmation prompt) ─────────────────────────────

    def _propose_action(self, action: "PendingAction") -> None:
        """Show action preview and store in ConfirmationManager."""
        self._confirm.set(action)
        console.print()
        div("proposed action")
        console.print()
        console.print(f"  [{P.MUTED}]I can run:[/]")
        console.print()
        console.print(
            f"  [{P.PRIMARY}]{action.command_str}[/]"
        )
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
            f"  [{P.AMBER}]Confirm?[/]  "
            f"[{P.PRIMARY}]yes[/]  [{P.DIM}]/[/]  [{P.RED}]no[/]"
        )
        console.print()
        div()

    # ── dispatch a confirmed pending action ─────────────────────────────

    def _dispatch_pending_action(self, action: "PendingAction") -> None:
        """
        Execute a confirmed PendingAction.

        Special case: autopwn actions are routed to engine.run(), not dispatch.
        All others go through Dispatcher.dispatch().
        """
        from hydrasight.services.action_planner import PendingAction as _PA

        # Special: full engagement
        if action.tool_hint == "autopwn":
            target = action.target
            if not is_valid_ip(target):
                err(f"invalid target ip: {target}")
                return
            kali_ok, _ = self.kali.health()
            ai_ok,   _ = self.ai.health()
            if not kali_ok:
                err("kali-server-mcp offline — start it first")
                return
            if not ai_ok:
                err("ollama offline — start with: ollama serve")
                return
            try:
                self.engine.run(target)
            except Exception:  # noqa: BLE001
                console.print_exception(show_locals=False)
            finally:
                self.dispatcher.canonical_target = None
            return

        # Standard tool dispatch
        tool_call = action.tool_call
        if not tool_call:
            err("no tool_call in pending action")
            return

        tool_label = TOOL_LABELS.get(
            tool_call.get("tool", ""), tool_call.get("tool", "?")
        )
        task_line(tool_label)

        old_target = self.dispatcher.canonical_target
        self.dispatcher.canonical_target = action.target
        try:
            with spinner("executing") as prog:
                prog.add_task("t", total=None)
                t_name, output, elapsed = self.dispatcher.dispatch(tool_call)
        finally:
            self.dispatcher.canonical_target = old_target

        self.tool_count += 1
        warnings = Parser.validate(t_name, output, elapsed)
        result_line(t_name, elapsed, len(output), warnings)
        raw_output(output, self.verbosity)
        self.engine._ingest(output, "MANUAL")

        with spinner("analysing") as prog:
            prog.add_task("t", total=None)
            analysis = self.ai.ask(
                f"Tool: {t_name}\nOutput:\n{output[:3000]}\n\n"
                "Analyse using PORTS/VULNS/CREDS/SESSIONS/NOTES format."
            )
        if analysis:
            analysis_panel(analysis)
        stats_line(self.findings)

    # ── stateful chat context helper ──────────────────────────────────────

    def _chat_context(self) -> Optional[str]:
        """
        Build a compact, deterministic HydraSight state block for chat prompts.

        This replaces the old one-line _findings_context() and gives the
        conversational model full awareness of:
          - current target and risk level
          - open ports and top services
          - vulnerability summary (count + top finding)
          - captured credentials / sessions
          - planned next phases (from engine planner state)
          - strict rules: no invented execution, no fake output
        """
        f = self.findings
        target = (
            f.target
            or self.dispatcher.canonical_target
            or None
        )

        lines: list[str] = [
            "=== HydraSight Engagement Context ===",
        ]

        if target:
            risk = f.overall_risk if f.has_data else "NONE"
            lines.append(f"Target     : {target}  |  Risk: {risk}")
        else:
            lines.append("Target     : none (no engagement started yet)")

        if f.ports:
            top_ports = ", ".join(
                f"{p['port']}/{p.get('service','?')}" for p in f.ports[:8]
            )
            lines.append(f"Open ports : {len(f.ports)} discovered — {top_ports}{'...' if len(f.ports) > 8 else ''}")
        else:
            lines.append("Open ports : none discovered")

        if f.vulns:
            top_vuln = f.vulns[0]
            lines.append(
                f"Vulns      : {len(f.vulns)} finding(s) — "
                f"top: {top_vuln.get('name','?')} [{top_vuln.get('severity','?')}]"
            )
        else:
            lines.append("Vulns      : none identified")

        if f.credentials:
            lines.append(f"Credentials: {len(f.credentials)} captured")
        if f.hashes:
            lines.append(f"Hashes     : {len(f.hashes)} captured")
        if f.sessions:
            lines.append(f"Sessions   : {len(f.sessions)} active")

        # Planned next phases
        state = getattr(self.engine, "_state", None)
        if state and hasattr(state, "remaining_phases") and state.remaining_phases:
            phases = ", ".join(str(ph) for ph in state.remaining_phases[:4])
            lines.append(f"Next phases: {phases}")
        elif target and f.has_data:
            lines.append("Next phases: use 'plan' to see engagement roadmap")

        lines += [
            "======================================",
            "RULES: You are the HydraSight operator assistant.",
            "- NEVER invent scan output, credentials, or tool results.",
            "- NEVER claim you are running or have run a tool.",
            "- Only describe what is shown above. Suggest real HydraSight actions.",
            "- Supported commands: autopwn <ip>, scan <ip>, verify, suggest, plan, conclusion.",
        ]
        return "\n".join(lines)

    def _findings_context(self) -> Optional[str]:
        """Legacy one-liner for backward compatibility. Prefer _chat_context()."""
        return self._chat_context()

    # ── /run path (only explicit operator action, needs target) ──────────────

    def _on_run(self, action_text: str) -> None:
        """
        Handle /run <action> input.

        Attempts to match *action_text* against known security intent patterns.
        If no match → prints safe error, NEVER falls through to AI execution.
        Requires a known target — does NOT use stale canonical_target from
        a previous session; uses findings.target or asks the operator.

        SAFETY: this is the ONLY place in the Shell that may call route_intent()
        and dispatch a tool. It is only reachable via explicit /run prefix.
        """
        if not action_text.strip():
            warn("usage: /run <action>  e.g. /run check smb on 192.168.1.10")
            return

        # Resolve target from action text or findings
        # Try to extract IP from the action text first
        import re as _re
        ip_match = _re.search(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", action_text
        )
        explicit_ip = ip_match.group(1) if ip_match else None
        target = (
            explicit_ip
            or self.findings.target
            or None
        )

        if not target:
            warn(
                "no target known — include an IP in your /run command, "
                "e.g. /run check smb on 192.168.1.10"
            )
            return

        if not is_valid_ip(target):
            err(f"invalid ip extracted: {target}")
            return

        routed = route_intent(action_text, target)
        if not routed:
            warn(
                f"no matching security action for: '{action_text[:80]}'  "
                f"[{P.DIM}]known patterns: smb vuln, smb enum, smbclient enum, ssh check, "
                f"ftp check, vuln scan[/]"
            )
            info(
                "for full engagement use [bold]autopwn <ip>[/]  "
                "or [bold]scan <ip>[/]"
            )
            return

        # Confirmed: we have a match — execute the tool
        tool_label = TOOL_LABELS.get(routed.get("tool", ""), routed.get("tool", "?"))
        info(f"/run matched → {tool_label} on {target}")
        task_line(tool_label)

        # Scope canonical_target strictly to this call
        old_target = self.dispatcher.canonical_target
        self.dispatcher.canonical_target = target
        try:
            with spinner("executing") as prog:
                prog.add_task("t", total=None)
                t_name, output, elapsed = self.dispatcher.dispatch(routed)
        finally:
            # ALWAYS restore — never leave stale target
            self.dispatcher.canonical_target = old_target

        self.tool_count += 1
        warnings = Parser.validate(t_name, output, elapsed)
        result_line(t_name, elapsed, len(output), warnings)
        raw_output(output, self.verbosity)
        self.engine._ingest(output, "MANUAL")

        # Analysis uses orchestration AI (which has tool system prompt),
        # but ONLY for structured output parsing — not for new tool calls.
        with spinner("analysing") as prog:
            prog.add_task("t", total=None)
            analysis = self.ai.ask(
                f"Tool: {t_name}\nOutput:\n{output[:3000]}\n\n"
                "Analyse using PORTS/VULNS/CREDS/SESSIONS/NOTES format."
            )
        if analysis:
            analysis_panel(analysis)
        stats_line(self.findings)


    # ── exit ──────────────────────────────────────────────────────────────────

    def _exit(self) -> None:
        console.print()
        info("shutting down")
        if self.cfg.get("auto_save", True) and self.findings.has_data:
            self._save_json(
                str(
                    self._out()
                    / f"autosave_exit_{int(time.time())}.json"
                )
            )
        self._show_stats()
        self._rl_save()
        ok("session terminated cleanly")
        console.print()

    # ── main REPL loop ────────────────────────────────────────────────────────

    def run(self) -> None:  # noqa: C901
        console.print()
        console.print(f"[{P.PRIMARY}]{BANNER}[/]")
        console.print()
        console.print(
            f"  [{P.MUTED}]v{VERSION}[/]  [{P.DIM}]│[/]"
            f"  [{P.MUTED}]codename {CODENAME}[/]  [{P.DIM}]│[/]"
            f"  [{P.MUTED}]authorized testing only[/]"
        )
        console.print()
        self._show_status()
        console.print(
            f"\n  [{P.MUTED}]type[/] [{P.PRIMARY}]help[/]"
            f" [{P.MUTED}]for commands  or  [/]"
            f"[{P.PRIMARY}]autopwn <ip>[/]"
            f" [{P.MUTED}]to begin engagement[/]\n"
        )

        while True:
            try:
                raw = self._prompt()
            except (EOFError, KeyboardInterrupt):
                raw = "exit"
            if not raw:
                continue
            self._rl_save()

            # ── DETERMINISTIC INPUT CLASSIFICATION ─────────────────────────────
            # CommandRouter.classify() is a pure function with no side effects.
            # It decides the execution path BEFORE any AI or tool call happens.
            ci = self._router.classify(raw)

            try:
                if ci.cls == InputClass.CHAT:
                    # ALL bare text → NL intent pipeline (may confirm+execute)
                    self._on_bare_text(ci.raw)
                    continue

                if ci.cls == InputClass.ASK:
                    # /ask prefix → force safe chat, NEVER executes tools
                    self._on_bare_text(ci.tail or ci.raw)
                    continue

                if ci.cls == InputClass.RUN:
                    # /run prefix → explicit tool routing only
                    self._on_run(ci.tail)
                    continue

                # ci.cls == InputClass.BUILTIN — handle known commands
                parts = ci.raw.split()
                cmd   = ci.command

                if cmd in ("exit", "quit"):
                    self._exit()
                    break
                elif cmd == "help":
                    self._show_help()
                elif cmd == "status":
                    self._show_status()
                elif cmd == "config":
                    self._show_config()
                elif cmd == "clear":
                    self.findings.reset()
                    self.ai.reset()
                    self._chat.reset()
                    self._confirm.clear()              # discard any pending action
                    self.dispatcher.canonical_target = None
                    ok("session state cleared")
                elif cmd == "findings":
                    self._show_findings()
                elif cmd in _FILTER_TYPES:
                    self._show_findings(filter_type=cmd)
                elif cmd == "stats":
                    self._show_stats()
                elif cmd == "history":
                    self._show_history()
                elif cmd == "abort":
                    self.engine.abort()
                elif cmd == "roe":
                    self._show_roe()
                elif cmd == "verify":
                    self._run_verify()
                elif cmd == "suggest":
                    self._show_suggest()
                elif cmd == "plan":
                    self._show_plan()
                elif cmd == "conclusion":
                    self._show_conclusion()
                elif cmd == "mode":
                    if len(parts) >= 2 and parts[1].lower() in VALID_MODES:
                        new_mode = parts[1].lower()
                        self.cfg["execution_mode"] = new_mode
                        _mode_labels = {
                            "confirm": "always ask for confirmation",
                            "auto"   : "run high-confidence requests automatically",
                            "never"  : "explain/suggest only — never execute from NL",
                        }
                        ok(f"execution mode \u2192 [bold]{new_mode}[/]")
                        label("mode", _mode_labels.get(new_mode, new_mode), 18)
                    else:
                        current = self.cfg.get("execution_mode", "confirm")
                        warn(f"usage: mode confirm|auto|never  (current: {current})")
                elif cmd == "verbose":
                    if len(parts) >= 2 and parts[1].isdigit():
                        v = max(0, min(3, int(parts[1])))
                        self.cfg["verbosity"] = v
                        self.engine.verbosity = v
                        self.verbosity        = v
                        ok(
                            f"verbosity set to {v} "
                            f"({['quiet','normal','verbose','debug'][v]})"
                        )
                    else:
                        warn("usage: verbose 0|1|2|3")
                elif cmd == "save":
                    path = (
                        parts[1] if len(parts) >= 2
                        else str(
                            self._out()
                            / f"findings_{int(time.time())}.json"
                        )
                    )
                    self._save_json(path)
                elif cmd == "report":
                    if len(parts) < 2:
                        warn("usage: report <ip>")
                    else:
                        ts_str = datetime.datetime.now().strftime(
                            "%Y%m%d_%H%M%S"
                        )
                        self._save_pdf(
                            parts[1],
                            str(
                                self._out()
                                / f"report_{parts[1]}_{ts_str}.pdf"
                            ),
                        )
                elif cmd == "autopwn":
                    if len(parts) < 2:
                        warn("usage: autopwn <ip>")
                    else:
                        target = parts[1]
                        if not is_valid_ip(target):
                            err(f"invalid ip: {target}")
                            continue
                        kali_ok, _ = self.kali.health()
                        ai_ok,   _ = self.ai.health()
                        if not kali_ok:
                            err(
                                "kali-server-mcp offline "
                                "— start it first"
                            )
                            continue
                        if not ai_ok:
                            err(
                                "ollama offline "
                                "— start with: ollama serve"
                            )
                            continue
                        try:
                            self.engine.run(target)
                        except Exception:  # noqa: BLE001
                            console.print_exception(show_locals=False)
                        finally:
                            # Always clear canonical_target after engagement
                            self.dispatcher.canonical_target = None
                        if self.cfg.get("auto_save", True):
                            ts_str = datetime.datetime.now().strftime(
                                "%Y%m%d_%H%M%S"
                            )
                            jsn = str(
                                self._out()
                                / f"autopwn_{target}_{ts_str}.json"
                            )
                            self._save_json(jsn)
                            if self.cfg.get("auto_pdf", True):
                                self._save_pdf(
                                    target,
                                    jsn.replace(".json", ".pdf"),
                                )
                elif cmd == "scan":
                    if len(parts) < 2:
                        warn("usage: scan <ip>")
                    else:
                        target = parts[1]
                        if not is_valid_ip(target):
                            err(f"invalid ip: {target}")
                            continue
                        info(f"deep scan on {target}")
                        self.dispatcher.canonical_target = target
                        try:
                            self.engine._ask_and_run(
                                f"nmap scan {target} with scan_type -sV -sC "
                                f"and ports {self.cfg['deep_scan_range']} "
                                f"and additional args -T4 -Pn",
                                "DEEP_SCAN",
                            )
                        finally:
                            # Always clear after scan
                            self.dispatcher.canonical_target = None
                else:
                    # Hard safety fallback — should never reach here since
                    # CommandRouter maps all non-builtin input to CHAT.
                    self._on_bare_text(raw)
            except Exception as exc:  # noqa: BLE001
                err(f"command failed: {exc}")
                self.log.exception("command exception")
