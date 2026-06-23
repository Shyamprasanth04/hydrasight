"""
Shell handlers — engagement actions, NL pipeline, and builtin command dispatch.

Extracted from shell.py to keep the REPL boundary thin.
ShellHandlers holds references to all services and implements all
non-REPL-loop logic.  Shell calls into ShellHandlers for every
classified input.
"""

from __future__ import annotations

import datetime
import logging
import re as _re
import time
from pathlib import Path
from typing import TYPE_CHECKING

from hydrasight.cli.display import (
    analysis_panel,
    console,
    err,
    info,
    label,
    ok,
    raw_output,
    result_line,
    spinner,
    stats_line,
    task_line,
    warn,
)

if TYPE_CHECKING:
    from hydrasight.core.session_manager import SessionManager
    from hydrasight.models.planner_state import PlannerState

from hydrasight.cli.shell_renderer import (
    render_clarification,
    render_conclusion,
    render_config,
    render_findings,
    render_help,
    render_history,
    render_plan,
    render_proposed_action,
    render_roe,
    render_stats,
    render_status,
    render_suggest,
    render_suggestion,
    render_verify_results,
)
from hydrasight.config.defaults import TOOL_LABELS, P
from hydrasight.parsers import Parser
from hydrasight.reporting.json_reporter import save_json
from hydrasight.reporting.pdf_reporter import generate_pdf
from hydrasight.services.context_builder import ContextBuilder
from hydrasight.services.execution_policy import VALID_MODES
from hydrasight.services.intent_classifier import Intent
from hydrasight.services.intent_router import route_intent
from hydrasight.utils.ip_utils import is_valid_ip

if TYPE_CHECKING:
    from hydrasight.core.engine import Engine
    from hydrasight.integrations.kali_api import KaliAPI
    from hydrasight.models.findings import Findings
    from hydrasight.models.roe import RulesOfEngagement
    from hydrasight.services.action_planner import ActionPlanner, PendingAction
    from hydrasight.services.ai_client import AIClient
    from hydrasight.services.chat_controller import ChatController
    from hydrasight.services.confirmation_manager import ConfirmationManager
    from hydrasight.services.dispatcher import Dispatcher
    from hydrasight.services.execution_policy import ExecutionPolicy
    from hydrasight.services.intent_classifier import IntentClassifier

_FILTER_TYPES = frozenset({"ports", "vulns", "creds", "hashes", "sessions"})


class ShellHandlers:
    """Handles all REPL actions — NL pipeline, builtins, engagement commands.

    Shell creates one ShellHandlers and delegates all logic to it.
    ShellHandlers does NOT own the REPL loop, readline, or signal handling.
    """

    ROE_FILE = "hydrasight.roe.json"

    def __init__(
        self,
        *,
        cfg: dict,
        findings: Findings,
        kali: KaliAPI,
        ai: AIClient,
        dispatcher: Dispatcher,
        engine: Engine,
        chat: ChatController,
        intent: IntentClassifier,
        planner: ActionPlanner,
        confirm: ConfirmationManager,
        policy: ExecutionPolicy,
        roe: RulesOfEngagement,
        log: logging.Logger,
        session_manager: SessionManager | None = None,
    ) -> None:
        self.cfg = cfg
        self.findings = findings
        self.kali = kali
        self.ai = ai
        self.dispatcher = dispatcher
        self.engine = engine
        self._chat = chat
        self._intent = intent
        self._planner = planner
        self._confirm = confirm
        self._policy = policy
        self.roe = roe
        self.log = log
        self.session_manager = session_manager
        self.start_time = time.time()
        self.tool_count = 0
        self.verbosity = cfg["verbosity"]

    # ── output directory ──────────────────────────────────────────────────────

    def _out(self) -> Path:
        d = Path(self.cfg["output_dir"])
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ── save helpers ──────────────────────────────────────────────────────────

    def save_json(self, path: str) -> bool:
        if save_json(self.findings, path):
            ok(f"saved   {path}")
            return True
        err(f"save failed: {path}")
        return False

    def save_pdf(self, target: str, path: str) -> bool:
        info("generating pdf report")
        if generate_pdf(target, self.findings, path):
            ok(f"pdf     {path}")
            return True
        return False

    # ── chat context ──────────────────────────────────────────────────────────

    def _chat_context(self) -> str | None:
        """Build compact engagement context for the chat model."""
        state = getattr(self.engine, "_state", None)
        canonical = getattr(self.dispatcher, "canonical_target", None)
        return ContextBuilder.build(
            self.findings,
            state,
            self.cfg,
            canonical_target=canonical,
        )

    # ── engine state helper ───────────────────────────────────────────────────

    def _engine_state(self) -> PlannerState | None:
        return getattr(self.engine, "_state", None)

    # ── NL intent pipeline ────────────────────────────────────────────────────

    def on_bare_text(self, user_input: str) -> None:
        """Smart NL handler — classify, policy, dispatch.

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

        # Step 1: check if this is a yes/no reply to a pending action
        if self._confirm.has_pending and self._confirm.is_yes_no(text):
            resolution, action = self._confirm.try_resolve(text)
            if resolution == "yes" and action:
                self._dispatch_pending_action(action)
            elif resolution == "no":
                ok("action cancelled")
            return

        # Step 2: classify intent
        result = self._intent.classify(text)

        # A new substantive request replaces any pending action
        if not self._confirm.is_yes_no(text) and result.intent not in (Intent.CHAT, Intent.EXPLAIN):
            self._confirm.clear()

        # Step 3: build action plan if needed
        pending = None
        if result.intent == Intent.EXECUTE_ACTION:
            pending = self._planner.plan(
                result,
                fallback_target=self.findings.target,
                cfg=self.cfg,
            )

        # Step 4: apply execution policy
        mode = self.cfg.get("execution_mode", "confirm")
        decision = self._policy.decide(result, pending, mode)

        # Step 5: dispatch decision
        # 5a. Operational meta-intents — bypass chat entirely
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

        # 5b. Normal policy decisions
        if decision.action == "chat" or (decision.action == "clarify" and not decision.message):
            context = self._chat_context()
            self._chat.chat(text, context=context)

        elif decision.action == "plan":
            self._show_plan()

        elif decision.action == "clarify":
            render_clarification(decision.message)

        elif decision.action == "suggest":
            render_suggestion(decision.message, decision.pending)

        elif decision.action == "confirm" and decision.pending:
            self._propose_action(decision.pending)

        elif decision.action == "execute" and decision.pending:
            self._dispatch_pending_action(decision.pending)

    # ── plan / verify / suggest / conclusion rendering ────────────────────────

    def _show_plan(self) -> None:
        """Render the engagement plan. Extracted so tests can intercept it."""
        render_plan(self.findings, self.roe, self._engine_state())

    def _run_verify(self) -> None:
        """Run verifier. Extracted so tests can intercept it."""
        self.handle_verify()

    def _show_suggest(self) -> None:
        """Render access suggestions. Extracted so tests can intercept it."""
        render_suggest(self.findings, self.roe, self._engine_state())

    def _show_conclusion(self) -> None:
        """Render engagement conclusion. Extracted so tests can intercept it."""
        render_conclusion(self.findings)

    # ── action proposal (confirmation prompt) ─────────────────────────────────

    def _propose_action(self, action: PendingAction) -> None:
        """Show action preview and store in ConfirmationManager."""
        self._confirm.set(action)
        render_proposed_action(action)

    # ── dispatch a confirmed pending action ───────────────────────────────────

    def _dispatch_pending_action(self, action: PendingAction) -> None:
        """Execute a confirmed PendingAction."""
        # Special: full engagement
        if action.tool_hint == "autopwn":
            target = action.target
            if not target or not is_valid_ip(target):
                err(f"invalid target ip: {target}")
                return
            kali_ok, _ = self.kali.health()
            ai_ok, _ = self.ai.health()
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

        tool_label = TOOL_LABELS.get(tool_call.get("tool", ""), tool_call.get("tool", "?"))
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

    # ── /run handler ──────────────────────────────────────────────────────────

    def on_run(self, action_text: str) -> None:
        """Handle /run <action> input."""
        if not action_text.strip():
            warn("usage: /run <action>  e.g. /run check smb on 192.168.1.10")
            return

        ip_match = _re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", action_text)
        explicit_ip = ip_match.group(1) if ip_match else None
        target = explicit_ip or self.findings.target or None

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
            info("for full engagement use [bold]autopwn <ip>[/]  or [bold]scan <ip>[/]")
            return

        tool_label = TOOL_LABELS.get(routed.get("tool", ""), routed.get("tool", "?"))
        info(f"/run matched → {tool_label} on {target}")
        task_line(tool_label)

        old_target = self.dispatcher.canonical_target
        self.dispatcher.canonical_target = target
        try:
            with spinner("executing") as prog:
                prog.add_task("t", total=None)
                t_name, output, elapsed = self.dispatcher.dispatch(routed)
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

    # ── verify handler ────────────────────────────────────────────────────────

    def handle_verify(self) -> None:
        """Run verifier against all unverified findings."""
        from hydrasight.services.verifier import VerifierService

        if not self.findings.finding_records:
            warn("no typed finding records yet — run autopwn or scan first")
            return
        target = self.findings.target or self.dispatcher.canonical_target or ""
        if not target:
            warn("no target set — run autopwn or scan first")
            return
        kali_ok, msg = self.kali.health()
        if not kali_ok:
            err(f"kali-server offline: {msg}")
            return
        verifier = VerifierService(self.kali, self.log, target)
        info(f"verifying findings against {target}")
        results = verifier.verify_findings(self.findings, only_high_and_above=False)
        if not results:
            info("all findings already verified or no strategy available")
            return
        render_verify_results(results)

    # ── builtin command dispatch ──────────────────────────────────────────────

    def handle_builtin(self, cmd: str, parts: list[str], raw: str) -> bool:
        """Handle a builtin command. Returns True to continue REPL, False to exit."""
        if cmd in ("exit", "quit"):
            self._handle_exit()
            return False

        if cmd == "help":
            render_help()
        elif cmd == "status":
            render_status(self.kali, self.ai, self.cfg)
        elif cmd == "config":
            render_config(self.cfg)
        elif cmd == "clear":
            self.findings.reset()
            self.ai.reset()
            self._chat.reset()
            self._confirm.clear()
            self.dispatcher.canonical_target = None
            ok("session state cleared")
        elif cmd == "findings":
            render_findings(self.findings)
        elif cmd in _FILTER_TYPES:
            render_findings(self.findings, filter_type=cmd)
        elif cmd == "stats":
            render_stats(self.findings, self.ai, self.start_time, self.tool_count)
        elif cmd == "history":
            if len(parts) > 1:
                self._handle_sessions(["sessions"] + parts[1:])
            else:
                render_history(self.ai)
        elif cmd == "sessions":
            self._handle_sessions(parts)
        elif cmd == "resume":
            self._handle_resume(parts)
        elif cmd == "abort":
            self.engine.abort()
        elif cmd == "roe":
            render_roe(self.roe, self.ROE_FILE)
        elif cmd == "verify":
            self.handle_verify()
        elif cmd == "suggest":
            render_suggest(self.findings, self.roe, self._engine_state())
        elif cmd == "plan":
            render_plan(self.findings, self.roe, self._engine_state())
        elif cmd == "conclusion":
            render_conclusion(self.findings)
        elif cmd == "mode":
            self._handle_mode(parts)
        elif cmd == "verbose":
            self._handle_verbose(parts)
        elif cmd == "save":
            path = (
                parts[1]
                if len(parts) >= 2
                else str(self._out() / f"findings_{int(time.time())}.json")
            )
            self.save_json(path)
        elif cmd == "report":
            if len(parts) < 2:
                warn("usage: report <ip>")
            else:
                ts_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                self.save_pdf(
                    parts[1],
                    str(self._out() / f"report_{parts[1]}_{ts_str}.pdf"),
                )
        elif cmd == "autopwn":
            self._handle_autopwn(parts)
        elif cmd == "scan":
            self._handle_scan(parts)
        else:
            # Safety fallback — should never reach here
            self.on_bare_text(raw)

        return True

    # ── specific builtin handlers ─────────────────────────────────────────────

    def _handle_mode(self, parts: list[str]) -> None:
        if len(parts) >= 2 and parts[1].lower() in VALID_MODES:
            new_mode = parts[1].lower()
            self.cfg["execution_mode"] = new_mode
            _mode_labels = {
                "confirm": "always ask for confirmation",
                "auto": "run high-confidence requests automatically",
                "never": "explain/suggest only — never execute from NL",
            }
            ok(f"execution mode → [bold]{new_mode}[/]")
            label("mode", _mode_labels.get(new_mode, new_mode), 18)
        else:
            current = self.cfg.get("execution_mode", "confirm")
            warn(f"usage: mode confirm|auto|never  (current: {current})")

    def _handle_verbose(self, parts: list[str]) -> None:
        if len(parts) >= 2 and parts[1].isdigit():
            v = max(0, min(3, int(parts[1])))
            self.cfg["verbosity"] = v
            self.engine.verbosity = v
            self.verbosity = v
            ok(f"verbosity set to {v} ({['quiet', 'normal', 'verbose', 'debug'][v]})")
        else:
            warn("usage: verbose 0|1|2|3")

    def _handle_autopwn(self, parts: list[str]) -> None:
        if len(parts) < 2:
            warn("usage: autopwn <ip>")
            return
        target = parts[1]
        if not is_valid_ip(target):
            err(f"invalid ip: {target}")
            return
        kali_ok, _ = self.kali.health()
        ai_ok, _ = self.ai.health()
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
        if self.cfg.get("auto_save", True):
            ts_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            jsn = str(self._out() / f"autopwn_{target}_{ts_str}.json")
            self.save_json(jsn)
            if self.cfg.get("auto_pdf", True):
                self.save_pdf(target, jsn.replace(".json", ".pdf"))

    def _handle_scan(self, parts: list[str]) -> None:
        if len(parts) < 2:
            warn("usage: scan <ip>")
            return
        target = parts[1]
        if not is_valid_ip(target):
            err(f"invalid ip: {target}")
            return
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
            self.dispatcher.canonical_target = None

    def _handle_exit(self) -> None:
        console.print()
        info("shutting down")
    def _handle_sessions(self, parts: list[str]) -> None:
        if not self.session_manager:
            warn("session manager is not enabled")
            return

        from hydrasight.cli.shell_renderer import render_session_detail, render_session_list

        if len(parts) > 1:
            session_id = parts[1]
            loaded = self.session_manager.load_session(session_id)
            if not loaded:
                err(f"session {session_id} not found")
                return
            session_f, session_ps = loaded
            render_session_detail(session_f, session_ps, session_id)
        else:
            summaries = self.session_manager.list_sessions()
            render_session_list(summaries)

    def _handle_resume(self, parts: list[str]) -> None:
        if len(parts) < 2:
            warn("usage: resume <session_id>")
            return

        session_id = parts[1]
        if not self.session_manager:
            warn("session manager is not enabled")
            return

        loaded = self.session_manager.load_session(session_id)
        if not loaded:
            err(f"session {session_id} not found")
            return

        session_f, session_ps = loaded

        # Deep update the existing findings object so Shell reference stays valid
        with self.findings._Findings__lock:  # type: ignore
            self.findings.target = session_f.target
            self.findings.started_at = session_f.started_at
            self.findings.host_info = session_f.host_info
            self.findings.ports = session_f.ports
            self.findings.vulns = session_f.vulns
            self.findings.finding_records = session_f.finding_records
            self.findings.credentials = session_f.credentials
            self.findings.hashes = session_f.hashes
            self.findings.dirs = session_f.dirs
            self.findings.sessions = session_f.sessions
            self.findings.timeline = session_f.timeline

        self.engine._state = session_ps
        self.dispatcher.canonical_target = session_f.target

        ok(f"resumed session [bold]{session_id}[/]")
        info(f"target: {session_f.target}")
        if session_ps:
            info(f"state: {len(session_ps.phase_results)} phases completed")
