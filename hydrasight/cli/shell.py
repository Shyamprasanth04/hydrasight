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

Architecture:
  Shell owns the REPL loop, readline, signal handling, and startup.
  All logic is delegated to ShellHandlers (engagement, NL pipeline,
  builtins) and shell_renderer (display).
"""

import json
import logging
import signal
from pathlib import Path
from typing import TYPE_CHECKING

from hydrasight.cli.display import (
    console,
    stats_line,
    warn,
)

if TYPE_CHECKING:
    from hydrasight.core.session_manager import SessionManager

from hydrasight.cli.shell_handlers import ShellHandlers
from hydrasight.cli.shell_renderer import render_status
from hydrasight.config.defaults import BANNER, CODENAME, VERSION, P
from hydrasight.core.engine import Engine
from hydrasight.integrations.kali_api import KaliAPI
from hydrasight.models.findings import Findings
from hydrasight.models.roe import RulesOfEngagement
from hydrasight.services.action_planner import ActionPlanner
from hydrasight.services.ai_client import AIClient
from hydrasight.services.chat_controller import ChatController
from hydrasight.services.command_router import CommandRouter, InputClass
from hydrasight.services.confirmation_manager import ConfirmationManager
from hydrasight.services.dispatcher import Dispatcher
from hydrasight.services.execution_policy import ExecutionPolicy
from hydrasight.services.intent_classifier import IntentClassifier
from hydrasight.services.session_manager import SessionManager

try:
    import readline as _rl

    _READLINE_OK = True
except ImportError:
    _READLINE_OK = False

# ── command list for tab completion ───────────────────────────────────────────
COMMANDS = [
    "autopwn",
    "scan",
    "findings",
    "stats",
    "save",
    "report",
    "clear",
    "history",
    "status",
    "verbose",
    "help",
    "exit",
    "quit",
    "abort",
    "config",
    "roe",
    "verify",
    "suggest",
    "plan",
    "conclusion",
    "ports",
    "vulns",
    "creds",
    "hashes",
    "sessions",
    "resume",
]


def _setup_log(log_file: str, verbosity: int) -> logging.Logger:
    level = {0: logging.ERROR, 1: logging.INFO, 2: logging.INFO, 3: logging.DEBUG}.get(
        verbosity, logging.INFO
    )
    logger = logging.getLogger("hydrasight")
    logger.setLevel(level)
    if not logger.handlers:
        try:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-7s] %(message)s"))
            logger.addHandler(fh)
        except (PermissionError, OSError) as exc:
            print(f"[!] Cannot write log file {log_file}: {exc}")
    return logger


def _completer(text: str, state: int) -> str | None:
    opts = [c for c in COMMANDS if c.startswith(text)]
    return opts[state] if state < len(opts) else None


if _READLINE_OK:
    _rl.set_completer(_completer)  # type: ignore[attr-defined]
    _rl.parse_and_bind("tab: complete")  # type: ignore[attr-defined]


class Shell:
    """Interactive REPL for HydraSight.

    This class owns:
      - REPL loop (run())
      - readline setup / save
      - signal handling
      - startup banner and status

    All logic is delegated to ShellHandlers.
    """

    HIST = ".hydrasight_history"
    ROE_FILE = "hydrasight.roe.json"

    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.log = _setup_log(cfg["log_file"], cfg["verbosity"])
        self.findings = Findings()
        self.kali = KaliAPI(cfg["kali_api_url"], self.log)
        self.ai = AIClient(
            cfg["ollama_url"],
            cfg["model"],
            cfg["context_size"],
            self.log,
            options=cfg.get("ollama_options_orchestrator"),
        )
        self.dispatcher = Dispatcher(self.kali, self.log, cfg)
        self.roe = self._load_roe()
        self.engine = Engine(
            self.ai,
            self.kali,
            self.dispatcher,
            self.findings,
            cfg,
            self.log,
            roe=self.roe,
            session_manager=SessionManager(cfg["output_dir"]),
        )
        self.session_manager = self.engine.session_manager
        self._chat_controller = ChatController(
            cfg["ollama_url"],
            cfg["model"],
            cfg["context_size"],
            self.log,
            options=cfg.get("ollama_options_chat"),
        )
        self._router = CommandRouter()

        # Build ShellHandlers with all services
        self._handlers = ShellHandlers(
            cfg=cfg,
            findings=self.findings,
            kali=self.kali,
            ai=self.ai,
            dispatcher=self.dispatcher,
            engine=self.engine,
            chat=self._chat_controller,
            intent=IntentClassifier(),
            planner=ActionPlanner(),
            confirm=ConfirmationManager(),
            policy=ExecutionPolicy(),
            roe=self.roe,
            log=self.log,
            session_manager=self.session_manager,
        )

        self._rl_init()
        signal.signal(signal.SIGINT, self._sigint)

    def _load_roe(self) -> RulesOfEngagement:
        """Load ROE from hydrasight.roe.json if present; else use permissive defaults."""
        p = Path(self.ROE_FILE)
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                roe = RulesOfEngagement.from_dict(data)
                return roe
            except Exception as exc:  # noqa: BLE001
                print(f"[!] roe load error: {exc} — using permissive defaults")
        return RulesOfEngagement.permissive()

    # ── handler delegation (test-friendly accessors) ──────────────────────────
    # These thin forwarders let tests address Shell as the single API boundary
    # without knowing about the Shell → ShellHandlers split from Phase 2.
    # Production code always goes through self._handlers directly.

    def _on_bare_text(self, text: str) -> None:
        """Delegate NL text to ShellHandlers.on_bare_text()."""
        self._handlers.on_bare_text(text)

    def _on_run(self, text: str) -> None:
        """Delegate /run text to ShellHandlers.on_run()."""
        self._handlers.on_run(text)

    def _chat_context(self) -> str | None:
        """Delegate to ShellHandlers._chat_context()."""
        return self._handlers._chat_context()

    # _dispatch_pending_action: property with setter so test mocks can replace it
    @property
    def _dispatch_pending_action(self):  # type: ignore[override]
        return self._handlers._dispatch_pending_action

    @_dispatch_pending_action.setter
    def _dispatch_pending_action(self, value) -> None:  # type: ignore[override]
        self._handlers._dispatch_pending_action = value  # type: ignore[method-assign]

    # _show_plan: property with setter for same reason
    @property
    def _show_plan(self):  # type: ignore[override]
        return self._handlers._show_plan

    @_show_plan.setter
    def _show_plan(self, value) -> None:  # type: ignore[override]
        self._handlers._show_plan = value  # type: ignore[method-assign]

    # _confirm: expose handlers' ConfirmationManager directly
    @property
    def _confirm(self):  # type: ignore[override]
        return self._handlers._confirm

    # _chat: expose handlers' ChatController directly so tests can mock .chat
    @property
    def _chat(self):  # type: ignore[override]
        return self._handlers._chat

    # _run_verify / _show_suggest / _show_conclusion: settable for test mocks
    @property
    def _run_verify(self):  # type: ignore[override]
        return self._handlers._run_verify

    @_run_verify.setter
    def _run_verify(self, value) -> None:  # type: ignore[override]
        self._handlers._run_verify = value  # type: ignore[method-assign]

    @property
    def _show_suggest(self):  # type: ignore[override]
        return self._handlers._show_suggest

    @_show_suggest.setter
    def _show_suggest(self, value) -> None:  # type: ignore[override]
        self._handlers._show_suggest = value  # type: ignore[method-assign]

    @property
    def _show_conclusion(self):  # type: ignore[override]
        return self._handlers._show_conclusion

    @_show_conclusion.setter
    def _show_conclusion(self, value) -> None:  # type: ignore[override]
        self._handlers._show_conclusion = value  # type: ignore[method-assign]


    # ── readline ──────────────────────────────────────────────────────────────

    def _rl_init(self) -> None:
        if not _READLINE_OK:
            return
        Path(self.HIST).touch(exist_ok=True)
        try:
            _rl.read_history_file(self.HIST)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass
        _rl.set_history_length(1000)  # type: ignore[attr-defined]

    def _rl_save(self) -> None:
        if not _READLINE_OK:
            return
        try:
            _rl.write_history_file(self.HIST)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass

    # ── signal handling ───────────────────────────────────────────────────────

    def _sigint(self, *_: object) -> None:
        self.engine.abort()
        warn("ctrl-c received — type 'exit' to quit cleanly")

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

    # ── main REPL loop ────────────────────────────────────────────────────────

    def run(self) -> None:
        console.print()
        console.print(f"[{P.PRIMARY}]{BANNER}[/]")
        console.print()
        console.print(
            f"  [{P.MUTED}]v{VERSION}[/]  [{P.DIM}]│[/]"
            f"  [{P.MUTED}]codename {CODENAME}[/]  [{P.DIM}]│[/]"
            f"  [{P.MUTED}]authorized testing only[/]"
        )
        console.print()
        render_status(self.kali, self.ai, self.cfg)
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

            # DETERMINISTIC INPUT CLASSIFICATION
            ci = self._router.classify(raw)

            try:
                if ci.cls == InputClass.CHAT:
                    self._handlers.on_bare_text(ci.raw)
                    continue

                if ci.cls == InputClass.ASK:
                    self._handlers.on_bare_text(ci.tail or ci.raw)
                    continue

                if ci.cls == InputClass.RUN:
                    self._handlers.on_run(ci.tail)
                    continue

                # ci.cls == InputClass.BUILTIN
                parts = ci.raw.split()
                should_continue = self._handlers.handle_builtin(ci.command, parts, ci.raw)
                if not should_continue:
                    self._rl_save()
                    break

            except Exception as exc:  # noqa: BLE001
                from hydrasight.cli.display import err

                err(f"command failed: {exc}")
                self.log.exception("command exception")
