"""Factory selecting the correct post-access handler for a session record."""

from __future__ import annotations

import logging

from hydrasight.services.post_access.base import BasePostAccessHandler
from hydrasight.services.post_access.ftp_handler import FTPAccessHandler
from hydrasight.services.post_access.msf_handlers import (
    MeterpreterHandler,
    ShellHandler,
)
from hydrasight.services.post_access.ssh_handler import SSHAccessHandler
from hydrasight.services.post_access.types import AccessType
from hydrasight.services.post_access.web_handler import WebAdminHandler


class PostAccessHandler:
    """Factory — select the correct handler from a session record or access type."""

    _REGISTRY: dict[AccessType, type[BasePostAccessHandler]] = {
        AccessType.METERPRETER: MeterpreterHandler,
        AccessType.SHELL: ShellHandler,
        AccessType.SSH: SSHAccessHandler,
        AccessType.FTP: FTPAccessHandler,
        AccessType.WEB_ADMIN: WebAdminHandler,
    }

    @classmethod
    def for_session(
        cls,
        session: dict,
        log: logging.Logger,
        access_type: AccessType | None = None,
    ) -> BasePostAccessHandler:
        """Return the appropriate handler for a session record.

        ``access_type`` overrides auto-detection. Auto-detection checks:
        - ``session["payload"]`` containing "meterpreter" → MeterpreterHandler
        - "cmd/unix/reverse" or a shell payload          → ShellHandler
        - payload == "ftp"                              → FTPAccessHandler
        - payload in ("web_admin", "http", "https")     → WebAdminHandler
        - ``session["username"]`` present               → SSHAccessHandler
        - default                                       → MeterpreterHandler
        """
        if access_type:
            handler_cls = cls._REGISTRY.get(access_type, MeterpreterHandler)
            return handler_cls(log, session)

        payload = str(session.get("payload", "")).lower()
        if "meterpreter" in payload:
            return MeterpreterHandler(log, session)
        if "cmd/unix" in payload or ("shell" in payload and "web" not in payload):
            return ShellHandler(log, session)
        if payload == "ftp":
            return FTPAccessHandler(log, session)
        if payload in ("web_admin", "http", "https"):
            return WebAdminHandler(log, session)
        if session.get("username"):
            return SSHAccessHandler(log, session)
        return MeterpreterHandler(log, session)

    @classmethod
    def register(
        cls,
        access_type: AccessType,
        handler_cls: type[BasePostAccessHandler],
    ) -> None:
        """Register a new handler type (extension point)."""
        cls._REGISTRY[access_type] = handler_cls
