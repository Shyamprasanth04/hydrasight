"""Post-access handler package.

Re-exports the public API so the historical single-module import path keeps
working (``from hydrasight.services.post_access import ...``).

Usage::

    handler = PostAccessHandler.for_session(session_record, log)
    result = handler.execute(dispatcher, target, lhost, lport, cfg)
"""

from __future__ import annotations

from hydrasight.services.post_access.base import BasePostAccessHandler
from hydrasight.services.post_access.factory import PostAccessHandler
from hydrasight.services.post_access.ftp_handler import FTPAccessHandler
from hydrasight.services.post_access.msf_handlers import (
    MeterpreterHandler,
    ShellHandler,
)
from hydrasight.services.post_access.ssh_handler import SSHAccessHandler
from hydrasight.services.post_access.types import (
    AccessType,
    PostAccessResult,
)
from hydrasight.services.post_access.web_handler import WebAdminHandler

__all__ = [
    "AccessType",
    "PostAccessResult",
    "BasePostAccessHandler",
    "MeterpreterHandler",
    "ShellHandler",
    "SSHAccessHandler",
    "FTPAccessHandler",
    "WebAdminHandler",
    "PostAccessHandler",
]
