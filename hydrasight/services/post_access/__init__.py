"""Post-access handler package.

Re-exports the public API so the historical single-module import path keeps
working (``from hydrasight.services.post_access import ...``).

Usage::

    handler = PostAccessHandler.for_session(session_record, log)
    result = handler.execute(dispatcher, target, lhost, lport, cfg)
"""

from __future__ import annotations

from .base import BasePostAccessHandler
from .factory import PostAccessHandler
from .ftp_handler import FTPAccessHandler
from .msf_handlers import (
    MeterpreterHandler,
    ShellHandler,
)
from .ssh_handler import SSHAccessHandler
from .types import (
    AccessType,
    PostAccessResult,
)
from .web_handler import WebAdminHandler

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
