"""HTTP wrapper around the kali-server-mcp REST API."""

import logging
import os
import re
from urllib.parse import urlsplit

import requests

# ── bridge route catalogue ────────────────────────────────────────────────────
# kali-server-mcp is a family of small Flask bridges, not one binary:
# digininja's kali-linux-mcp, i3T4AN's Kali_Linux_MCP, the Kali
# ``mcp-kali-server`` package and the zebbern-kali-mcp build all spell their
# routes slightly differently.  HydraSight therefore probes a short list of
# well-known routes instead of hard-coding a single path, so a bridge that
# only implements part of the API is still recognised (and reported) instead
# of surfacing a bare ``404 Client Error``.
HEALTH_ROUTES: tuple[str, ...] = ("/health", "/api/health")
COMMAND_ROUTES: tuple[str, ...] = ("/api/command", "/api/exec")

_PROBE_COMMAND = "whoami"
# Flask answers 404 for an unknown path and 405 for a known path used with the
# wrong verb — both mean "this build does not expose that route".
_ROUTE_ABSENT = frozenset({404, 405})
# Hostnames that mean "this machine".  A bridge configured against one of
# these is very often just pointed at the wrong box.
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "0.0.0.0", "[::1]"})
_PROXY_ENV_VARS = (
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
)


class CommandRouteMissing(RuntimeError):
    """No known command endpoint answered on the target host."""

    def __init__(self, base: str, tried: list[str]) -> None:
        self.base = base
        self.tried = tried
        super().__init__(f"no command endpoint at {base} (tried {', '.join(tried)})")


class KaliAPI:
    """Thin wrapper around kali-server-mcp (POST /api/command)."""

    def __init__(self, base_url: str, log: logging.Logger) -> None:
        self.base = base_url.rstrip("/")
        self.log = log
        self.sess = requests.Session()
        self.sess.headers.update({"Content-Type": "application/json"})
        # Command route discovered on first use — cached so later calls do
        # not repeat the 404 walk on every single command.
        self.command_route: str | None = None
        # Routes seen to be absent while probing, for diagnostics only.
        self.absent_routes: list[str] = []

    # ── health ───────────────────────────────────────────────────────────────

    def health(self) -> tuple[bool, str]:
        """Return ``(ok, message)`` for the kali-server-mcp bridge.

        The bridge's ``GET /health`` route exists only in newer builds of
        kali-server-mcp; the Kali packaging has shipped versions without it.
        When that endpoint is absent (404/405) the *mounting bridge is still
        online*, so we fall back to exercising the command transport itself —
        ``POST /api/command`` with a harmless ``whoami`` — which is present in
        every build.  This keeps the status line honest: a bridge answering
        commands reports online even when it has no dedicated health route.

        When *nothing* answers, the message names the URL that was probed and
        the routes that 404'd, because the usual cause is ``kali_api_url``
        pointing at the wrong host (a loopback URL while the bridge runs on
        the Kali box) rather than a dead bridge.
        """
        # 1) Try the optional /health endpoint first.
        self.absent_routes = []
        try:
            verdict = self._probe_health_routes()
        except requests.ConnectionError:
            return False, "connection refused — run: kali-server-mcp"
        except requests.Timeout:
            return False, "timeout"
        except requests.RequestException as exc:
            self.log.error("health request error: %s", exc)
            return False, str(exc)
        if verdict is not None:
            return verdict

        # 2) No /health route — verify the command endpoint instead.
        try:
            return self._probe_command_transport()
        except requests.ConnectionError:
            return False, "connection refused — run: kali-server-mcp"
        except requests.Timeout:
            return False, "timeout"
        except requests.RequestException as exc:
            self.log.error("health probe error: %s", exc)
            return False, str(exc)

    def _probe_health_routes(self) -> tuple[bool, str] | None:
        """Probe the liveness routes; ``None`` when none of them exist."""
        for route in HEALTH_ROUTES:
            r = self.sess.get(f"{self.base}{route}", timeout=5)
            if r.status_code == 200:
                return True, "ready"
            if r.status_code not in _ROUTE_ABSENT:
                # Something IS listening but reporting an error state.
                return False, f"HTTP {r.status_code} from {route}"
            # 404/405 → route absent on this build, keep probing below.
            self.absent_routes.append(route)
        return None

    def _probe_command_transport(self) -> tuple[bool, str]:
        """Prove the bridge is alive by running a harmless command."""
        try:
            probe = self._post_command({"command": _PROBE_COMMAND}, timeout=10)
        except CommandRouteMissing as exc:
            return False, self._not_a_bridge_message(exc.tried)
        try:
            data = probe.json()
        except ValueError as exc:
            self.log.error("health probe returned invalid JSON: %s", exc)
            return False, f"invalid JSON from API: {exc}"
        succeeded = bool(
            data.get("success", data.get("return_code", data.get("returncode", 1)) == 0)
        )
        if succeeded:
            return True, "bridge ready (no /health endpoint on this build)"
        detail = data.get("stderr") or data.get("error") or f"rc={data.get('return_code')}"
        return False, f"command endpoint errored: {detail}"

    # ── command execution ────────────────────────────────────────────────────

    def run(self, command: str, timeout: int = 300) -> dict:
        self.log.info("RUN [%ds] %s", timeout, command[:140])
        try:
            r = self._post_command({"command": command}, timeout=timeout + 15)
            r.raise_for_status()
            data = r.json()
            stdout = data.get("stdout") or ""
            stderr = data.get("stderr") or ""
            output = (stdout + ("\n" + stderr if stderr.strip() else "")).strip()
            if not output:
                output = data.get("output") or data.get("result") or ""
            rc = data.get("return_code", data.get("returncode", 0))
            timed = data.get("timed_out", False)
            if timed:
                output = f"[TIMED OUT after {timeout}s]\n{output}"
                self.log.warning("timeout: %s", command[:80])
            self.log.info("rc=%s bytes=%d timed=%s", rc, len(output), timed)
            return {
                "output": output,
                "error": stderr if rc != 0 else "",
                "returncode": rc,
                "success": data.get("success", rc == 0),
                "timed_out": timed,
            }
        except CommandRouteMissing as exc:
            self.log.error("no command endpoint at %s", exc.base)
            return {
                "output": "",
                "error": self._not_a_bridge_message(exc.tried),
                "returncode": -1,
                "success": False,
                "timed_out": False,
            }
        except requests.Timeout:
            self.log.error("API timeout")
            return {
                "output": "",
                "error": "API request timeout",
                "returncode": -1,
                "success": False,
                "timed_out": True,
            }
        except requests.ConnectionError:
            self.log.error("API connection refused")
            return {
                "output": "",
                "error": "kali-server-mcp not reachable",
                "returncode": -1,
                "success": False,
                "timed_out": False,
            }
        except ValueError as exc:
            # Invalid JSON payload from the API.
            self.log.error("API returned invalid JSON: %s", exc)
            return {
                "output": "",
                "error": f"invalid JSON from API: {exc}",
                "returncode": -1,
                "success": False,
                "timed_out": False,
            }
        except requests.RequestException as exc:
            self.log.error("API error: %s", exc)
            return {
                "output": "",
                "error": str(exc),
                "returncode": -1,
                "success": False,
                "timed_out": False,
            }

    def _post_command(self, payload: dict, timeout: int) -> requests.Response:
        """POST *payload* to the bridge's command endpoint.

        The route is discovered once and then cached: kali-server-mcp builds
        disagree on the exact path, so a 404/405 simply moves on to the next
        known spelling instead of failing the engagement.
        """
        tried: list[str] = []
        for route in self._command_routes():
            tried.append(route)
            r = self.sess.post(f"{self.base}{route}", json=payload, timeout=timeout)
            if r.status_code in _ROUTE_ABSENT:
                continue
            self.command_route = route
            return r
        raise CommandRouteMissing(self.base, tried)

    def _command_routes(self) -> list[str]:
        """Known command routes, the already-discovered one first."""
        routes = list(COMMAND_ROUTES)
        if self.command_route in routes:
            routes.remove(self.command_route)
            routes.insert(0, self.command_route)
        return routes

    # ── helpers ──────────────────────────────────────────────────────────────

    def local_ip(self, target: str) -> str:
        res = self.run(f"ip route get {target} | grep -oP 'src \\K\\S+'", timeout=10)
        raw = res.get("output", "").strip()
        parts = raw.split()
        if parts:
            candidate = parts[0]
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", candidate):
                return str(candidate)
        return "127.0.0.1"

    def check_target(self, target: str) -> dict:
        res = self.run(f"ping -c 2 -W 2 {target} 2>&1 | tail -3", timeout=15)
        out = res.get("output", "").lower()
        # NOTE: "0% packet loss" is a substring of "100% packet loss", so a
        # naive `in` test marks a fully-dropping host as reachable.  Match a
        # real received count, or a loss percentage that is NOT "100%".
        reachable = bool(
            re.search(r"\b[1-9]\d* received", out) or re.search(r"(?<!\d)0% packet loss", out)
        )
        return {
            "reachable": reachable,
            "output": res.get("output", ""),
        }

    # ── diagnostics ──────────────────────────────────────────────────────────

    def _not_a_bridge_message(self, tried: list[str]) -> str:
        """Explain a host that answers HTTP but is not a kali-server-mcp API."""
        absent = self.absent_routes + [route for route in tried if route not in self.absent_routes]
        routes = " and ".join(absent) if len(absent) == 2 else ", ".join(absent)
        msg = f"no kali-server-mcp API at {self.base} (404 on {routes}) — check kali_api_url"
        if self._is_local_host():
            msg += "; if the bridge runs on another host, point kali_api_url at it"
        proxy = self._proxy_env()
        if proxy:
            msg += f" (note: {proxy} is set — requests may be routing through it)"
        return msg

    def _is_local_host(self) -> bool:
        try:
            host = (urlsplit(self.base).hostname or "").lower()
        except ValueError:
            return False
        return host in _LOCAL_HOSTS

    @staticmethod
    def _proxy_env() -> str:
        """First proxy variable set in the environment, if any."""
        for var in _PROXY_ENV_VARS:
            val = os.environ.get(var)
            if val:
                return f"{var}={val}"
        return ""
