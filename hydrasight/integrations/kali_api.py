"""HTTP wrapper around the kali-server-mcp REST API."""

import logging
import re

import requests


class KaliAPI:
    """Thin wrapper around kali-server-mcp (POST /api/command)."""

    def __init__(self, base_url: str, log: logging.Logger) -> None:
        self.base = base_url.rstrip("/")
        self.log = log
        self.sess = requests.Session()
        self.sess.headers.update({"Content-Type": "application/json"})

    def health(self) -> tuple[bool, str]:
        try:
            r = self.sess.get(f"{self.base}/health", timeout=5)
            if r.status_code == 200:
                return True, "ready"
            return False, f"HTTP {r.status_code}"
        except requests.ConnectionError:
            return False, "connection refused — run: kali-server-mcp"
        except requests.Timeout:
            return False, "timeout"
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    def run(self, command: str, timeout: int = 300) -> dict:
        self.log.info("RUN [%ds] %s", timeout, command[:140])
        try:
            r = self.sess.post(
                f"{self.base}/api/command",
                json={"command": command},
                timeout=timeout + 15,
            )
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
        except Exception as exc:  # noqa: BLE001
            self.log.error("API error: %s", exc)
            return {
                "output": "",
                "error": str(exc),
                "returncode": -1,
                "success": False,
                "timed_out": False,
            }

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
        return {
            "reachable": ("0% packet loss" in out or "1 received" in out or "2 received" in out),
            "output": res.get("output", ""),
        }
