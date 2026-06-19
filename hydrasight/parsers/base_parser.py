"""
Unified Parser — regex-based extractor for all tool output.

Class methods only; no instance state required.
Split into logical sections: ports/dirs/CVE (nmap/gobuster),
hashes/creds (hashdump/hydra), and validation helpers.
"""
import re
from typing import Optional


class Parser:
    """Extracts structured data from raw security tool output strings."""

    # ── compiled patterns ─────────────────────────────────────────────────────

    PORT_RE = re.compile(
        r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$", re.MULTILINE
    )
    HASH_RE = re.compile(
        r"^([^:\n]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::",
        re.MULTILINE,
    )
    HASH_LOOSE_RE = re.compile(
        r"^([^:\n\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})",
        re.MULTILINE,
    )
    KIWI_USER_RE = re.compile(
        r"Username\s*:\s*(?:[^\s\\]+\\)?(\S+)", re.IGNORECASE
    )
    KIWI_NTLM_RE = re.compile(
        r"NTLM\s*:\s*([a-fA-F0-9]{32})", re.IGNORECASE
    )
    DIR_RE = re.compile(
        r"(?:^|\s)(/[^\s(]*)\s+\(Status:\s*(\d+)\)", re.MULTILINE
    )
    CVE_RE      = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    MS17_RE     = re.compile(r"VULNERABLE|ms17-010|EternalBlue", re.IGNORECASE)
    SESSION_RE  = re.compile(
        r"(?:Meterpreter|Command shell) session (\d+) opened|"
        r"session (\d+) created",
        re.IGNORECASE,
    )
    UID_RE = re.compile(
        r"Server username:\s*(.+?)$|Computer\s*:\s*(.+?)$",
        re.IGNORECASE | re.MULTILINE,
    )
    OS_RE = re.compile(
        r"OS\s*(?:Name)?\s*:\s*(.+?)$", re.IGNORECASE | re.MULTILINE
    )
    ANONYMOUS_FTP = re.compile(
        r"Anonymous (?:FTP )?login allowed", re.IGNORECASE
    )
    SMB_SHARE_RE = re.compile(
        r"^\s*([A-Z0-9_$]+)\s+(?:Disk|IPC)", re.MULTILINE
    )
    HYDRA_CRED_RE = re.compile(
        r"\[(\d+)\]\[(\w+)\]\s+host:\s*\S+\s+login:\s*(\S+)"
        r"\s+password:\s*(\S+)",
        re.IGNORECASE,
    )
    _MAC_RE = re.compile(r"\s*MAC Address:.*$", re.IGNORECASE)

    # ── internal helpers ──────────────────────────────────────────────────────

    @classmethod
    def _clean_version(cls, raw: str) -> str:
        if not raw:
            return ""
        ver = raw.strip()
        ver = cls._MAC_RE.sub("", ver)
        ver = re.sub(r"\s*\|.*$", "", ver)
        ver = re.sub(r"\s*Host is up.*$", "", ver, flags=re.IGNORECASE)
        return ver.strip()

    # ── port / service extraction ─────────────────────────────────────────────

    @classmethod
    def ports(cls, out: str) -> list[dict]:
        results: list[dict]            = []
        seen   : set[tuple[int, str]]  = set()
        for m in cls.PORT_RE.finditer(out):
            port    = int(m.group(1))
            proto   = m.group(2)
            service = m.group(3)
            version = cls._clean_version(m.group(4) or "")
            key     = (port, proto)
            if key not in seen:
                seen.add(key)
                results.append({
                    "port": port, "proto": proto,
                    "service": service, "version": version,
                })
        return results

    # ── hash / credential extraction ──────────────────────────────────────────

    @classmethod
    def hashes(cls, out: str) -> list[dict]:
        blank   = "aad3b435b51404eeaad3b435b51404ee"
        results : list[dict] = []
        seen    : set[str]   = set()

        for m in cls.HASH_RE.finditer(out):
            ntlm = m.group(4).lower()
            if ntlm not in seen:
                seen.add(ntlm)
                results.append({
                    "username" : m.group(1).strip(),
                    "rid"      : m.group(2),
                    "lm"       : m.group(3).lower(),
                    "ntlm"     : ntlm,
                    "crackable": m.group(3).lower() != blank,
                })

        for m in cls.HASH_LOOSE_RE.finditer(out):
            ntlm = m.group(4).lower()
            if ntlm not in seen:
                seen.add(ntlm)
                results.append({
                    "username" : m.group(1).strip(),
                    "rid"      : m.group(2),
                    "lm"       : m.group(3).lower(),
                    "ntlm"     : ntlm,
                    "crackable": m.group(3).lower() != blank,
                })

        # Kiwi output pairing (fix W0640: use default-arg to avoid cell-var)
        users = [
            (m.group(1).strip(), m.end())
            for m in cls.KIWI_USER_RE.finditer(out)
        ]
        ntlms = [
            (m.group(1).strip().lower(), m.start())
            for m in cls.KIWI_NTLM_RE.finditer(out)
        ]
        for user, upos in users:
            if not ntlms:
                break
            nearest = min(
                ntlms,
                key=lambda x, p=upos: abs(x[1] - p),  # type: ignore[misc]
            )
            if abs(nearest[1] - upos) < 500:
                ntlm = nearest[0]
                if ntlm not in seen:
                    seen.add(ntlm)
                    results.append({
                        "username" : user, "rid": "0",
                        "lm"       : blank, "ntlm": ntlm,
                        "crackable": True,
                    })
        return results

    @classmethod
    def hydra_creds(cls, out: str) -> list[dict]:
        return [
            {
                "username": m.group(3), "password": m.group(4),
                "port": m.group(1), "service": m.group(2),
            }
            for m in cls.HYDRA_CRED_RE.finditer(out)
        ]

    # ── directory / web extraction ────────────────────────────────────────────

    @classmethod
    def dirs(cls, out: str) -> list[dict]:
        return [
            {"path": m.group(1), "status": int(m.group(2))}
            for m in cls.DIR_RE.finditer(out)
            if m.group(1) not in ("/", "")
        ]

    # ── CVE / vulnerability detection ─────────────────────────────────────────

    @classmethod
    def cves(cls, out: str) -> list[str]:
        return list({c.upper() for c in cls.CVE_RE.findall(out)})

    @classmethod
    def smb_shares(cls, out: str) -> list[str]:
        return list(set(cls.SMB_SHARE_RE.findall(out)))

    @classmethod
    def is_ms17(cls, out: str) -> bool:
        return bool(cls.MS17_RE.search(out))

    @classmethod
    def has_anon_ftp(cls, out: str) -> bool:
        return bool(cls.ANONYMOUS_FTP.search(out))

    # ── session / host metadata ───────────────────────────────────────────────

    @classmethod
    def session_id(cls, out: str) -> Optional[int]:
        m = cls.SESSION_RE.search(out)
        if m:
            for g in m.groups():
                if g:
                    return int(g)
        return None

    @classmethod
    def uid(cls, out: str) -> Optional[str]:
        m = cls.UID_RE.search(out)
        if m:
            return (m.group(1) or m.group(2) or "").strip() or None
        return None

    @classmethod
    def os_info(cls, out: str) -> Optional[str]:
        m = cls.OS_RE.search(out)
        return m.group(1).strip() if m else None

    # ── output validation ─────────────────────────────────────────────────────

    @classmethod
    def validate(cls, tool: str, out: str, elapsed: float) -> list[str]:
        min_times = {
            "gobuster_scan": 3.0,
            "nikto_scan"   : 15.0,
            "nmap_scan"    : 0.8,
        }
        warnings: list[str] = []
        if tool in min_times and elapsed < min_times[tool]:
            warnings.append(
                f"completed in {elapsed:.1f}s — possible error or empty result"
            )
        if not out.strip():
            warnings.append("empty output returned")
        for pat in (
            "error:", "failed to", "command not found",
            "no such file", "permission denied",
        ):
            if pat in out.lower():
                warnings.append(f"error pattern detected: '{pat}'")
                break
        return warnings

    @classmethod
    def cve_context(cls, cve: str, out: str) -> str:
        cve_upper = cve.upper()
        for line in out.splitlines():
            if cve_upper in line.upper():
                clean = re.sub(r"^\s*\|_?\s*", "", line).strip()
                if len(clean) > 120:
                    clean = clean[:117] + "…"
                if clean and clean.upper() != cve_upper:
                    return clean
        return "CVE detected in scan output"
