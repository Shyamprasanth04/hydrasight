"""
Thread-safe container for all engagement artefacts.

Phase 2 additions:
  - ``finding_records``: typed ``FindingRecord`` list alongside existing
    ``vulns`` dicts (backward-compatible — both coexist).
  - ``add_vuln()`` now also creates a ``FindingRecord`` in ``finding_records``.
  - ``add_finding_record()`` for direct FindingRecord insertion.
  - ``verified_count`` / ``unverified_count`` properties.

Lock is name-mangled (_Findings__lock) so it is never cleared
by reset() and never appears in serialisation.
"""
import threading
from typing import Any, TYPE_CHECKING

from hydrasight.config.defaults import SEV, VERSION
from hydrasight.utils.time_utils import ts

if TYPE_CHECKING:
    from hydrasight.models.finding_record import FindingRecord


class Findings:
    """Thread-safe store for ports, vulns, creds, hashes, sessions."""

    def __init__(self) -> None:
        self.__lock          : threading.Lock           = threading.Lock()
        self.ports           : list[dict[str, Any]]     = []
        self.vulns           : list[dict[str, Any]]     = []
        self.credentials     : list[dict[str, Any]]     = []
        self.hashes          : list[dict[str, Any]]     = []
        self.dirs            : list[dict[str, Any]]     = []
        self.sessions        : list[dict[str, Any]]     = []
        self.host_info       : dict[str, Any]           = {}
        self.timeline        : list[dict[str, Any]]     = []
        # Phase 2 — typed finding records (parallel, backward-compatible)
        self.finding_records : list["FindingRecord"]    = []
        self.target          : str = ""
        self.started_at      : str = ""

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def reset(self) -> None:
        """Clear all artefacts; the internal lock is preserved."""
        with self.__lock:
            self.ports           = []
            self.vulns           = []
            self.credentials     = []
            self.hashes          = []
            self.dirs            = []
            self.sessions        = []
            self.host_info       = {}
            self.timeline        = []
            self.finding_records = []
            self.target          = ""
            self.started_at      = ""

    # ── add methods ───────────────────────────────────────────────────────────

    def add_port(
        self, port: int, proto: str,
        service: str, version: str = "",
    ) -> None:
        with self.__lock:
            if any(
                p["port"] == port and p["proto"] == proto
                for p in self.ports
            ):
                return
            self.ports.append({
                "port": port, "proto": proto,
                "service": service, "version": version,
            })

    def add_vuln(
        self, name: str, severity: str,
        description: str, cve: str = "",
        port: int = 0,
        phase: str = "",
        source_tool: str = "",
        confidence: float = 0.5,
    ) -> None:
        severity = severity.upper()
        if severity not in SEV:
            severity = "INFO"
        with self.__lock:
            if any(v["name"] == name for v in self.vulns):
                # Boost confidence on existing finding_record if re-seen
                for rec in self.finding_records:
                    if rec.name == name:
                        rec.boost_confidence(0.1)
                return
            self.vulns.append({
                "name": name, "severity": severity,
                "description": description, "cve": cve,
                "port": port, "ts": ts(),
            })
            # Phase 2: also create a typed FindingRecord
            self._create_finding_record(
                name=name, severity=severity,
                description=description, cve=cve,
                port=port, phase=phase,
                source_tool=source_tool, confidence=confidence,
            )

    def _create_finding_record(
        self, name: str, severity: str, description: str,
        cve: str = "", port: int = 0, phase: str = "",
        source_tool: str = "", confidence: float = 0.5,
    ) -> None:
        """Internal — creates a FindingRecord; caller must hold lock."""
        # Import inside method to avoid circular import at module load
        from hydrasight.models.finding_record import (
            FindingRecord, FindingSeverity,
        )
        rec = FindingRecord(
            name        = name,
            severity    = FindingSeverity.from_str(severity),
            description = description,
            cve         = cve,
            port        = port,
            phase       = phase,
            source_tool = source_tool,
            confidence  = confidence,
        )
        self.finding_records.append(rec)

    def add_finding_record(self, record: "FindingRecord") -> None:
        """Directly add a typed FindingRecord (e.g. from verifier)."""
        with self.__lock:
            self.finding_records.append(record)

    def add_cred(
        self, username: str, secret: str,
        kind: str = "password", source: str = "",
    ) -> None:
        with self.__lock:
            if any(
                c["username"] == username and c["secret"] == secret
                for c in self.credentials
            ):
                return
            self.credentials.append({
                "username": username, "secret": secret,
                "kind": kind, "source": source, "ts": ts(),
            })

    def add_hash(
        self, username: str, lm: str,
        ntlm: str, source: str = "hashdump",
    ) -> None:
        with self.__lock:
            if any(h["ntlm"] == ntlm for h in self.hashes):
                return
            self.hashes.append({
                "username": username, "lm": lm, "ntlm": ntlm,
                "source": source, "cracked": "",
                "crackable": lm != "aad3b435b51404eeaad3b435b51404ee",
                "ts": ts(),
            })

    def add_dir(self, path: str, status: int = 200) -> None:
        with self.__lock:
            entry: dict[str, Any] = {"path": path, "status": status}
            if entry not in self.dirs:
                self.dirs.append(entry)

    def add_session(self, **kwargs: Any) -> None:
        with self.__lock:
            kwargs["ts"] = ts()
            self.sessions.append(kwargs)

    def add_event(self, phase: str, event: str) -> None:
        with self.__lock:
            self.timeline.append(
                {"phase": phase, "event": event, "ts": ts()}
            )

    # ── computed properties ───────────────────────────────────────────────────

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulns if v["severity"] == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulns if v["severity"] == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulns if v["severity"] == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulns if v["severity"] == "LOW")

    @property
    def overall_risk(self) -> str:
        if self.critical_count:
            return "CRITICAL"
        if self.high_count:
            return "HIGH"
        if self.medium_count:
            return "MEDIUM"
        if self.low_count:
            return "LOW"
        return "NONE"

    @property
    def has_data(self) -> bool:
        return bool(
            self.ports or self.vulns or self.hashes
            or self.credentials or self.dirs
        )

    # ── Phase 2 properties ────────────────────────────────────────────────────

    @property
    def verified_count(self) -> int:
        return sum(1 for r in self.finding_records if r.verified)

    @property
    def unverified_count(self) -> int:
        return sum(
            1 for r in self.finding_records
            if not r.verified and r.verification_attempted
        )

    @property
    def high_confidence_findings(self) -> list["FindingRecord"]:
        return [r for r in self.finding_records if r.is_high_confidence]

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": {
                "version": VERSION, "target": self.target,
                "started": self.started_at, "completed": ts(),
                "risk": self.overall_risk,
            },
            "summary": {
                "ports"        : len(self.ports),
                "vulns"        : len(self.vulns),
                "critical"     : self.critical_count,
                "high"         : self.high_count,
                "medium"       : self.medium_count,
                "low"          : self.low_count,
                "hashes"       : len(self.hashes),
                "credentials"  : len(self.credentials),
                "sessions"     : len(self.sessions),
                "dirs"         : len(self.dirs),
                "verified"     : self.verified_count,
                "unverified"   : self.unverified_count,
            },
            "host_info"      : self.host_info,
            "ports"          : self.ports,
            "vulns"          : self.vulns,
            "finding_records": [r.to_dict() for r in self.finding_records],
            "credentials"    : self.credentials,
            "hashes"         : self.hashes,
            "dirs"           : self.dirs,
            "sessions"       : self.sessions,
            "timeline"       : self.timeline,
        }
