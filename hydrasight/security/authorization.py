"""Mandatory operator authorization for HydraSight.

Nothing that touches a target may execute until an operator has explicitly
attested that they are authorized to test the target scope.  The scope is
expressed as a list of IP addresses and/or CIDR networks.  Authorization is
**deny by default**: until a valid attestation exists, every target is
denied.

Two attestation paths are supported:

* **Interactive** — the REPL ``authorize <ip|cidr>`` command prompts the
  operator to type the exact phrase ``I AUTHORIZE`` (see
  :data:`ATTEST_PHRASE`).
* **CI / automation** — a pre-signed ``hydrasight.authorization.json`` file
  loaded via :meth:`AuthorizationManager.load_file`, suitable for CTF / CI
  pipelines where there is no human at the terminal.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("hydrasight")

#: Exact phrase an operator must type to grant an interactive attestation.
ATTEST_PHRASE = "I AUTHORIZE"

#: Default filename for the pre-signed authorization file.
AUTHORIZATION_FILE = "hydrasight.authorization.json"

#: Default attestation lifetime in minutes.
DEFAULT_EXPIRES_MINUTES = 480


def scope_is_valid(scope: list[str]) -> bool:
    """True iff every entry in *scope* is a valid IP address or CIDR network."""
    if not scope:
        return False
    for entry in scope:
        entry = str(entry).strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                ipaddress.ip_network(entry, strict=False)
            else:
                ipaddress.ip_address(entry)
        except ValueError:
            return False
    return True


@dataclass
class AuthorizationAttestation:
    """A single operator authorization decision covering a scope."""

    operator: str
    scope: list[str]
    reference: str = ""
    phrase_confirmed: bool = False
    expires_after_minutes: int = DEFAULT_EXPIRES_MINUTES
    granted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "interactive"

    # ── scope checks ─────────────────────────────────────────────────────────

    def covers(self, ip: str) -> bool:
        """True iff *ip* is an exact match or inside one of the CIDR scopes."""
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        for entry in self.scope:
            entry = str(entry).strip()
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                elif str(addr) == entry:
                    return True
            except ValueError:
                continue
        return False

    def is_expired(self) -> bool:
        """True once the attestation has outlived its validity window."""
        if self.expires_after_minutes <= 0:  # zero/negative => never expires
            return False
        deadline = self.granted_at + timedelta(minutes=self.expires_after_minutes)
        return datetime.now(timezone.utc) >= deadline

    # ── identity / serialisation ──────────────────────────────────────────────

    @property
    def authorization_id(self) -> str:
        """Stable short id derived from operator + scope + reference."""
        material = f"{self.operator}|{','.join(sorted(self.scope))}|{self.reference}"
        return "auth-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            "operator": self.operator,
            "scope": list(self.scope),
            "reference": self.reference,
            "phrase_confirmed": self.phrase_confirmed,
            "expires_after_minutes": self.expires_after_minutes,
            "granted_at": self.granted_at.isoformat(),
            "source": self.source,
            "authorization_id": self.authorization_id,
        }


class AuthorizationManager:
    """Holds the active attestation and answers scope questions.

    State machine: no attestation → :attr:`is_active` is False and every
    :meth:`check` denies.  Once an interactive or file attestation is
    recorded, targets within scope (and not expired) are allowed.
    """

    def __init__(self) -> None:
        self.attestation: AuthorizationAttestation | None = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    @property
    def is_active(self) -> bool:
        """True iff an attestation exists, covers something, and is unexpired."""
        att = self.attestation
        if att is None:
            return False
        if not att.scope:
            return False
        return not att.is_expired()

    def reset(self) -> None:
        """Clear any active attestation (deny all again)."""
        self.attestation = None

    # ── interactive attestation ───────────────────────────────────────────────

    def record_interactive(
        self,
        operator: str,
        scope: list[str],
        phrase: str,
        *,
        expires_after_minutes: int = DEFAULT_EXPIRES_MINUTES,
    ) -> tuple[bool, str]:
        """Record an interactive attestation.

        Succeeds only when the operator typed :data:`ATTEST_PHRASE` exactly
        and the scope is valid.  Returns ``(ok, message)``.
        """
        if not scope_is_valid(scope):
            self.attestation = None
            return False, "invalid scope: must be one or more IP/CIDR entries"
        # The phrase must match EXACTLY (callers strip surrounding whitespace).
        if phrase is None or phrase != ATTEST_PHRASE:
            self.attestation = None
            return False, f"authorization NOT granted — type {ATTEST_PHRASE!r} exactly"
        self.attestation = AuthorizationAttestation(
            operator=str(operator or "operator"),
            scope=[str(s).strip() for s in scope],
            reference="interactive REPL attestation",
            phrase_confirmed=True,
            expires_after_minutes=expires_after_minutes,
            source="interactive",
        )
        log.info("authorization granted (interactive) for %s", self.attestation.scope)
        return True, f"authorization granted for scope: {', '.join(self.attestation.scope)}"

    # ── file attestation (CI / CTF) ───────────────────────────────────────────

    def load_file(self, path: str = AUTHORIZATION_FILE) -> tuple[bool, str]:
        """Load a pre-signed authorization file.

        Expected keys: ``operator``, ``scope`` (list), ``reference``,
        ``phrase_confirmed`` (must be true), ``expires_after_minutes``.
        Malformed/missing files deny by default.  Returns ``(ok, message)``.
        """
        p = Path(path)
        if not p.exists():
            return False, f"no authorization file: {path}"
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self.attestation = None
            return False, f"authorization file unreadable: {exc}"

        if not isinstance(data, dict):
            self.attestation = None
            return False, "authorization file malformed: top-level object expected"

        scope = data.get("scope")
        operator = str(data.get("operator", "operator") or "operator")
        reference = str(data.get("reference", f"pre-signed file {path}"))
        phrase_confirmed = bool(data.get("phrase_confirmed", False))
        try:
            expires = int(data.get("expires_after_minutes", DEFAULT_EXPIRES_MINUTES))
        except (TypeError, ValueError):
            expires = DEFAULT_EXPIRES_MINUTES

        if not isinstance(scope, list) or not scope:
            self.attestation = None
            return False, "authorization file malformed: 'scope' must be a non-empty list"
        scope = [str(s).strip() for s in scope]
        if not scope_is_valid(scope):
            self.attestation = None
            return False, "authorization file malformed: invalid IP/CIDR in 'scope'"
        if not phrase_confirmed:
            self.attestation = None
            return False, "authorization denied: 'phrase_confirmed' is not true"

        self.attestation = AuthorizationAttestation(
            operator=operator,
            scope=scope,
            reference=reference,
            phrase_confirmed=True,
            expires_after_minutes=expires,
            source=str(p),
        )
        log.info("authorization loaded from %s for %s", path, scope)
        return True, f"authorization loaded from {path} for scope: {', '.join(scope)}"

    # ── enforcement ───────────────────────────────────────────────────────────

    def check(self, target: str) -> tuple[bool, str]:
        """Deny-by-default gate.  Returns ``(allowed, reason)``."""
        att = self.attestation
        if att is None:
            return False, "no authorization — run `authorize <ip|cidr>` and type I AUTHORIZE"
        if not att.scope:
            return False, "authorization has empty scope"
        if att.is_expired():
            return False, "authorization expired — re-attest with `authorize <ip|cidr>`"
        try:
            ipaddress.ip_address(str(target))
        except ValueError:
            return False, f"target {target!r} is not a valid IP address"
        if att.covers(str(target)):
            return True, f"target {target} within attested scope"
        return False, f"target {target} outside attested scope {', '.join(att.scope)}"

    def scope_summary(self) -> str:
        """Human-readable current scope."""
        if not self.is_active or self.attestation is None:
            return "none — no active authorization"
        return ", ".join(self.attestation.scope)
