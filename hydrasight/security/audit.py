"""Tamper-evident, append-only audit trail for HydraSight.

Every security-relevant event (authorization grants/denials and every
command allowed or blocked at the dispatch chokepoint) is appended to a
JSONL log as a SHA-256 hash-chained record.  The chain can be replayed
and verified at any time with :meth:`AuditLogger.verify`, which detects
both tampered lines (content altered after the fact) and deleted lines
(a broken ``prev_hash`` link).

Design guarantees
-----------------
* **Append-only** — records are never rewritten; the chain resumes from
  the last line when the log already exists.
* **Secret redaction** — ``command`` (and free-text) is scrubbed for
  passwords/tokens before it is ever written.
* **Fail-safe** — auditing must never break an engagement: every write
  is wrapped defensively and failures are logged, not raised.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger("hydrasight")

#: 64-zero genesis hash — the (non-existent) predecessor of the first record.
GENESIS_HASH = "0" * 64

#: String substituted for any redacted secret.
REDACTED = "[REDACTED]"

# ── secret redaction patterns ─────────────────────────────────────────────────
# sshpass -p 'secret' … / sshpass -p secret …
_SSHPASS_RE = re.compile(r"(sshpass\s+(?:-p\s+)?)(?:'[^']*'|\"[^\"]*\"|\S+)")
# inline URL credentials: scheme://user:pass@host
_URL_CRED_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s/@:]+:[^\s/@]+@")
# key=value / key: value secrets
_SECRET_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret|authorization|credential)"
    r"\s*([=:])\s*('[^']*'|\"[^\"]*\"|[^\s;|&]+)"
)


def redact_secrets(text: Any) -> str:
    """Return *text* with common secret material replaced by ``[REDACTED]``.

    Scrubs ``sshpass -p`` passwords, inline URL credentials
    (``scheme://user:pass@host``) and ``password=`` / ``token=`` style
    key/value pairs.  Never raises.
    """
    if text is None:
        return ""
    s = str(text)
    s = _SSHPASS_RE.sub(lambda m: m.group(1) + REDACTED, s)
    s = _URL_CRED_RE.sub(lambda m: m.group(1) + REDACTED + "@", s)
    s = _SECRET_KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", s)
    return s


class AuditAction(str, Enum):
    """Keys for the security events recorded in the audit trail."""

    COMMAND_ALLOWED = "command_allowed"
    COMMAND_BLOCKED = "command_blocked"
    AUTHORIZATION_GRANTED = "authorization_granted"
    AUTHORIZATION_DENIED = "authorization_denied"
    ENGAGEMENT_START = "engagement_start"
    ENGAGEMENT_END = "engagement_end"


# Fields that carry the hash chain, excluded from the hashed payload.
_HASH_FIELDS = ("prev_hash", "hash")


class AuditLogger:
    """Append-only, hash-chained JSONL audit log.

    Parameters
    ----------
    output_dir:
        Directory in which ``hydrasight_audit.jsonl`` is created.
    operator:
        Operator identity stamped onto every record.
    session_id:
        Stable id for this engagement session (auto-generated if omitted).
    enabled:
        Set ``False`` to construct a no-op logger.
    """

    AUDIT_FILENAME = "hydrasight_audit.jsonl"

    def __init__(
        self,
        output_dir: str | Path,
        *,
        operator: str = "operator",
        session_id: str | None = None,
        enabled: bool = True,
    ) -> None:
        self.path = Path(output_dir) / self.AUDIT_FILENAME
        self.operator = operator
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self.enabled = enabled
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        self._resume()

    # ── chain primitives ──────────────────────────────────────────────────────

    @staticmethod
    def _canonical(payload: dict) -> str:
        """Deterministic JSON encoding of a payload (sorted keys)."""
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False
        )

    @classmethod
    def _hash(cls, prev_hash: str, payload: dict) -> str:
        """SHA-256 over the previous hash concatenated with the canonical payload."""
        material = (prev_hash + cls._canonical(payload)).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def _resume(self) -> None:
        """Resume the chain from the last record if the log already exists."""
        if not self.enabled or not self.path.exists():
            return
        try:
            last: dict | None = None
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    last = json.loads(line)
            if last is not None:
                self._seq = int(last.get("sequence", 0))
                self._prev_hash = str(last.get("hash", GENESIS_HASH))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.warning("audit chain resume failed for %s: %s", self.path, exc)

    # ── core write path ───────────────────────────────────────────────────────

    def log(
        self,
        action: AuditAction | str,
        *,
        tool: str = "",
        target: str = "",
        command: Any = "",
        decision: str = "",
        reason: str = "",
        roe_scope: str = "",
        authorization_id: str = "",
        operator: str | None = None,
        extra: dict | None = None,
    ) -> dict | None:
        """Append a record to the chain. Returns the record, or ``None`` on failure.

        Never raises — audit failures must not interrupt an engagement.
        """
        if not self.enabled:
            return None
        try:
            payload: dict[str, Any] = {
                "sequence": self._seq + 1,
                "ts": datetime.now(timezone.utc).isoformat(),
                "action": getattr(action, "value", action),
                "operator": operator or self.operator,
                "tool": str(tool or ""),
                "target": str(target or ""),
                "command": redact_secrets(command),
                "decision": str(decision or ""),
                "reason": str(reason or ""),
                "roe_scope": str(roe_scope or ""),
                "authorization_id": str(authorization_id or ""),
                "session_id": self.session_id,
                "extra": dict(extra or {}),
            }
            prev_hash = self._prev_hash
            digest = self._hash(prev_hash, payload)
            record = dict(payload)
            record["prev_hash"] = prev_hash
            record["hash"] = digest

            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str, ensure_ascii=False) + "\n")

            self._seq = int(payload["sequence"])
            self._prev_hash = digest
            return record
        except Exception as exc:  # noqa: BLE001 — audit must never break an engagement
            log.warning("audit write failed: %s", exc)
            return None

    # ── convenience event helpers ─────────────────────────────────────────────

    def command_allowed(
        self,
        *,
        tool: str,
        target: str,
        command: Any = "",
        reason: str = "within ROE ∩ authorization scope",
        roe_scope: str = "",
        authorization_id: str = "",
        extra: dict | None = None,
    ) -> dict | None:
        return self.log(
            AuditAction.COMMAND_ALLOWED,
            tool=tool,
            target=target,
            command=command,
            decision="allow",
            reason=reason,
            roe_scope=roe_scope,
            authorization_id=authorization_id,
            extra=extra,
        )

    def command_blocked(
        self,
        *,
        tool: str,
        target: str,
        command: Any = "",
        reason: str = "",
        roe_scope: str = "",
        authorization_id: str = "",
        extra: dict | None = None,
    ) -> dict | None:
        return self.log(
            AuditAction.COMMAND_BLOCKED,
            tool=tool,
            target=target,
            command=command,
            decision="block",
            reason=reason,
            roe_scope=roe_scope,
            authorization_id=authorization_id,
            extra=extra,
        )

    def authorization_granted(
        self,
        *,
        target: str = "",
        reason: str = "",
        scope: str = "",
        authorization_id: str = "",
        extra: dict | None = None,
    ) -> dict | None:
        return self.log(
            AuditAction.AUTHORIZATION_GRANTED,
            target=target,
            command="",
            decision="allow",
            reason=reason,
            roe_scope=scope,
            authorization_id=authorization_id,
            extra=extra,
        )

    def authorization_denied(
        self,
        *,
        target: str = "",
        reason: str = "",
        scope: str = "",
        extra: dict | None = None,
    ) -> dict | None:
        return self.log(
            AuditAction.AUTHORIZATION_DENIED,
            target=target,
            command="",
            decision="block",
            reason=reason,
            roe_scope=scope,
            extra=extra,
        )

    def engagement_start(self, *, target: str = "", extra: dict | None = None) -> dict | None:
        return self.log(AuditAction.ENGAGEMENT_START, target=target, decision="start", extra=extra)

    def engagement_end(self, *, target: str = "", extra: dict | None = None) -> dict | None:
        return self.log(AuditAction.ENGAGEMENT_END, target=target, decision="end", extra=extra)

    # ── verification ──────────────────────────────────────────────────────────

    def verify(self) -> tuple[bool, str]:
        """Replay the chain and verify integrity.

        Returns ``(ok, message)``.  Detects:
          * tampered lines  — recomputed hash != stored hash;
          * deleted lines   — a ``prev_hash`` that does not link to the
            previous record's ``hash``;
          * sequence gaps   — non-contiguous ``sequence`` numbers;
          * malformed JSON  — unparseable log line.

        Never raises.
        """
        try:
            if not self.path.exists():
                return True, "no audit log present"
            prev_hash = GENESIS_HASH
            expected_seq = 0
            with open(self.path, encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        return False, f"line {lineno}: malformed JSON"
                    if not isinstance(rec, dict):
                        return False, f"line {lineno}: record is not an object"

                    rec_prev = str(rec.get("prev_hash", ""))
                    rec_hash = str(rec.get("hash", ""))
                    payload = {k: v for k, v in rec.items() if k not in _HASH_FIELDS}
                    calc_hash = self._hash(rec_prev, payload)

                    if not hmac.compare_digest(rec_prev, prev_hash):
                        return (
                            False,
                            f"line {lineno}: chain broken — prev_hash does not link "
                            "(possible deleted or missing record)",
                        )
                    if not rec_hash or not hmac.compare_digest(calc_hash, rec_hash):
                        return False, f"line {lineno}: hash mismatch — record content tampered"

                    expected_seq += 1
                    try:
                        seq = int(payload.get("sequence", -1))
                    except (ValueError, TypeError):
                        seq = -1
                    if seq != expected_seq:
                        return (
                            False,
                            f"line {lineno}: sequence gap (expected {expected_seq}, got {seq})",
                        )

                    prev_hash = rec_hash
            return True, f"verified {expected_seq} record(s); chain intact"
        except Exception as exc:  # noqa: BLE001 — verification must report, not raise
            return False, f"verification error: {exc}"
