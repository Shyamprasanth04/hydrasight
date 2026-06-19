"""
Generic finding verifier service.

Runs targeted second-pass probes to distinguish true positives from
scanner noise. Designed to work across service types — web, SMB, FTP,
SSH, container, and mixed-service targets.

Design principles:
- Findings are NEVER automatically promoted to verified.
- If verification cannot be performed, the finding stays unverified
  with an explanatory note — it is not silently trusted.
- Verification reduces confidence for false positives, not the finding
  record itself (findings are never deleted by the verifier).
- Strategies are registered in a lookup table so new service types
  can be added without modifying the core verifier logic.
"""
import logging
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

from hydrasight.integrations.kali_api import KaliAPI
from hydrasight.models.finding_record import FindingRecord, FindingSeverity

if TYPE_CHECKING:
    from hydrasight.models.findings import Findings


@dataclass
class VerificationResult:
    """Outcome of a single verification attempt."""

    finding_id  : str
    finding_name: str
    verified    : bool
    confidence  : float
    command     : str
    output      : str
    note        : str


# ── strategy registry ─────────────────────────────────────────────────────────
# Each entry: (match_substring_lower, command_template, success_pattern_lower)
# Placeholders: {target}  {port}  {path}
#
# Strategies are matched against the lower-cased finding name.
# First match wins. Add new entries here for new service types.

_VERIFY_STRATEGIES: list[tuple[str, str, str]] = [
    # ── SMB / Windows ─────────────────────────────────────────────────────────
    (
        "ms17-010",
        "nmap --script smb-vuln-ms17-010 -p 445 {target} 2>&1",
        "vulnerable",
    ),
    (
        "eternalblue",
        "nmap --script smb-vuln-ms17-010 -p 445 {target} 2>&1",
        "vulnerable",
    ),
    (
        "ms08-067",
        "nmap --script smb-vuln-ms08-067 -p 445 {target} 2>&1",
        "vulnerable",
    ),
    (
        "samba usermap",
        "nmap --script smb-vuln-cve-2007-2447 -p 139 {target} 2>&1",
        "vulnerable",
    ),

    # ── FTP ───────────────────────────────────────────────────────────────────
    (
        "anonymous ftp",
        "nmap --script ftp-anon -p {port} {target} 2>&1",
        "anonymous ftp login allowed",
    ),
    (
        "vsftpd 2.3.4",
        "nmap -sV -p {port} {target} 2>&1",
        "vsftpd 2.3.4",
    ),
    (
        "proftpd",
        "nmap -sV -p {port} {target} 2>&1",
        "proftpd",
    ),

    # ── SSH ───────────────────────────────────────────────────────────────────
    (
        "libssh",
        "nmap --script ssh-auth-methods -p {port} {target} 2>&1",
        "none",
    ),

    # ── Web ───────────────────────────────────────────────────────────────────
    (
        "directory listing",
        (
            "curl -s -m 10 -o /dev/null -w '%{http_code}' "
            "http://{target}:{port}/{path} 2>&1"
        ),
        "200",
    ),
    (
        "drupal",
        "curl -s -m 10 -IL http://{target}:{port}/ 2>&1",
        "drupal",
    ),
    (
        "phpmyadmin",
        "curl -s -m 10 -IL http://{target}:{port}/phpmyadmin/ 2>&1",
        "200",
    ),

    # ── Misc services ─────────────────────────────────────────────────────────
    (
        "distcc",
        "nmap --script distcc-cve2004-2687 -p {port} {target} 2>&1",
        "vulnerable",
    ),
    (
        "unrealircd",
        "nmap --script irc-unrealircd-backdoor -p {port} {target} 2>&1",
        "backdoor",
    ),
    (
        "java rmi",
        "nmap -sV -p {port} {target} 2>&1",
        "java rmi",
    ),
]


class VerifierService:
    """
    Runs targeted verification commands against individual FindingRecords.

    Usage:
        verifier = VerifierService(kali, log, target="192.168.1.10")
        results  = verifier.verify_findings(findings)
    """

    def __init__(
        self,
        kali   : KaliAPI,
        log    : logging.Logger,
        target : str = "",
    ) -> None:
        self.kali   = kali
        self.log    = log
        self.target = target

    # ── strategy lookup ───────────────────────────────────────────────────────

    def _find_strategy(
        self, finding: FindingRecord
    ) -> Optional[tuple[str, str]]:
        name_lower = finding.name.lower()
        for substring, cmd_template, success_pat in _VERIFY_STRATEGIES:
            if substring in name_lower:
                return cmd_template, success_pat
        return None

    def _build_command(
        self, template: str, finding: FindingRecord, target: str
    ) -> str:
        port = str(finding.port) if finding.port else "80"
        # Extract a path from evidence if this strategy needs one
        path = ""
        for ev in finding.evidence:
            ev_stripped = ev.strip()
            if ev_stripped.startswith("/"):
                path = ev_stripped.lstrip("/")
                break
        return (
            template
            .replace("{target}", target)
            .replace("{port}",   port)
            .replace("{path}",   path)
        )

    # ── single-finding verification ───────────────────────────────────────────

    def verify_one(
        self,
        finding : FindingRecord,
        target  : Optional[str] = None,
    ) -> VerificationResult:
        """
        Verify a single finding. Returns a VerificationResult.
        Always updates finding.verified and finding.confidence.
        """
        tgt = target or self.target
        if not tgt:
            finding.mark_unverified("no target set for verifier")
            return VerificationResult(
                finding_id   = finding.id,
                finding_name = finding.name,
                verified     = False,
                confidence   = finding.confidence,
                command      = "",
                output       = "",
                note         = "no target provided",
            )

        if finding.verification_attempted:
            return VerificationResult(
                finding_id   = finding.id,
                finding_name = finding.name,
                verified     = finding.verified,
                confidence   = finding.confidence,
                command      = finding.verification_command,
                output       = finding.verification_output,
                note         = "already verified",
            )

        strategy = self._find_strategy(finding)
        if not strategy:
            note = f"no strategy registered for '{finding.name}'"
            finding.verification_attempted = True
            self.log.debug("verifier: %s", note)
            return VerificationResult(
                finding_id   = finding.id,
                finding_name = finding.name,
                verified     = False,
                confidence   = finding.confidence,
                command      = "",
                output       = "",
                note         = note,
            )

        cmd_template, success_pat = strategy
        cmd = self._build_command(cmd_template, finding, tgt)
        finding.verification_command = cmd
        self.log.info(
            "verifying '%s' via: %s", finding.name, cmd[:100]
        )

        try:
            result  = self.kali.run(cmd, timeout=60)
            output  = result.get("output", "")
            matched = success_pat in output.lower()

            if matched:
                finding.mark_verified(
                    confidence = 0.9,
                    output     = output[:300],
                    command    = cmd,
                )
                note = f"verified — pattern '{success_pat}' found"
            else:
                finding.mark_unverified(
                    f"pattern '{success_pat}' not in output"
                )
                note = "not verified — pattern not matched"

            return VerificationResult(
                finding_id   = finding.id,
                finding_name = finding.name,
                verified     = matched,
                confidence   = finding.confidence,
                command      = cmd,
                output       = output[:200],
                note         = note,
            )

        except Exception as exc:  # noqa: BLE001
            self.log.error("verifier error on '%s': %s", finding.name, exc)
            finding.mark_unverified(f"verification error: {exc}")
            return VerificationResult(
                finding_id   = finding.id,
                finding_name = finding.name,
                verified     = False,
                confidence   = finding.confidence,
                command      = cmd,
                output       = "",
                note         = f"error: {exc}",
            )

    # ── bulk verification ─────────────────────────────────────────────────────

    def verify_findings(
        self,
        findings           : "Findings",
        target             : Optional[str] = None,
        only_high_and_above: bool          = True,
    ) -> list[VerificationResult]:
        """
        Run verification on all unverified FindingRecords in a Findings object.

        Args:
            only_high_and_above: If True, only verify CRITICAL and HIGH severity
                                 findings (avoids excessive re-scanning).
        """
        tgt     = target or self.target or findings.target
        results : list[VerificationResult] = []

        for record in findings.finding_records:
            if record.verification_attempted:
                continue
            if only_high_and_above and record.severity not in (
                FindingSeverity.CRITICAL, FindingSeverity.HIGH
            ):
                continue
            result = self.verify_one(record, tgt)
            results.append(result)

        verified_count = sum(1 for r in results if r.verified)
        self.log.info(
            "verification complete: %d/%d confirmed", verified_count, len(results)
        )
        return results
