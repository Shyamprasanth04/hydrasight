#!/usr/bin/env python3
"""Generate a synthetic lab engagement and export JSON + PDF samples.

This runs entirely in-process (no Kali/Ollama) and exercises the real
reporting reporters so the committed examples reflect the actual report
schema and PDF layout.
"""

from __future__ import annotations

from pathlib import Path

from hydrasight.models.finding_record import (
    FindingRecord,
    FindingSeverity,
    FindingStage,
    VerificationState,
)
from hydrasight.models.findings import Findings
from hydrasight.reporting.json_reporter import save_json
from hydrasight.reporting.pdf_reporter import generate_pdf

HERE = Path(__file__).resolve().parent
TARGET = "10.10.10.15"


def build_findings() -> Findings:
    f = Findings()
    f.target = TARGET
    f.started_at = "2026-09-01T09:00:00Z"
    f.host_info = {"os": "Windows Server 2019", "hostname": "LAB-DC01"}

    f.add_port(445, "tcp", "microsoft-ds")
    f.add_port(3389, "tcp", "ms-wbt-server")
    f.add_port(80, "tcp", "http")

    f.add_vuln(
        name="MS17-010 EternalBlue",
        severity="CRITICAL",
        port=445,
        description="SMBv1 remote code execution via EternalBlue.",
        cve="CVE-2017-0144",
        source_tool="nmap",
    )

    f.add_finding_record(
        FindingRecord(
            name="MS17-010 EternalBlue (SMB RCE)",
            severity=FindingSeverity.CRITICAL,
            stage=FindingStage.EXPLOITED,
            service="microsoft-ds",
            port=445,
            verification_state=VerificationState.EXPLOITED,
            description="SMBv1 vulnerable; exploit confirmed SYSTEM shell.",
        )
    )
    f.add_finding_record(
        FindingRecord(
            name="RDP exposed",
            severity=FindingSeverity.LOW,
            stage=FindingStage.OBSERVED,
            service="ms-wbt-server",
            port=3389,
            verification_state=VerificationState.SUPPORTED_CANDIDATE,
            description="RDP reachable on 3389/tcp.",
        )
    )

    f.add_cred("administrator", "P@ssw0rd-lab", kind="password", source="smb")
    f.add_hash(
        "administrator", "aad3b435b51404eeaad3b435b51404ee", "31d6cfe0d16ae931b73c59d7e0c089c0"
    )
    f.add_session(
        id=1, type="meterpreter", target=TARGET, via="ms17_010_eternalblue", info="SYSTEM"
    )
    return f


def main() -> None:
    findings = build_findings()
    json_path = HERE / "sample-engagement.json"
    pdf_path = HERE / "sample-engagement.pdf"

    assert save_json(findings, str(json_path)), "JSON export failed"
    assert generate_pdf(TARGET, findings, str(pdf_path)), "PDF generation failed"
    print(f"wrote {json_path}")
    print(f"wrote {pdf_path}")


if __name__ == "__main__":
    main()
