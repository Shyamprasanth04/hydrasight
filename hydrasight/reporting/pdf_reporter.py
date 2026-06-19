"""
PDF report generator using ReportLab — Phase 3 update.

Produces a professional dark-themed engagement report.
Designed to be useful regardless of whether exploitation succeeded:
- recon-only engagements produce a port/service/vuln report
- credential engagements add a credentials section
- access engagements add a sessions/proof section

Phase 3 additions:
- Verified findings section with confidence, evidence, remediation
- Exploit status column (suggested / attempted / blocked / N/A)
- Verified vs unverified count in exec summary
"""
import logging
from typing import Optional

from hydrasight.config.defaults import VERSION, SEV
from hydrasight.models.findings import Findings
from hydrasight.reporting.remediation import build_recommendations
from hydrasight.utils.time_utils import ts

log = logging.getLogger("hydrasight")

try:
    from reportlab.lib           import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles    import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units     import mm
    from reportlab.lib.enums     import TA_CENTER
    from reportlab.platypus      import (
        HRFlowable, PageBreak, Paragraph, SimpleDocTemplate,
        Spacer, KeepTogether,
        Table as RLTable, TableStyle,
    )
    _PDF_OK = True
except ImportError:
    _PDF_OK = False


def _table_style(
    bg: object, bg2: object, green2: object,
    grey: object, bord: object,
) -> "TableStyle":
    return TableStyle([
        ("BACKGROUND",    (0, 0), (-1,  0), green2),
        ("TEXTCOLOR",     (0, 0), (-1, -1), grey),
        ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.3, bord),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [bg, bg2]),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ])


def generate_pdf(
    target: str,
    findings: Findings,
    path: str,
    operator: str = "HydraSight",
) -> bool:
    """
    Generate a dark-themed PDF report.

    Produces a useful report for any engagement outcome:
    recon-only, vuln-only, credential, or access engagements.
    Returns True on success.
    """
    if not _PDF_OK:
        log.warning("reportlab not installed — skipping PDF generation")
        return False

    # ── colour palette ─────────────────────────────────────────────────────
    bg     = colors.HexColor("#0D0D14")
    bg2    = colors.HexColor("#1A1A24")
    green  = colors.HexColor("#00D67D")
    green2 = colors.HexColor("#007A45")
    grey   = colors.HexColor("#E0E0E8")
    muted  = colors.HexColor("#9090A8")
    bord   = colors.HexColor("#8888A8")
    sev_colors = {
        "CRITICAL": colors.HexColor("#FF5C5C"),
        "HIGH"    : colors.HexColor("#FFA94D"),
        "MEDIUM"  : colors.HexColor("#E8C547"),
        "LOW"     : colors.HexColor("#7AB8E0"),
        "INFO"    : colors.HexColor("#9090A8"),
    }

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle(
        "H1", parent=styles["Title"], fontSize=24, textColor=green,
        spaceAfter=4, alignment=TA_CENTER,
    )
    h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"], fontSize=13, textColor=green,
        spaceBefore=10, spaceAfter=4,
    )
    h3 = ParagraphStyle(
        "H3", parent=styles["Heading3"], fontSize=10, textColor=muted,
        spaceBefore=4, spaceAfter=2,
    )
    bd = ParagraphStyle(
        "BD", parent=styles["Normal"], fontSize=9,
        textColor=grey, leading=13,
    )
    sub = ParagraphStyle(
        "SUB", parent=styles["Normal"], fontSize=8, textColor=muted,
        leading=11, alignment=TA_CENTER,
    )

    def tbl() -> "TableStyle":
        return _table_style(bg, bg2, green2, grey, bord)

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"HydraSight Report — {target}",
        author=operator,
    )

    # ── engagement outcome summary (generic, not exploit-centric) ──────────
    has_access  = bool(findings.sessions)
    has_creds   = bool(findings.credentials)
    has_vulns   = bool(findings.vulns)
    outcome_str = (
        "Active session obtained" if has_access
        else "Credentials recovered" if has_creds
        else "Vulnerabilities identified" if has_vulns
        else "Reconnaissance completed"
    )

    story: list = [
        Spacer(1, 30 * mm),
        Paragraph("HydraSight", h1),
        Spacer(1, 2 * mm),
        Paragraph(
            "Security Assessment Report",
            ParagraphStyle(
                "Sub2", parent=styles["Heading2"],
                fontSize=14, textColor=muted, alignment=TA_CENTER,
            ),
        ),
        Spacer(1, 20 * mm),
        RLTable(
            [
                ["TARGET",    target],
                ["DATE",      ts()],
                ["RISK",      findings.overall_risk],
                ["OUTCOME",   outcome_str],
                ["ENGINE",    f"HydraSight v{VERSION}"],
                ["OPERATOR",  operator],
            ],
            colWidths=[55 * mm, 115 * mm], style=tbl(),
        ),
        Spacer(1, 40 * mm),
        Paragraph(
            "CONFIDENTIAL — For authorised recipients only.<br/>"
            "This report contains sensitive security information.",
            sub,
        ),
        PageBreak(),

        # ── executive summary ──────────────────────────────────────────────
        Paragraph("Executive Summary", h2),
        HRFlowable(color=green, thickness=0.5),
        Spacer(1, 4 * mm),
        Paragraph(
            f"A security assessment was conducted against <b>{target}</b> on {ts()}. "
            f"The assessment identified <b>{len(findings.vulns)}</b> "
            f"vulnerabilities of which <b>{findings.critical_count}</b> "
            f"are critical and <b>{findings.high_count}</b> are high severity. "
            f"<b>{findings.verified_count}</b> finding(s) were independently verified "
            f"and <b>{findings.unverified_count}</b> could not be confirmed. "
            f"{'An active session was obtained during exploitation.' if has_access else 'No active sessions were established during this engagement.'} "
            f"{'Credentials were recovered.' if has_creds else ''} "
            f"Overall risk rating: <b>{findings.overall_risk}</b>.",
            bd,
        ),
        Spacer(1, 6 * mm),
        Paragraph("Key Metrics", h3),
        RLTable(
            [
                ["Metric",                "Value"],
                ["Open Ports",            str(len(findings.ports))],
                ["Total Vulnerabilities", str(len(findings.vulns))],
                ["Critical",              str(findings.critical_count)],
                ["High",                  str(findings.high_count)],
                ["Medium",                str(findings.medium_count)],
                ["Low",                   str(findings.low_count)],
                ["Verified Findings",     str(findings.verified_count)],
                ["Unconfirmed Findings",  str(findings.unverified_count)],
                ["Credentials",           str(len(findings.credentials))],
                ["NTLM Hashes",           str(len(findings.hashes))],
                ["Sessions",              str(len(findings.sessions))],
                ["Web Paths Found",       str(len(findings.dirs))],
                ["Overall Risk",          findings.overall_risk],
            ],
            colWidths=[80 * mm, 90 * mm], style=tbl(),
        ),
        PageBreak(),
    ]

    # ── open ports ────────────────────────────────────────────────────────
    if findings.ports:
        rows = [["Port", "Proto", "Service", "Version"]] + [
            [str(p["port"]), p["proto"], p["service"], p.get("version", "")]
            for p in sorted(findings.ports, key=lambda x: x["port"])
        ]
        story += [
            Paragraph("Open Ports & Services", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
            RLTable(
                rows,
                colWidths=[18 * mm, 14 * mm, 38 * mm, 104 * mm],
                style=tbl(),
            ),
            Spacer(1, 6 * mm),
        ]

    # ── vulnerabilities ───────────────────────────────────────────────────
    if findings.vulns:
        story += [
            Paragraph("Vulnerabilities", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
        ]
        sev_order = list(SEV.keys())
        for v in sorted(
            findings.vulns,
            key=lambda x: sev_order.index(x["severity"]),
        ):
            sc    = sev_colors.get(v["severity"], grey)
            block = [
                RLTable(
                    [[v["severity"], v["name"], v.get("cve", "")]],
                    colWidths=[22 * mm, 95 * mm, 57 * mm],
                    style=TableStyle([
                        ("BACKGROUND",    (0, 0), (0, 0),   sc),
                        ("BACKGROUND",    (1, 0), (-1, 0),  bg),
                        ("TEXTCOLOR",     (0, 0), (-1, -1), grey),
                        ("FONTNAME",      (0, 0), (0, -1),  "Helvetica-Bold"),
                        ("FONTSIZE",      (0, 0), (-1, -1), 8),
                        ("GRID",          (0, 0), (-1, -1), 0.3, bord),
                        ("TOPPADDING",    (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                    ]),
                )
            ]
            if v.get("description"):
                block.append(Paragraph(f"   {v['description']}", bd))
            if v.get("port"):
                block.append(Paragraph(f"   Port: {v['port']}", bd))
            block.append(Spacer(1, 3 * mm))
            story.append(KeepTogether(block))

    # ── verified findings (typed FindingRecords) ─────────────────────────
    if findings.finding_records:
        story += [
            Paragraph("Finding Verification Status", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
            Paragraph(
                f"<b>{findings.verified_count}</b> finding(s) independently verified  "
                f"·  <b>{findings.unverified_count}</b> unconfirmed  "
                f"·  "
                f"<b>{len(findings.finding_records) - findings.verified_count - findings.unverified_count}</b> "
                "pending verification",
                bd,
            ),
            Spacer(1, 3 * mm),
        ]
        # Table header
        vf_header = [
            "Severity", "Finding", "Confidence", "Status",
            "Exploit", "CVE",
        ]
        vf_rows: list[list[str]] = [vf_header]
        sev_order = list(SEV.keys())
        sorted_records = sorted(
            findings.finding_records,
            key=lambda r: (
                sev_order.index(r.severity.value)
                if r.severity.value in sev_order else 99,
                -r.confidence,
            ),
        )
        # Build exploit status map from session records
        exploited_cves: set[str] = set()
        for sess in findings.sessions:
            cve_ref = sess.get("cve", "")
            if cve_ref:
                exploited_cves.add(cve_ref.upper())

        for rec in sorted_records:
            # Determine exploit status
            if rec.confidence == 1.0 and rec.verified:
                exploit_status = "PROVEN"
            elif rec.cve.upper() in exploited_cves:
                exploit_status = "EXPLOITED"
            elif any(
                v["name"].lower().startswith(rec.name.lower()[:15])
                for v in findings.vulns
                if "exploited" in v["name"].lower()
            ):
                exploit_status = "EXPLOITED"
            elif rec.phase == "EXPLOIT":
                exploit_status = "ATTEMPTED"
            else:
                exploit_status = "N/A"

            vf_rows.append([
                rec.severity.value,
                rec.name[:30],
                f"{rec.confidence:.0%}  {rec.confidence_label}",
                "✓ VERIFIED" if rec.verified else
                ("✗ FAILED" if rec.verification_attempted else "PENDING"),
                exploit_status,
                rec.cve[:18] if rec.cve else "—",
            ])

        story.append(
            RLTable(
                vf_rows,
                colWidths=[18*mm, 52*mm, 28*mm, 22*mm, 22*mm, 32*mm],
                style=tbl(),
            )
        )

        # Evidence + remediation detail blocks for verified/high-confidence
        notable = [
            r for r in sorted_records
            if r.is_high_confidence or r.verification_attempted
        ]
        if notable:
            story += [Spacer(1, 4 * mm), Paragraph("Finding Detail", h3)]
            for rec in notable[:12]:   # cap at 12 to keep report concise
                sc = sev_colors.get(rec.severity.value, grey)
                status_color = (
                    colors.HexColor("#00D67D") if rec.verified else
                    colors.HexColor("#FF5C5C") if rec.verification_attempted else
                    grey
                )
                block = [
                    RLTable(
                        [[
                            rec.severity.value,
                            rec.name[:45],
                            f"{rec.confidence:.0%}",
                            "VERIFIED" if rec.verified else
                            ("FAILED" if rec.verification_attempted else "PENDING"),
                        ]],
                        colWidths=[18*mm, 90*mm, 16*mm, 22*mm],
                        style=TableStyle([
                            ("BACKGROUND",   (0, 0), (0, 0),   sc),
                            ("BACKGROUND",   (1, 0), (2, 0),   bg),
                            ("BACKGROUND",   (3, 0), (3, 0),   status_color),
                            ("TEXTCOLOR",    (0, 0), (-1, -1), grey),
                            ("FONTNAME",     (0, 0), (0, -1),  "Helvetica-Bold"),
                            ("FONTSIZE",     (0, 0), (-1, -1), 8),
                            ("GRID",         (0, 0), (-1, -1), 0.3, bord),
                            ("TOPPADDING",   (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
                            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
                        ]),
                    )
                ]
                if rec.description:
                    block.append(
                        Paragraph(f"   {rec.description[:200]}", bd)
                    )
                if rec.evidence:
                    block.append(
                        Paragraph(
                            "   Evidence: " +
                            " | ".join(rec.evidence[:3])[:150],
                            bd,
                        )
                    )
                if rec.remediation:
                    block.append(
                        Paragraph(f"   Remediation: {rec.remediation[:180]}", bd)
                    )
                if rec.verification_command:
                    block.append(
                        Paragraph(
                            f"   Verified by: "
                            f"{rec.verification_command[:100]}",
                            bd,
                        )
                    )
                block.append(Spacer(1, 3 * mm))
                story.append(KeepTogether(block))

    # ── credentials ───────────────────────────────────────────────────────
    if findings.credentials:
        rows = [["Type", "Username", "Secret", "Source"]] + [
            [c["kind"], c["username"][:25], c["secret"][:40],
             c.get("source", "")]
            for c in findings.credentials
        ]
        story += [
            PageBreak(),
            Paragraph("Recovered Credentials", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
            Paragraph(
                f"<b>{len(findings.credentials)}</b> credential(s) recovered.",
                bd,
            ),
            Spacer(1, 3 * mm),
            RLTable(
                rows,
                colWidths=[28 * mm, 40 * mm, 80 * mm, 26 * mm],
                style=tbl(),
            ),
        ]

    # ── hashes ────────────────────────────────────────────────────────────
    if findings.hashes:
        rows = [["Username", "NTLM Hash", "Cracked"]] + [
            [h["username"], h["ntlm"], h.get("cracked", "—")]
            for h in findings.hashes
        ]
        story += [
            PageBreak(),
            Paragraph("Captured Hashes", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
            RLTable(
                rows,
                colWidths=[40 * mm, 98 * mm, 36 * mm],
                style=tbl(),
            ),
        ]

    # ── access sessions ───────────────────────────────────────────────────
    if findings.sessions:
        story += [
            PageBreak(),
            Paragraph("Access & Exploitation Proof", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
        ]
        for s in findings.sessions:
            story += [
                Paragraph(f"<b>{s.get('exploit', '—')}</b>", bd),
                Spacer(1, 1 * mm),
                RLTable(
                    [
                        ["Access Level", s.get("uid",     "unknown")],
                        ["Method",       s.get("exploit", "—")],
                        ["Payload",      s.get("payload", "—")],
                        ["Target",       s.get("target",  "—")],
                        ["Timestamp",    s.get("ts",      "—")],
                    ],
                    colWidths=[40 * mm, 130 * mm], style=tbl(),
                ),
                Spacer(1, 4 * mm),
            ]

    # ── web paths ─────────────────────────────────────────────────────────
    if findings.dirs:
        rows = [["Path", "Status"]] + [
            [d["path"], str(d["status"])]
            for d in sorted(
                findings.dirs, key=lambda x: x.get("status", 0)
            )
        ]
        story += [
            PageBreak(),
            Paragraph("Discovered Web Paths", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
            RLTable(rows, colWidths=[130 * mm, 44 * mm], style=tbl()),
        ]

    # ── remediation ───────────────────────────────────────────────────────
    recs = build_recommendations(findings)
    story += [
        PageBreak(),
        Paragraph("Remediation Recommendations", h2),
        HRFlowable(color=green, thickness=0.5),
        Spacer(1, 3 * mm),
        Paragraph(
            "Address critical findings within 24 hours, "
            "high within 7 days, medium within 30 days.", bd,
        ),
        Spacer(1, 4 * mm),
    ]
    for i, (pri, rec) in enumerate(recs, 1):
        pc    = sev_colors.get(pri, grey)
        block = [
            RLTable(
                [[f"  {i}", pri, ""]],
                colWidths=[10 * mm, 25 * mm, 139 * mm],
                style=TableStyle([
                    ("BACKGROUND",    (1, 0), (1, 0),   pc),
                    ("BACKGROUND",    (0, 0), (0, 0),   bg2),
                    ("BACKGROUND",    (2, 0), (2, 0),   bg),
                    ("TEXTCOLOR",     (0, 0), (-1, -1), grey),
                    ("FONTNAME",      (0, 0), (1, -1),  "Helvetica-Bold"),
                    ("FONTSIZE",      (0, 0), (-1, -1), 8),
                    ("GRID",          (0, 0), (-1, -1), 0.3, bord),
                    ("TOPPADDING",    (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ]),
            ),
            Paragraph(f"   {rec}", bd),
            Spacer(1, 4 * mm),
        ]
        story.append(KeepTogether(block))

    # ── timeline ──────────────────────────────────────────────────────────
    if findings.timeline:
        rows = [["Time", "Phase", "Event"]] + [
            [ev["ts"][-8:], ev["phase"], ev["event"][:60]]
            for ev in findings.timeline
        ]
        story += [
            PageBreak(),
            Paragraph("Engagement Timeline", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
            RLTable(
                rows,
                colWidths=[22 * mm, 32 * mm, 120 * mm],
                style=tbl(),
            ),
        ]

    # ── footer ────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 10 * mm),
        HRFlowable(color=muted, thickness=0.3),
        Spacer(1, 2 * mm),
        Paragraph(
            f"Generated by HydraSight v{VERSION} on {ts()}"
            f"  •  For authorised security testing only",
            sub,
        ),
    ]

    try:
        doc.build(story)
        log.info("pdf generated: %s", path)
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("pdf generation failed: %s", exc)
        return False
