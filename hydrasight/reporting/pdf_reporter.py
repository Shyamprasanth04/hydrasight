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

from hydrasight.config.defaults import VERSION
from hydrasight.models.findings import Findings
from hydrasight.models.report_model import ReportModel
from hydrasight.utils.time_utils import ts

log = logging.getLogger("hydrasight")

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        TableStyle,
    )
    from reportlab.platypus import (
        Table as RLTable,
    )

    _PDF_OK = True
except ImportError:
    _PDF_OK = False


def _table_style(
    bg: object,
    bg2: object,
    green2: object,
    grey: object,
    bord: object,
) -> "TableStyle":
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), green2),
            ("TEXTCOLOR", (0, 0), (-1, -1), grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, bord),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [bg, bg2]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
    )


def generate_pdf(
    target: str,
    findings: Findings,
    path: str,
    operator: str = "HydraSight",
) -> bool:
    """
    Generate a dark-themed PDF report emphasizing verified/exploited findings.
    """
    if not _PDF_OK:
        log.warning("reportlab not installed — skipping PDF generation")
        return False

    report = ReportModel.from_findings(findings)

    # ── colour palette ─────────────────────────────────────────────────────
    bg = colors.HexColor("#0D0D14")
    bg2 = colors.HexColor("#1A1A24")
    green = colors.HexColor("#00D67D")
    green2 = colors.HexColor("#007A45")
    grey = colors.HexColor("#E0E0E8")
    muted = colors.HexColor("#9090A8")
    bord = colors.HexColor("#8888A8")
    sev_colors = {
        "CRITICAL": colors.HexColor("#FF5C5C"),
        "HIGH": colors.HexColor("#FFA94D"),
        "MEDIUM": colors.HexColor("#E8C547"),
        "LOW": colors.HexColor("#7AB8E0"),
        "INFO": colors.HexColor("#9090A8"),
    }

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle(
        "H1",
        parent=styles["Title"],
        fontSize=24,
        textColor=green,
        spaceAfter=4,
        alignment=TA_CENTER,
    )
    h2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=green,
        spaceBefore=10,
        spaceAfter=4,
    )
    h3 = ParagraphStyle(
        "H3",
        parent=styles["Heading3"],
        fontSize=10,
        textColor=muted,
        spaceBefore=4,
        spaceAfter=2,
    )
    bd = ParagraphStyle(
        "BD",
        parent=styles["Normal"],
        fontSize=9,
        textColor=grey,
        leading=13,
    )
    sub = ParagraphStyle(
        "SUB",
        parent=styles["Normal"],
        fontSize=8,
        textColor=muted,
        leading=11,
        alignment=TA_CENTER,
    )

    def tbl() -> "TableStyle":
        return _table_style(bg, bg2, green2, grey, bord)

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"HydraSight Report — {target}",
        author=operator,
    )

    has_access = bool(report.sessions)
    has_creds = bool(report.credentials)
    has_vulns = bool(report.exploited_findings or report.verified_findings or report.supported_candidates or report.no_strategy_candidates)

    outcome_str = (
        "Active session obtained" if has_access
        else "Credentials recovered" if has_creds
        else "Vulnerabilities verified" if (report.verified_findings or report.exploited_findings)
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
                "Sub2",
                parent=styles["Heading2"],
                fontSize=14,
                textColor=muted,
                alignment=TA_CENTER,
            ),
        ),
        Spacer(1, 20 * mm),
        RLTable(
            [
                ["TARGET", target],
                ["DATE", ts()],
                ["CONFIRMED RISK", report.confirmed_risk],
                ["POTENTIAL RISK", report.potential_risk],
                ["OUTCOME", outcome_str],
                ["ENGINE", f"HydraSight v{VERSION}"],
            ],
            colWidths=[55 * mm, 115 * mm],
            style=tbl(),
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
            f"<b>{report.verification_coverage.exploited}</b> finding(s) were successfully exploited, and "
            f"<b>{report.verification_coverage.verified}</b> were independently verified. "
            f"There are <b>{report.verification_coverage.unsupported}</b> candidate findings that remain unverified "
            f"due to missing strategy coverage, and <b>{report.verification_coverage.failed}</b> that failed verification. "
            f"{'An active session was obtained.' if has_access else 'No active sessions were established.'} "
            f"Confirmed Risk Rating: <b>{report.confirmed_risk}</b>. Potential Risk Rating: <b>{report.potential_risk}</b>.",
            bd,
        ),
        Spacer(1, 6 * mm),
        Paragraph("Verification Coverage", h3),
        RLTable(
            [
                ["Metric", "Value"],
                ["Total Findings", str(report.verification_coverage.total)],
                ["Exploited", str(report.verification_coverage.exploited)],
                ["Verified", str(report.verification_coverage.verified)],
                ["Failed Verification", str(report.verification_coverage.failed)],
                ["No Verification Strategy", str(report.verification_coverage.no_strategy)],
                ["Error / Not Applicable", str(report.verification_coverage.error + report.verification_coverage.not_applicable)],
            ],
            colWidths=[80 * mm, 90 * mm],
            style=tbl(),
        ),
        Spacer(1, 6 * mm),
        Paragraph("Environment Summary", h3),
        RLTable(
            [
                ["Metric", "Value"],
                ["Open Ports", str(len(report.ports))],
                ["Credentials", str(len(report.credentials))],
                ["Sessions", str(len(report.sessions))],
                ["Web Paths Found", str(len(report.dirs))],
            ],
            colWidths=[80 * mm, 90 * mm],
            style=tbl(),
        ),
        PageBreak(),
    ]

    # Helper to render a finding block
    def render_finding_block(rec, label_text, label_color):
        sc = sev_colors.get(rec.severity, grey)
        block = [
            RLTable(
                [
                    [
                        rec.severity,
                        rec.display_title[:45],
                        rec.verification_reason_code,
                        label_text,
                    ]
                ],
                colWidths=[18 * mm, 90 * mm, 36 * mm, 22 * mm],
                style=TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0), sc),
                        ("BACKGROUND", (1, 0), (2, 0), bg),
                        ("BACKGROUND", (3, 0), (3, 0), label_color),
                        ("TEXTCOLOR", (0, 0), (-1, -1), grey),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.3, bord),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]
                ),
            )
        ]
        if rec.display_summary:
            block.append(Paragraph(f"   {rec.display_summary[:200]}", bd))
        if rec.display_evidence:
            block.append(Paragraph("   Evidence: " + str(rec.display_evidence)[:150], bd))
        if rec.display_remediation:
            block.append(Paragraph(f"   Remediation: {str(rec.display_remediation)[:180]}", bd))
        block.append(Spacer(1, 3 * mm))
        return KeepTogether(block)

    # ── Exploited Findings ──────────────────────────────────────────────────
    if report.exploited_findings:
        story += [
            Paragraph("Proven Access / Exploitation", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
        ]
        for rec in report.exploited_findings:
            story.append(render_finding_block(rec, "PROVEN", colors.HexColor("#8B008B")))

    # ── Verified Findings ───────────────────────────────────────────────────
    if report.verified_findings:
        story += [
            Paragraph("Independently Verified Findings", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
        ]
        for rec in report.verified_findings:
            story.append(render_finding_block(rec, "VERIFIED", colors.HexColor("#00D67D")))

    # ── Candidate Findings With Strategy Support ────────────────────────────
    if report.supported_candidates:
        story += [
            Paragraph("Candidate Findings With Strategy Support", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
        ]
        for rec in report.supported_candidates:
            story.append(render_finding_block(rec, "SUPPORTED CANDIDATE", colors.HexColor("#FFA94D")))

    # ── Attempted But Not Confirmed ─────────────────────────────────────────
    if report.attempted_not_confirmed_findings:
        story += [
            Paragraph("Attempted But Not Confirmed", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
        ]
        for rec in report.attempted_not_confirmed_findings:
            story.append(render_finding_block(rec, "NOT CONFIRMED", colors.HexColor("#FF5C5C")))

    # ── Credentials & Sessions ──────────────────────────────────────────────
    if report.credentials:
        rows = [["Type", "Username", "Secret", "Source"]] + [
            [c["kind"], c["username"][:25], c["secret"][:40], c.get("source", "")]
            for c in report.credentials
        ]
        story += [
            Spacer(1, 6 * mm),
            Paragraph("Recovered Credentials", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
            RLTable(rows, colWidths=[28 * mm, 40 * mm, 80 * mm, 26 * mm], style=tbl()),
        ]

    if report.sessions:
        story += [
            Spacer(1, 6 * mm),
            Paragraph("Access Sessions", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
        ]
        for s in report.sessions:
            story += [
                RLTable(
                    [
                        ["Access Level", s.get("uid", "unknown")],
                        ["Method", s.get("exploit", "—")],
                        ["Target", s.get("target", "—")],
                        ["Timestamp", s.get("ts", "—")],
                    ],
                    colWidths=[40 * mm, 130 * mm],
                    style=tbl(),
                ),
                Spacer(1, 4 * mm),
            ]

    story.append(PageBreak())

    # ── Open Ports ─────────────────────────────────────────────────────────
    if report.ports:
        rows = [["Port", "Proto", "Service", "Version"]] + [
            [str(p["port"]), p["proto"], p["service"], p.get("version", "")]
            for p in sorted(report.ports, key=lambda x: x["port"])
        ]
        story += [
            Paragraph("Open Ports & Services", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
            RLTable(rows, colWidths=[18 * mm, 14 * mm, 38 * mm, 104 * mm], style=tbl()),
            Spacer(1, 6 * mm),
        ]

    # ── Candidate Findings Without Verification Strategy ───────────────────
    if report.no_strategy_candidates:
        story += [
            Paragraph("Candidate Findings Without Verification Strategy", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
            Paragraph("These candidate findings lack automated verification strategies and must be investigated manually. Most are placed in the appendix.", bd),
            Spacer(1, 3 * mm),
        ]
        shown = 0
        for rec in report.no_strategy_candidates:
            if shown >= 5:
                break
            story.append(render_finding_block(rec, "NO STRATEGY", grey))
            shown += 1

        if len(report.no_strategy_candidates) > 5:
            story.append(Paragraph(f"<i>... and {len(report.no_strategy_candidates) - 5} more unverified candidates not shown (see Appendix).</i>", bd))

    # ── Appendix ───────────────────────────────────────────────────────────
    if report.appendix_findings:
        story += [
            PageBreak(),
            Paragraph("Appendix: Additional Candidates", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
        ]
        rows = [["Severity", "Finding", "Status"]] + [
            [r.severity, r.display_title[:60], r.status_label]
            for r in report.appendix_findings
        ]
        story.append(RLTable(rows, colWidths=[20 * mm, 120 * mm, 34 * mm], style=tbl()))

    # ── Remediation Recommendations ────────────────────────────────────────
    # Use normalized report items for remediation to prevent serialization leakage
    recs_from_items = []
    for bucket in [report.exploited_findings, report.verified_findings, report.supported_candidates, report.no_strategy_candidates, report.attempted_not_confirmed_findings]:
        for item in bucket:
            if item.display_remediation:
                recs_from_items.append((item.severity, str(item.display_remediation)))

    # Deduplicate while preserving order
    seen_rems = set()
    unique_recs = []
    for sev, rem in recs_from_items:
        if rem not in seen_rems:
            seen_rems.add(rem)
            unique_recs.append((sev, rem))

    if unique_recs:
        story += [
            PageBreak(),
            Paragraph("Remediation Recommendations", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
        ]
        for i, (pri, remedy) in enumerate(unique_recs[:20], 1):
            pc = sev_colors.get(pri, grey)
            block = [
                RLTable(
                    [[f"  {i}", pri, ""]],
                    colWidths=[10 * mm, 25 * mm, 139 * mm],
                    style=TableStyle(
                        [
                            ("BACKGROUND", (1, 0), (1, 0), pc),
                            ("BACKGROUND", (0, 0), (0, 0), bg2),
                            ("BACKGROUND", (2, 0), (2, 0), bg),
                            ("TEXTCOLOR", (0, 0), (-1, -1), grey),
                            ("FONTNAME", (0, 0), (1, -1), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("GRID", (0, 0), (-1, -1), 0.3, bord),
                            ("TOPPADDING", (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ]
                    ),
                ),
                Paragraph(f"   {remedy}", bd),
                Spacer(1, 4 * mm),
            ]
            story.append(KeepTogether(block))

    # ── Timeline ───────────────────────────────────────────────────────────
    if report.timeline:
        rows = [["Time", "Phase", "Event"]] + [
            [ev["ts"][-8:], ev["phase"], ev["event"][:60]] for ev in report.timeline
        ]
        story += [
            PageBreak(),
            Paragraph("Engagement Timeline", h2),
            HRFlowable(color=green, thickness=0.5),
            Spacer(1, 3 * mm),
            RLTable(rows, colWidths=[22 * mm, 32 * mm, 120 * mm], style=tbl()),
        ]

    # ── Footer ─────────────────────────────────────────────────────────────
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
