"""
All Rich terminal UI helpers — panels, spinners, stats line, phase headers.

The module-level `console` object is the single shared Rich Console
used throughout the entire application.
"""

import json
import re
from typing import TYPE_CHECKING, Any

from rich import box
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table

from hydrasight.config.defaults import TOOL_LABELS, P

if TYPE_CHECKING:
    from hydrasight.models.findings import Findings

# ── shared console ────────────────────────────────────────────────────────────
console = Console(highlight=False)


# ── dividers ──────────────────────────────────────────────────────────────────


def div(label: str = "") -> None:
    if label:
        console.print(Rule(f"[{P.MUTED}] {label} [/]", style=P.DIM))
    else:
        console.print(Rule(style=P.DIM))


# ── one-liner status messages ─────────────────────────────────────────────────


def ok(msg: str) -> None:
    console.print(f"  [{P.PRIMARY}][+][/]  [{P.TEXT}]{msg}[/]")


def warn(msg: str) -> None:
    console.print(f"  [{P.AMBER}][!][/]  [{P.AMBER}]{msg}[/]")


def info(msg: str) -> None:
    console.print(f"  [{P.DIM}][>][/]  [{P.MUTED}]{msg}[/]")


def err(msg: str) -> None:
    console.print(f"  [{P.RED}][x][/]  [{P.RED}]{msg}[/]")


def hit(msg: str) -> None:
    console.print(f"  [{P.BRIGHT}][*][/]  [{P.BRIGHT}]{msg}[/]")


def label(key: str, val: str, kw: int = 14) -> None:
    console.print(f"  [{P.MUTED}]{key.ljust(kw)}[/]  [{P.TEXT}]{val}[/]")


# ── spinners ──────────────────────────────────────────────────────────────────


def spinner(text: str) -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="line", style=P.PRIMARY),
        TextColumn(f"[{P.MUTED}]{text}[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


# ── phase header ──────────────────────────────────────────────────────────────


def phase_header(phase_id: str, phase_label: str, color: str, idx: int, total: int) -> None:
    pct = int((idx / total) * 100)
    filled = int((idx / total) * 24)
    progress_bar = f"[{P.PRIMARY}]{'█' * filled}[/][{P.DIM}]{'─' * (24 - filled)}[/]"
    console.print()
    console.print(
        f"  [{P.DIM}]┌──[/] [bold {color}]{phase_label.upper()}[/]"
        f"  [{P.DIM}]│[/]  [{P.MUTED}]phase {idx}/{total}[/]"
        f"  [{P.DIM}]│[/]  [{P.MUTED}]{phase_id}[/]"
    )
    console.print(f"  [{P.DIM}]│[/]  {progress_bar}  [{P.PRIMARY}]{pct}%[/]")
    console.print(f"  [{P.DIM}]└──────────────────────────────[/]")


# ── tool execution lines ──────────────────────────────────────────────────────


def task_line(tool: str) -> None:
    console.print(f"\n  [{P.MUTED}]exec[/]    [{P.PRIMARY}]{TOOL_LABELS.get(tool, tool)}[/]")


def result_line(tool: str, elapsed: float, chars: int, warnings: list[str]) -> None:
    lbl = TOOL_LABELS.get(tool, tool)
    char_s = f"{chars:,}" if chars else "0"
    color = P.PRIMARY if chars else P.AMBER
    console.print(
        f"  [{P.PRIMARY}][+][/]  [{P.MUTED}]{lbl}[/]"
        f"  [{P.DIM}]│[/]  [{P.DIM}]{elapsed:.1f}s[/]"
        f"  [{P.DIM}]│[/]  [{color}]{char_s} bytes[/]"
    )
    for w in warnings:
        warn(w)


# ── AI analysis panel ─────────────────────────────────────────────────────────


def analysis_panel(text: str) -> None:
    section_map = {
        "PORTS": (P.BLUE, "ports   "),
        "VULNS": (P.AMBER, "vulns   "),
        "CREDS": (P.PRIMARY, "creds   "),
        "SESSIONS": (P.PRIMARY, "session "),
        "NOTES": (P.MUTED, "notes   "),
    }
    lines_out: list[tuple[str, str, str]] = []
    clean = re.sub(r"```(?:json)?|```", "", text).strip()
    try:
        data = json.loads(clean)
        if isinstance(data, dict):
            for key, (color, lbl) in section_map.items():
                val: Any = data.get(key) or data.get(key.lower())
                if val is None:
                    val = "—"
                elif isinstance(val, list):
                    parts: list[str] = []
                    for item in val:
                        if isinstance(item, dict):
                            sev = item.get("severity", "")
                            desc = item.get(
                                "description",
                                item.get("name", str(item)),
                            )
                            parts.append(f"[{sev.upper()}] {desc}" if sev else str(desc))
                        else:
                            parts.append(str(item))
                    val = "  │  ".join(parts) if parts else "—"
                elif str(val).lower() in ("null", "none", ""):
                    val = "—"
                lines_out.append((color, lbl, str(val)))
    except (json.JSONDecodeError, TypeError):
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            matched = False
            for key, (color, lbl) in section_map.items():
                if line.upper().startswith(key + ":"):
                    val_str = line[len(key) + 1 :].strip() or "—"
                    lines_out.append((color, lbl, val_str))
                    matched = True
                    break
            if not matched and lines_out:
                c, lb, v = lines_out[-1]
                lines_out[-1] = (c, lb, f"{v} {line}")
    if not lines_out:
        return
    console.print()
    console.print(f"  [{P.DIM}]┌──[/]  [{P.MUTED}]intelligence[/]")
    for color, lbl, val in lines_out:
        if len(val) > 92:
            val = val[:89] + "…"
        console.print(f"  [{P.DIM}]│[/]   [{P.MUTED}]{lbl}[/]  [{color}]{val}[/]")
    console.print(f"  [{P.DIM}]└────────────────────────────────[/]")


# ── raw output preview ────────────────────────────────────────────────────────


def raw_output(output: str, verbosity: int) -> None:
    if verbosity >= 2 and output:
        preview = output[:1200] + ("…" if len(output) > 1200 else "")
        console.print()
        console.print(f"  [{P.DIM}]┌──[/]  [{P.MUTED}]raw output[/]")
        for line in preview.splitlines()[:35]:
            console.print(f"  [{P.DIM}]│[/]   [{P.MUTED}]{line}[/]")
        if len(output) > 1200:
            console.print(f"  [{P.DIM}]│   … truncated[/]")
        console.print(f"  [{P.DIM}]└────────────────────────────────[/]")


# ── stats line ────────────────────────────────────────────────────────────────


def stats_line(findings: "Findings") -> None:
    rc = findings.overall_risk
    risk_color = {
        "CRITICAL": P.RED,
        "HIGH": P.AMBER,
        "MEDIUM": P.YELLOW,
        "LOW": P.BLUE,
        "NONE": P.DIM,
    }.get(rc, P.DIM)
    console.print(
        f"\n  [{P.DIM}]│[/]  [{P.MUTED}]ports[/] "
        f"[{P.TEXT}]{len(findings.ports):>3}[/]"
        f"  [{P.DIM}]│[/]  [{P.MUTED}]vulns[/] "
        f"[{P.AMBER}]{len(findings.vulns):>3}[/]"
        f"  [{P.DIM}]│[/]  [{P.MUTED}]crit[/]  "
        f"[{P.RED}]{findings.critical_count:>3}[/]"
        f"  [{P.DIM}]│[/]  [{P.MUTED}]creds[/] "
        f"[{P.BRIGHT}]{len(findings.credentials):>2}[/]"
        f"  [{P.DIM}]│[/]  [{P.MUTED}]sess[/]  "
        f"[{P.BRIGHT}]{len(findings.sessions):>2}[/]"
        f"  [{P.DIM}]│[/]  [{P.MUTED}]risk[/]  "
        f"[{risk_color}]{rc}[/]"
        f"  [{P.DIM}]│[/]"
    )


# ── findings table helper ─────────────────────────────────────────────────────


def make_table(*cols: tuple) -> Table:
    t = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style=P.MUTED,
        border_style=P.DIM,
        padding=(0, 2),
    )
    for name, style, width in cols:
        kw: dict[str, Any] = {"style": style}
        if width:
            kw["width"] = width
        t.add_column(name, **kw)
    return t
