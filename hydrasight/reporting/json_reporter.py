"""JSON engagement export."""

import json
import logging
from pathlib import Path

from hydrasight.models.findings import Findings
from hydrasight.models.report_model import ReportModel

log = logging.getLogger("hydrasight")


def save_json(findings: Findings, path: str) -> bool:
    """Serialise findings to a JSON file, including the normalized ReportModel."""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        # Build structured output
        out = {
            "reporting": ReportModel.from_findings(findings).to_dict(),
            "_deprecated_legacy_raw": findings.to_dict()  # compatibility only, do not use for new consumers
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, default=str)
        log.info("saved json: %s", path)
        return True
    except (OSError, PermissionError) as exc:
        log.error("json save failed: %s", exc)
        return False
