"""JSON engagement export."""
import json
import logging
from pathlib import Path

from hydrasight.models.findings import Findings

log = logging.getLogger("hydrasight")


def save_json(findings: Findings, path: str) -> bool:
    """Serialise all findings to a JSON file. Returns True on success."""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(findings.to_dict(), fh, indent=2, default=str)
        log.info("saved json: %s", path)
        return True
    except (OSError, PermissionError) as exc:
        log.error("json save failed: %s", exc)
        return False
