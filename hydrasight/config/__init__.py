"""Config package."""

from hydrasight.config.defaults import (
    VERSION, CODENAME, APP_NAME,
    DEFAULT_CONFIG, _CONFIG_ALLOWED_KEYS,
    P, SEV, TOOL_LABELS, PHASE_DEFS, TOOL_TIMEOUTS,
    NIKTO_MAXTIME, BANNER, SYSTEM_PROMPT,
)
from hydrasight.config.loader import load_config

__all__ = [
    "VERSION", "CODENAME", "APP_NAME",
    "DEFAULT_CONFIG", "_CONFIG_ALLOWED_KEYS",
    "P", "SEV", "TOOL_LABELS", "PHASE_DEFS", "TOOL_TIMEOUTS",
    "NIKTO_MAXTIME", "BANNER", "SYSTEM_PROMPT",
    "load_config",
]
