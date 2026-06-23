"""Config package."""

from hydrasight.config.defaults import (
    _CONFIG_ALLOWED_KEYS,
    APP_NAME,
    BANNER,
    CODENAME,
    DEFAULT_CONFIG,
    NIKTO_MAXTIME,
    PHASE_DEFS,
    SEV,
    SYSTEM_PROMPT,
    TOOL_LABELS,
    TOOL_TIMEOUTS,
    VERSION,
    P,
)
from hydrasight.config.loader import load_config

__all__ = [
    "VERSION",
    "CODENAME",
    "APP_NAME",
    "DEFAULT_CONFIG",
    "_CONFIG_ALLOWED_KEYS",
    "P",
    "SEV",
    "TOOL_LABELS",
    "PHASE_DEFS",
    "TOOL_TIMEOUTS",
    "NIKTO_MAXTIME",
    "BANNER",
    "SYSTEM_PROMPT",
    "load_config",
]
