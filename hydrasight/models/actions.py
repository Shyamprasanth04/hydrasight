from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ROECategory(str, Enum):
    RECON = "RECON"
    ENUM = "ENUM"
    VULN = "VULN"
    EXPLOIT = "EXPLOIT"
    POST_EXPLOIT = "POST_EXPLOIT"
    REPORT = "REPORT"
    NOTE = "NOTE"

@dataclass
class ActionArgSchema:
    name: str
    type: type
    required: bool = False
    default: Any = None
    choices: list[Any] | None = None
    description: str = ""

@dataclass
class ActionDefinition:
    action_id: str
    display_name: str
    roe_category: ROECategory
    description: str
    tool_family: str

    # Execution Rules
    default_timeout: int = 60
    confirmation_override: bool | None = None  # None = use global policy
    confidence_threshold: int = 0

    # Arguments
    args: dict[str, ActionArgSchema] = field(default_factory=dict)
    default_ports: list[int] | None = None
    allowed_custom_flags: dict[str, list[str]] | list[str] | None = None
    raw_mode_schema: dict[str, ActionArgSchema] | None = None

    # Capabilities
    supports_raw_output: bool = True
    supports_notes: bool = True
    supports_custom_flags: bool = False
    supports_dry_run: bool = True

    # Router metadata
    aliases: list[str] = field(default_factory=list)
    routing_keywords: list[str] = field(default_factory=list)

    # References (Strings/Ids instead of functions for serializability)
    builder_id: str | None = None
    parser_strategy_id: str | None = None
    verification_strategy_id: str | None = None

    # Output Handling
    output_handling_profile: str = "default"
    truncation_defaults: dict[str, int] = field(default_factory=lambda: {"head": 500, "tail": 0})

    examples: list[str] = field(default_factory=list)
