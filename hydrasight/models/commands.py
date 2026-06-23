from dataclasses import dataclass, field
from typing import Any


@dataclass
class CommandPart:
    value: str
    quote: bool = True

@dataclass
class RedirectSpec:
    target: str
    append: bool = False
    fd: int = 1 # 1 for stdout, 2 for stderr

@dataclass
class PipeSpec:
    command: str
    args: list[str] = field(default_factory=list)

@dataclass
class TruncationSpec:
    max_lines_head: int | None = None
    max_lines_tail: int | None = None

@dataclass
class CommandSpec:
    executable: str
    args: list[CommandPart] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    redirects: list[RedirectSpec] = field(default_factory=list)
    pipes: list[PipeSpec] = field(default_factory=list)
    truncation: TruncationSpec | None = None
    stderr_to_stdout: bool = False

@dataclass
class RenderedCommand:
    raw_string: str
    spec: CommandSpec
    is_safe: bool = True
    validation_errors: list[str] = field(default_factory=list)

@dataclass
class ActionRequest:
    action_id: str
    target: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    profile: str | None = None
    custom_flags: list[str] = field(default_factory=list)
    is_raw_mode: bool = False

@dataclass
class PendingAction:
    request: ActionRequest
    spec: CommandSpec

    def __init__(
        self,
        request: ActionRequest | None = None,
        spec: CommandSpec | None = None,
        tool_hint: str | None = None,
        target: str | None = None,
        ports: str | None = None,
        flags: list[str] | None = None,
        command_str: str | None = None,
        tool_call: dict | None = None,
        reason: str = "",
        confidence: float = 1.0,
    ):
        if request is not None and spec is not None:
            self.request = request
            self.spec = spec
        else:
            self.request = ActionRequest(action_id=tool_hint or "unknown", target=target)
            args = []
            if command_str:
                args = [CommandPart(command_str, quote=False)]
            self.spec = CommandSpec(executable="legacy", args=args)

        # Legacy compatibility properties
        self._legacy_tool_hint = tool_hint
        self._legacy_target = target
        self._legacy_ports = ports
        self._legacy_flags = flags or []
        self._legacy_command_str = command_str
        self._legacy_tool_call = tool_call
        self.reason = reason
        self.confidence = confidence

    @property
    def command_str(self) -> str:
        legacy = getattr(self, "_legacy_command_str", None)
        if legacy is not None:
            return str(legacy)
        from hydrasight.core.command_builder import CommandBuilder
        return CommandBuilder.build(self.spec).raw_string

    @property
    def tool_hint(self) -> str:
        return getattr(self, "_legacy_tool_hint", None) or self.request.action_id

    @property
    def target(self) -> str | None:
        return getattr(self, "_legacy_target", None) or self.request.target

    @property
    def ports(self) -> str | None:
        return getattr(self, "_legacy_ports", None)

    @property
    def flags(self) -> list[str]:
        return getattr(self, "_legacy_flags", [])

    @property
    def tool_call(self) -> dict:
        legacy = getattr(self, "_legacy_tool_call", None)
        if legacy is not None:
            from typing import cast
            return cast(dict, legacy)
        return {
            "tool": self.request.action_id,
            "args": {"target": self.request.target, **self.request.args}
        }

    @property
    def display(self) -> str:
        return (
            f"  tool    : {self.tool_hint}\n"
            f"  target  : {self.target}\n"
            f"  command : {self.command_str}\n"
            f"  reason  : {getattr(self, 'reason', '')}\n"
            f"  confidence: {getattr(self, 'confidence', 0.0):.0%}"
        )

@dataclass
class ExecutionRequest:
    pending_action: PendingAction
    rendered: RenderedCommand
    dry_run: bool = False
