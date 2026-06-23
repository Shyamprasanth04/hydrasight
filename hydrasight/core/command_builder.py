import shlex

from hydrasight.models.commands import (
    CommandPart,
    CommandSpec,
    RenderedCommand,
)


class CommandBuilderError(Exception):
    pass

class CommandBuilder:
    @staticmethod
    def _quote(part: CommandPart) -> str:
        if part.quote:
            # shlex.quote handles safely quoting strings for shell execution
            return shlex.quote(part.value)
        return part.value

    @staticmethod
    def build(spec: CommandSpec) -> RenderedCommand:
        errors = []
        parts = []

        if not spec.executable:
            errors.append("Command specification missing executable")
            return RenderedCommand(raw_string="", spec=spec, is_safe=False, validation_errors=errors)

        parts.append(CommandBuilder._quote(CommandPart(spec.executable, quote=True)))

        for arg in spec.args:
            # Prevent injection of shell meta-characters if not quoted
            if not arg.quote and any(c in arg.value for c in ['|', '>', '<', '&', ';', '$', '`', '\n']):
                errors.append(f"Unquoted argument contains shell metacharacters: {arg.value}")

            parts.append(CommandBuilder._quote(arg))

        if spec.stderr_to_stdout:
            parts.append("2>&1")

        for pipe in spec.pipes:
            if not pipe.command:
                errors.append("Empty pipe command")
                continue
            parts.append("|")
            parts.append(shlex.quote(pipe.command))
            for parg in pipe.args:
                parts.append(shlex.quote(parg))

        if spec.truncation:
            # Only head/tail are supported for truncation
            if spec.truncation.max_lines_head is not None:
                parts.append("|")
                parts.append("head")
                parts.append(f"-n {spec.truncation.max_lines_head}")
            if spec.truncation.max_lines_tail is not None:
                parts.append("|")
                parts.append("tail")
                parts.append(f"-n {spec.truncation.max_lines_tail}")

        for redir in spec.redirects:
             operator = ">>" if redir.append else ">"
             fd_prefix = str(redir.fd) if redir.fd != 1 else ""
             parts.append(f"{fd_prefix}{operator} {shlex.quote(redir.target)}")

        # Join the command
        raw_string = " ".join(parts)

        # Verify no rogue "21" suffix exists due to malformed stderr redirects
        if " 21 " in f" {raw_string} " or raw_string.endswith(" 21"):
            errors.append("Detected malformed '21' suffix. This is typically a broken '2>&1' redirect.")

        is_safe = len(errors) == 0
        return RenderedCommand(raw_string=raw_string, spec=spec, is_safe=is_safe, validation_errors=errors)

    @staticmethod
    def normalize_flag(flag: str) -> str:
        """Helper to fix malformed flags like '--max-retries 1' to '--max-retries=1'"""
        flag = flag.strip()
        if flag.startswith("--") and " " in flag and "=" not in flag:
            parts = flag.split(" ", 1)
            return f"{parts[0]}={parts[1]}"
        return flag
