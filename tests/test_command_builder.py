from hydrasight.core.command_builder import CommandBuilder
from hydrasight.models.commands import CommandPart, CommandSpec, TruncationSpec


def test_basic_command_rendering():
    spec = CommandSpec(
        executable="nmap",
        args=[CommandPart("-p", quote=False), CommandPart("80,443", quote=True), CommandPart("10.10.10.10", quote=True)]
    )
    rendered = CommandBuilder.build(spec)
    assert rendered.is_safe
    assert rendered.raw_string == "nmap -p 80,443 10.10.10.10"

def test_stderr_to_stdout_correctness():
    # It must render as 2>&1, not 21
    spec = CommandSpec(
        executable="enum4linux",
        args=[CommandPart("-a", quote=False), CommandPart("192.168.100.133", quote=True)],
        stderr_to_stdout=True
    )
    rendered = CommandBuilder.build(spec)
    assert rendered.is_safe
    assert rendered.raw_string == "enum4linux -a 192.168.100.133 2>&1"
    assert "21" not in rendered.raw_string

def test_truncation_rendering():
    spec = CommandSpec(
        executable="nikto",
        args=[CommandPart("-h", quote=False), CommandPart("http://10.10.10.10", quote=True)],
        stderr_to_stdout=True,
        truncation=TruncationSpec(max_lines_head=150)
    )
    rendered = CommandBuilder.build(spec)
    assert rendered.is_safe
    # order: args, stderr, pipes, truncation
    assert rendered.raw_string == "nikto -h http://10.10.10.10 2>&1 | head -n 150"
    assert "21" not in rendered.raw_string

def test_normalize_nmap_flag():
    flag = "--max-retries 1"
    normalized = CommandBuilder.normalize_flag(flag)
    assert normalized == "--max-retries=1"

    flag2 = "--min-rate 1000"
    normalized2 = CommandBuilder.normalize_flag(flag2)
    assert normalized2 == "--min-rate=1000"

def test_shell_metacharacter_rejection():
    # Testing that an unquoted argument with a metacharacter throws a validation error
    spec = CommandSpec(
        executable="ping",
        args=[CommandPart("-c", quote=False), CommandPart("1", quote=False), CommandPart("127.0.0.1; id", quote=False)]
    )
    rendered = CommandBuilder.build(spec)
    assert not rendered.is_safe
    assert "Unquoted argument contains shell metacharacters: 127.0.0.1; id" in rendered.validation_errors

def test_shell_metacharacter_quoted_is_safe():
    # If quoted, it's treated as a single argument safely by shlex.quote
    spec = CommandSpec(
        executable="echo",
        args=[CommandPart("hello; id", quote=True)]
    )
    rendered = CommandBuilder.build(spec)
    assert rendered.is_safe
    assert rendered.raw_string == "echo 'hello; id'"
