"""
Command sanitization layer for the HydraSight execution boundary.

Validates all tool_call arguments and raw command strings before they
reach KaliAPI.  Every field from the AI model is treated as untrusted.

Design principles:
  - Fail closed: if validation cannot determine safety, reject.
  - Allowlist over blocklist: only known-safe binaries and patterns pass.
  - Preserve HydraSight's existing safe internal patterns
    (2>&1 piping, | head/tail/grep truncation, timeout prefix, base64
    transport for post_exploit).
  - No broad exception catches — callers handle errors.
  - Stateless: every function is pure.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

# ── result type ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SanitizeResult:
    """Outcome of a sanitization check."""

    allowed: bool
    reason: str

    @staticmethod
    def ok() -> SanitizeResult:
        return SanitizeResult(allowed=True, reason="")

    @staticmethod
    def reject(reason: str) -> SanitizeResult:
        return SanitizeResult(allowed=False, reason=reason)


# ── constants ─────────────────────────────────────────────────────────────────

# Binaries that HydraSight legitimately executes via run_command or
# builds internally.  Anything not on this list is blocked.
ALLOWED_BINARIES: frozenset[str] = frozenset(
    {
        "nmap",
        "gobuster",
        "nikto",
        "whatweb",
        "enum4linux",
        "hydra",
        "msfconsole",
        "smbclient",
        "curl",
        "sshpass",
        "john",
        "ping",
        "ip",
        "timeout",
        "head",
        "tail",
        "grep",
        "cat",
        "printf",
        "base64",
        "rm",
    }
)

# Shell metacharacters that MUST NOT appear in untrusted input.
# The patterns below are checked AFTER stripping known-safe suffixes
# (like 2>&1, | head, | tail, | grep) that HydraSight itself appends.
_UNSAFE_METACHAR_RE = re.compile(
    r"[;`]"  # command chaining, subshell
    r"|\$\("  # $( subshell
    r"|\$\{"  # ${ variable expansion
    r"|(?<!\d)>{1,2}(?!&)"  # > or >> redirect (but NOT 2>&1)
    r"|<(?!<)"  # < input redirect (but not <<)
)

# Pipe targets that are safe — HydraSight appends these internally.
_SAFE_PIPE_TARGETS: frozenset[str] = frozenset({"head", "tail", "grep"})

# ── IP validation ─────────────────────────────────────────────────────────────

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _is_ip(value: str) -> bool:
    if not _IP_RE.match(value):
        return False
    return all(0 <= int(o) <= 255 for o in value.split("."))


# ── port validation ───────────────────────────────────────────────────────────

_PORT_SPEC_RE = re.compile(
    r"^"
    r"(?:\d{1,5})"  # single port
    r"(?:"
    r"[-,]"  # separator
    r"\d{1,5}"  # another port
    r")*"
    r"$"
)


def _is_valid_port_spec(value: str) -> bool:
    """Validate port specifications like '80', '1-1000', '22,80,443'."""
    value = value.strip()
    if not value:
        return False
    if not _PORT_SPEC_RE.match(value):
        return False
    # Check each port number is in range
    for part in re.split(r"[-,]", value):
        if part and (int(part) < 1 or int(part) > 65535):
            return False
    return True


# ── nmap flag validation ──────────────────────────────────────────────────────

# Nmap flags: must start with - and contain only alphanumeric, hyphens.
# Examples: -sV, -sC, -sS, -T4, -Pn, -O, -A, --script, --script-timeout
_NMAP_FLAG_RE = re.compile(r"^--?[a-zA-Z][a-zA-Z0-9-]*$")

# Nmap flag arguments that take a value (the value follows the flag).
# Example: --script smb-vuln-ms17-010, --script-timeout 60s
_NMAP_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--script",
        "--script-timeout",
        "--script-args",
        "--min-rate",
        "--max-rate",
        "--top-ports",
        "--version-intensity",
    }
)

# Allowed characters in nmap flag values (script names, timeouts, etc.).
_NMAP_VALUE_RE = re.compile(r"^[a-zA-Z0-9_,.*:=/-]+$")


def _validate_nmap_flags(raw: str) -> SanitizeResult:
    """Validate a string of nmap flags/args (scan_type + additional_args)."""
    if not raw or not raw.strip():
        return SanitizeResult.ok()

    tokens = raw.split()
    i = 0
    while i < len(tokens):
        token = tokens[i]

        # Skip -p flags (Dispatcher strips these anyway)
        if token == "-p":
            i += 2
            continue
        if token.startswith("-p") and len(token) > 2:
            i += 1
            continue

        # Must look like a flag
        if not _NMAP_FLAG_RE.match(token):
            return SanitizeResult.reject(
                f"invalid nmap flag: {token!r}"
            )

        # If this is a value-taking flag, validate its argument
        if token in _NMAP_VALUE_FLAGS:
            i += 1
            if i >= len(tokens):
                return SanitizeResult.reject(
                    f"nmap flag {token} requires a value"
                )
            val = tokens[i]
            if not _NMAP_VALUE_RE.match(val):
                return SanitizeResult.reject(
                    f"unsafe value for {token}: {val!r}"
                )
        i += 1

    return SanitizeResult.ok()


# ── path validation ───────────────────────────────────────────────────────────

# Wordlists, userlists, passlists must be absolute paths under known
# safe directories with no traversal or metacharacters.
_SAFE_PATH_PREFIXES: tuple[str, ...] = (
    "/usr/share/wordlists/",
    "/usr/share/seclists/",
    "/opt/",
    "/tmp/",
)

_PATH_RE = re.compile(r"^/[a-zA-Z0-9_./-]+$")


def _is_safe_path(path: str) -> bool:
    """Return True if path is absolute, under a safe prefix, and clean."""
    if not path:
        return False
    if not _PATH_RE.match(path):
        return False
    if ".." in path:
        return False
    return any(path.startswith(pfx) for pfx in _SAFE_PATH_PREFIXES)


# ── URL validation ────────────────────────────────────────────────────────────

_URL_RE = re.compile(
    r"^https?://"
    r"[\da-zA-Z._:@/-]+"  # host, port, path
    r"(\?[a-zA-Z0-9_=&.%+-]*)?"  # optional query string
    r"$"
)


def _is_safe_url(url: str) -> bool:
    return bool(url and _URL_RE.match(url))


# ── MSF module validation ────────────────────────────────────────────────────

_MSF_MODULE_RE = re.compile(
    r"^(exploit|auxiliary|post|payload|encoder|nop)/"
    r"[a-zA-Z0-9_/.-]+$"
)


def _is_safe_msf_module(module: str) -> bool:
    return bool(module and _MSF_MODULE_RE.match(module))


# ── MSF payload validation ───────────────────────────────────────────────────

_MSF_PAYLOAD_RE = re.compile(r"^[a-zA-Z0-9_/.-]+$")


def _is_safe_msf_payload(payload: str) -> bool:
    if not payload:
        return True  # empty payload is valid (auxiliary modules)
    return bool(_MSF_PAYLOAD_RE.match(payload))


# ── extensions validation (gobuster -x) ───────────────────────────────────────

_EXTENSIONS_RE = re.compile(r"^[a-zA-Z0-9,]+$")


# ── metacharacter checking ────────────────────────────────────────────────────


def _strip_safe_suffixes(cmd: str) -> str:
    """Remove known-safe trailing patterns before metachar scanning.

    HydraSight internally appends patterns like:
        2>&1
        2>&1 | head -150
        2>&1 | tail -40
    These are safe and must not trigger false positives.
    """
    # Strip trailing 2>&1 (with optional | head/tail/grep)
    cmd = re.sub(
        r"\s+2>&1(?:\s*\|\s*(?:head|tail|grep)\s+(?:-n\s+\d+|-\d+|\w+))?$",
        "",
        cmd,
    )
    # Strip leading timeout prefix
    cmd = re.sub(r"^timeout\s+\d+\s+", "", cmd)
    return cmd


def _has_unsafe_metacharacters(value: str) -> bool:
    """Return True if *value* contains shell metacharacters.

    This is checked AFTER known-safe suffixes are stripped, so
    patterns like '2>&1 | head -150' do not trigger.
    """
    cleaned = _strip_safe_suffixes(value)
    return bool(_UNSAFE_METACHAR_RE.search(cleaned))


# ── raw-command binary allowlist ──────────────────────────────────────────────


def _extract_binary(cmd: str) -> str | None:
    """Extract the first binary name from a command string.

    Handles:
        nmap ...           → nmap
        timeout 300 hydra  → hydra (skips timeout prefix)
    """
    tokens = cmd.strip().split()
    if not tokens:
        return None

    # Skip 'timeout N' prefix
    if tokens[0] == "timeout" and len(tokens) >= 3:
        try:
            int(tokens[1])
            return tokens[2]
        except ValueError:
            pass

    return tokens[0]


# ── per-tool validators ───────────────────────────────────────────────────────


def validate_nmap_scan(args: dict) -> SanitizeResult:
    """Validate nmap_scan tool_call args."""
    target = args.get("target", "")
    if not _is_ip(target):
        return SanitizeResult.reject(f"invalid target IP: {target!r}")

    ports = args.get("ports", "1-1000")
    if not _is_valid_port_spec(str(ports)):
        return SanitizeResult.reject(f"invalid port spec: {ports!r}")

    scan_type = args.get("scan_type", "-sV")
    additional_args = args.get("additional_args", "")
    combined_flags = f"{scan_type} {additional_args}".strip()

    result = _validate_nmap_flags(combined_flags)
    if not result.allowed:
        return result

    return SanitizeResult.ok()


def validate_gobuster_scan(args: dict) -> SanitizeResult:
    """Validate gobuster_scan tool_call args."""
    url = args.get("url", "")
    if not _is_safe_url(url):
        return SanitizeResult.reject(f"invalid URL: {url!r}")

    wl = args.get("wordlist", "")
    if wl and not _is_safe_path(wl):
        return SanitizeResult.reject(f"invalid wordlist path: {wl!r}")

    ext = args.get("extensions", "")
    if ext and not _EXTENSIONS_RE.match(ext):
        return SanitizeResult.reject(f"invalid extensions: {ext!r}")

    return SanitizeResult.ok()


def validate_nikto_scan(args: dict) -> SanitizeResult:
    """Validate nikto_scan tool_call args."""
    target = args.get("target", "")
    if not _is_ip(target):
        return SanitizeResult.reject(f"invalid target IP: {target!r}")

    port = args.get("port", 80)
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        return SanitizeResult.reject(f"invalid port: {port!r}")
    if not (1 <= port_int <= 65535):
        return SanitizeResult.reject(f"port out of range: {port_int}")

    return SanitizeResult.ok()


def validate_whatweb_scan(args: dict) -> SanitizeResult:
    """Validate whatweb_scan tool_call args."""
    url = args.get("url", "")
    if not _is_safe_url(url):
        return SanitizeResult.reject(f"invalid URL: {url!r}")
    return SanitizeResult.ok()


def validate_smb_enum(args: dict) -> SanitizeResult:
    """Validate smb_enum tool_call args."""
    target = args.get("target", "")
    if not _is_ip(target):
        return SanitizeResult.reject(f"invalid target IP: {target!r}")
    return SanitizeResult.ok()


def validate_ssh_brute(args: dict) -> SanitizeResult:
    """Validate ssh_brute tool_call args."""
    target = args.get("target", "")
    if not _is_ip(target):
        return SanitizeResult.reject(f"invalid target IP: {target!r}")

    for key in ("userlist", "passlist"):
        path = args.get(key, "")
        if path and not _is_safe_path(path):
            return SanitizeResult.reject(f"invalid {key} path: {path!r}")

    return SanitizeResult.ok()


def validate_ftp_brute(args: dict) -> SanitizeResult:
    """Validate ftp_brute tool_call args (same shape as ssh_brute)."""
    return validate_ssh_brute(args)


def validate_post_exploit(args: dict) -> SanitizeResult:
    """Validate post_exploit tool_call args.

    The actual shell command is entirely internally generated by
    Dispatcher._post_exploit(), but we validate the AI-supplied
    *arguments* that feed into the RC script.
    """
    target = args.get("target", "")
    if not _is_ip(target):
        return SanitizeResult.reject(f"invalid target IP: {target!r}")

    module = args.get("module", "")
    if module and not _is_safe_msf_module(module):
        return SanitizeResult.reject(f"invalid MSF module: {module!r}")

    payload = args.get("payload", "")
    if not _is_safe_msf_payload(payload):
        return SanitizeResult.reject(f"invalid MSF payload: {payload!r}")

    for port_key in ("rport", "lport"):
        pval = args.get(port_key)
        if pval is not None:
            try:
                pint = int(pval)
            except (ValueError, TypeError):
                return SanitizeResult.reject(
                    f"invalid {port_key}: {pval!r}"
                )
            if not (1 <= pint <= 65535):
                return SanitizeResult.reject(
                    f"{port_key} out of range: {pint}"
                )

    # Validate post-exploit commands (semicolon-separated inside RC)
    commands = args.get("commands", "")
    if commands:
        # Commands are Meterpreter commands, not shell commands.
        # They go inside sessions -i -1 -C "...", so reject
        # anything that looks like shell injection.
        for part in str(commands).split(";"):
            part = part.strip()
            if not part:
                continue
            if _UNSAFE_METACHAR_RE.search(part):
                return SanitizeResult.reject(
                    f"unsafe meterpreter command: {part!r}"
                )

    return SanitizeResult.ok()


def validate_run_command(args: dict) -> SanitizeResult:
    """Validate run_command — the most dangerous tool.

    Enforces:
    1. Binary allowlist
    2. No unsafe metacharacters (after stripping safe suffixes)
    """
    cmd = args.get("command", "")
    if not cmd or not cmd.strip():
        return SanitizeResult.reject("empty command")

    binary = _extract_binary(cmd)
    if not binary:
        return SanitizeResult.reject("cannot determine binary")

    if binary not in ALLOWED_BINARIES:
        return SanitizeResult.reject(
            f"binary not allowed: {binary!r}"
        )

    # Check pipes: only allow piping to safe targets
    parts = cmd.split("|")
    for pipe_segment in parts[1:]:  # skip first segment (main command)
        segment_tokens = pipe_segment.strip().split()
        if segment_tokens:
            pipe_binary = segment_tokens[0]
            if pipe_binary not in _SAFE_PIPE_TARGETS:
                return SanitizeResult.reject(
                    f"pipe to disallowed binary: {pipe_binary!r}"
                )

    # Check for unsafe metacharacters in the full command
    if _has_unsafe_metacharacters(cmd):
        return SanitizeResult.reject(
            f"unsafe metacharacters in command: {cmd!r}"
        )

    return SanitizeResult.ok()


# ── main entry points ─────────────────────────────────────────────────────────

# Tool → validator mapping
def _generic_target_validator(args: dict) -> SanitizeResult:
    target = args.get("target", "")
    if target and not _is_ip(target):
        return SanitizeResult.reject(f"invalid target IP: {target!r}")
    return SanitizeResult.ok()



_TOOL_VALIDATORS: dict[str, Callable[[dict], SanitizeResult]] = {
    "nmap_scan": validate_nmap_scan,
    "gobuster_scan": validate_gobuster_scan,
    "nikto_scan": validate_nikto_scan,
    "whatweb_scan": validate_whatweb_scan,
    "smb_enum": validate_smb_enum,
    "ssh_brute": validate_ssh_brute,
    "ftp_brute": validate_ftp_brute,
    "post_exploit": validate_post_exploit,
    "run_command": validate_run_command,
    # New registry action IDs
    "smb_check": _generic_target_validator,
    "smbclient_enum": _generic_target_validator,
    "ftp_check": _generic_target_validator,
    "ssh_check": _generic_target_validator,
    "vuln_scan": _generic_target_validator,
    "dir_enum": validate_gobuster_scan,
    "autopwn": _generic_target_validator,
}


def validate_tool_call(tool: str, args: dict) -> SanitizeResult:
    """Validate a tool_call before Dispatcher builds the command.

    This is the primary entry point.  Call it after canonical target
    enforcement and before _build().

    Returns SanitizeResult.ok() if safe, or SanitizeResult.reject(reason)
    if the command should be blocked.
    """
    validator = _TOOL_VALIDATORS.get(tool)
    if validator is None:
        return SanitizeResult.reject(f"unknown tool: {tool!r}")
    res = validator(args)
    if isinstance(res, SanitizeResult):
        return res
    return SanitizeResult.reject(f"invalid result from {tool} validator")


def validate_built_command(cmd: str, tool: str) -> SanitizeResult:
    """Validate the final assembled command string before execution.

    This is a second-pass check on the fully built command.
    post_exploit is exempt because its shell command is entirely
    internally generated (base64 RC transport).
    """
    if tool == "post_exploit":
        return SanitizeResult.ok()

    if not cmd or not cmd.strip():
        return SanitizeResult.reject("empty command")

    binary = _extract_binary(cmd)
    if not binary:
        return SanitizeResult.reject("cannot determine binary")

    if binary not in ALLOWED_BINARIES:
        return SanitizeResult.reject(
            f"binary not allowed in built command: {binary!r}"
        )

    if _has_unsafe_metacharacters(cmd):
        return SanitizeResult.reject(
            "unsafe metacharacters in built command"
        )

    return SanitizeResult.ok()
