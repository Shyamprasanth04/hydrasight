"""Pure, testable hash-cracking helpers.

The engagement :class:`~hydrasight.core.engine.Engine` delegates the
*construction* of a `john the ripper <https://www.openwall.com/john/>`_ command
and the *parsing* of its output to the functions here, keeping the credential-
recovery logic free of dispatcher/UI concerns.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path

# Marker echoed between the crack pass and the ``--show`` pass; only output
# after this line is parsed for recovered credentials.
CRACKED_MARKER = "---CRACKED---"

# Passwords longer than this are treated as junk/noise rather than credentials.
_MAX_PASSWORD_LEN = 64


def encode_hashes(hashes: list[dict]) -> str:
    """Render captured hash dicts into john ``user:$NT$hash`` lines."""
    return "\n".join(f"{h['username']}:$NT${h['ntlm']}" for h in hashes)


def build_crack_command(hash_lines: str, rockyou_path: str | Path) -> str:
    """Build the self-contained john command.

    The hash lines are base64-embedded into a temp file so no quoting issues
    reach the shell. The command runs john (NT format, rockyou wordlist),
    echoes the :data:`CRACKED_MARKER`, then runs ``john --show`` so recovered
    credentials appear after the marker; the temp file is cleaned up.
    """
    rockyou = str(rockyou_path)
    b64 = base64.b64encode(hash_lines.encode()).decode()
    return (
        "HFILE=$(mktemp /tmp/hs_XXXXXX.txt) && "
        f"printf '%s' '{b64}' | base64 -d > \"$HFILE\" && "
        f"john --format=NT --wordlist={rockyou} "
        '"$HFILE" --pot=/tmp/hs.pot 2>&1 ; '
        f"echo '{CRACKED_MARKER}' ; "
        'john --format=NT --show "$HFILE" '
        "--pot=/tmp/hs.pot 2>&1 ; "
        'rm -f "$HFILE"'
    )


def parse_cracked_output(output: str) -> dict[str, str]:
    """Parse john ``--show`` output into a ``{user: password}`` mapping.

    Only lines after the :data:`CRACKED_MARKER` are considered. The numeric
    summary line (e.g. ``2 password hashes cracked``), over-long values, and
    duplicate users are dropped.
    """
    cracked: dict[str, str] = {}
    in_cracked = False
    for line in output.splitlines():
        line = line.strip()
        if line == CRACKED_MARKER:
            in_cracked = True
            continue
        if not in_cracked:
            continue
        m = re.match(r"^([^:]+):([^:$][^:]*?)(?::|$)", line)
        if not m:
            continue
        user, pw = m.group(1).strip(), m.group(2).strip()
        if not pw or len(pw) > _MAX_PASSWORD_LEN or user.isdigit():
            continue
        # john --show may repeat the same account; keep the first recovery.
        if user.lower() not in {u.lower() for u in cracked}:
            cracked[user] = pw
    return cracked
