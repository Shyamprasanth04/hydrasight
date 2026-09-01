"""Tests for the pure hash-cracking helpers in core/hash_crack.py."""

from __future__ import annotations

from hydrasight.core.hash_crack import (
    CRACKED_MARKER,
    build_crack_command,
    encode_hashes,
    parse_cracked_output,
)


def test_encode_hashes_nt_format():
    hashes = [
        {"username": "alice", "ntlm": "11111111111111111111111111111111"},
        {"username": "bob", "ntlm": "22222222222222222222222222222222"},
    ]
    out = encode_hashes(hashes)
    assert out == (
        "alice:$NT$11111111111111111111111111111111\nbob:$NT$22222222222222222222222222222222"
    )


def test_encode_hashes_empty():
    assert encode_hashes([]) == ""


def test_build_crack_command_embeds_hashes_and_marker():
    cmd = build_crack_command("alice:$NT$abc", "/usr/share/wordlists/rockyou.txt")
    assert "john --format=NT" in cmd
    assert "--wordlist=/usr/share/wordlists/rockyou.txt" in cmd
    assert CRACKED_MARKER in cmd
    assert "john --format=NT --show" in cmd
    assert "base64 -d" in cmd
    assert "mktemp" in cmd
    assert "rm -f" in cmd


def test_parse_cracked_output_only_after_marker():
    output = (
        "Using default input encoding: UTF-8\n"
        "Loaded 2 password hashes (NT [MD4 32/32])\n"
        "Press 'q' or Ctrl-C to abort\n"
        f"{CRACKED_MARKER}\n"
        "alice:Password123:::\n"
        "bob:hunter2:::\n"
        "2 password hashes cracked, 0 left\n"
    )
    result = parse_cracked_output(output)
    assert result == {"alice": "Password123", "bob": "hunter2"}


def test_parse_cracked_output_ignores_pre_marker_noise():
    # Credentials appearing BEFORE the marker must not be parsed (they are
    # progress output, not the --show dump).
    output = f"eve:shouldnotparse:::\n{CRACKED_MARKER}\nrealuser:goodpass:::\n"
    result = parse_cracked_output(output)
    assert result == {"realuser": "goodpass"}


def test_parse_cracked_output_drops_summary_line():
    output = f"{CRACKED_MARKER}\n1 password hashes cracked, 1 left\n"
    assert parse_cracked_output(output) == {}


def test_parse_cracked_output_drops_overlong_values():
    long_pw = "x" * 200
    output = f"{CRACKED_MARKER}\nuser:{long_pw}:::\n"
    assert parse_cracked_output(output) == {}


def test_parse_cracked_output_drops_numeric_usernames():
    output = f"{CRACKED_MARKER}\n1234:somepass:::\n"
    assert parse_cracked_output(output) == {}


def test_parse_cracked_output_dedupes_users_case_insensitive():
    output = f"{CRACKED_MARKER}\nADMIN:FirstPass:::\nadmin:SecondPass:::\n"
    result = parse_cracked_output(output)
    # First recovery wins; both casings collapse to one user.
    assert len(result) == 1
    assert result["ADMIN"] == "FirstPass"


def test_parse_cracked_output_empty_without_marker():
    assert parse_cracked_output("user:pass:::\n") == {}
    assert parse_cracked_output("") == {}
