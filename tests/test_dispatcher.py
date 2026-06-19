"""Tests for Dispatcher command builders (no live Kali required)."""
import pytest
from unittest.mock import MagicMock
from hydrasight.services.dispatcher import Dispatcher


@pytest.fixture
def dispatcher() -> Dispatcher:
    mock_kali = MagicMock()
    mock_kali.local_ip.return_value = "10.10.10.1"
    mock_log  = MagicMock()
    cfg = {
        "wordlist"    : "/usr/share/wordlists/dirb/common.txt",
        "lport"       : 4444,
        "verbosity"   : 0,
    }
    return Dispatcher(mock_kali, mock_log, cfg)


class TestNmapBuilder:
    def test_basic_nmap(self, dispatcher):
        cmd = dispatcher._build("nmap_scan", {
            "target": "192.168.1.10",
            "scan_type": "-sV -sC",
            "ports": "1-1000",
            "additional_args": "-T4 -Pn",
        })
        assert cmd.startswith("nmap")
        assert "192.168.1.10" in cmd
        assert "-p 1-1000" in cmd
        assert "-sV" in cmd

    def test_nmap_deduplicates_flags(self, dispatcher):
        cmd = dispatcher._build("nmap_scan", {
            "target": "192.168.1.10",
            "scan_type": "-sV -sV",
            "ports": "22",
            "additional_args": "",
        })
        # -sV should appear only once
        assert cmd.count("-sV") == 1

    def test_nmap_no_inline_port_flag(self, dispatcher):
        cmd = dispatcher._build("nmap_scan", {
            "target": "192.168.1.10",
            "scan_type": "-sV -p 80",
            "ports": "1-1000",
            "additional_args": "",
        })
        # The -p 80 from scan_type should be stripped; ports arg controls -p
        assert "-p 1-1000" in cmd


class TestGobusterBuilder:
    def test_basic_gobuster(self, dispatcher):
        cmd = dispatcher._build("gobuster_scan", {
            "url": "http://192.168.1.10",
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
        })
        assert cmd.startswith("gobuster dir")
        assert "http://192.168.1.10" in cmd
        assert "--no-color" in cmd

    def test_gobuster_with_extensions(self, dispatcher):
        cmd = dispatcher._build("gobuster_scan", {
            "url": "http://192.168.1.10",
            "extensions": "php,html",
        })
        assert "-x php,html" in cmd

    def test_gobuster_no_extensions(self, dispatcher):
        cmd = dispatcher._build("gobuster_scan", {
            "url": "http://192.168.1.10",
        })
        assert "-x" not in cmd


class TestNiktoBuilder:
    def test_basic_nikto(self, dispatcher):
        cmd = dispatcher._build("nikto_scan", {
            "target": "192.168.1.10",
            "port": 80,
        })
        assert "nikto" in cmd
        assert "192.168.1.10" in cmd
        assert "-maxtime" in cmd

    def test_nikto_custom_port(self, dispatcher):
        cmd = dispatcher._build("nikto_scan", {
            "target": "192.168.1.10",
            "port": 8080,
        })
        assert "8080" in cmd


class TestRunCommandBuilder:
    def test_passthrough(self, dispatcher):
        cmd = dispatcher._build("run_command", {
            "command": "id && whoami"
        })
        assert cmd == "id && whoami"

    def test_default_echo(self, dispatcher):
        cmd = dispatcher._build("run_command", {})
        assert cmd == "echo ok"


class TestUnknownTool:
    def test_unknown_returns_empty(self, dispatcher):
        cmd = dispatcher._build("nonexistent_tool", {})
        assert cmd == ""


class TestSmbEnumBuilder:
    def test_smb_enum(self, dispatcher):
        cmd = dispatcher._build("smb_enum", {"target": "192.168.1.10"})
        assert "enum4linux" in cmd
        assert "192.168.1.10" in cmd


class TestSSHBruteBuilder:
    def test_ssh_brute(self, dispatcher):
        cmd = dispatcher._build("ssh_brute", {"target": "192.168.1.10"})
        assert "hydra" in cmd
        assert "ssh://192.168.1.10" in cmd

    def test_ftp_brute(self, dispatcher):
        cmd = dispatcher._build("ftp_brute", {"target": "192.168.1.10"})
        assert "hydra" in cmd
        assert "ftp://192.168.1.10" in cmd
