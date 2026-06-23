"""Tests for ip_utils — validation, dedup, force_ip."""

from hydrasight.utils.ip_utils import dedup_ports, force_ip, is_valid_ip


class TestIsValidIP:
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert is_valid_ip("::1") is True

    def test_invalid_too_large_octet(self):
        assert is_valid_ip("999.1.1.1") is False

    def test_invalid_hostname(self):
        assert is_valid_ip("example.com") is False

    def test_invalid_empty(self):
        assert is_valid_ip("") is False

    def test_invalid_partial(self):
        assert is_valid_ip("192.168") is False

    def test_loopback(self):
        assert is_valid_ip("127.0.0.1") is True

    def test_broadcast(self):
        assert is_valid_ip("255.255.255.255") is True


class TestDedupPorts:
    def test_basic_dedup(self):
        ports = [
            {"port": 22, "proto": "tcp"},
            {"port": 22, "proto": "tcp"},
            {"port": 80, "proto": "tcp"},
        ]
        result = dedup_ports(ports)
        assert result == [22, 80]

    def test_sorted_output(self):
        ports = [
            {"port": 443, "proto": "tcp"},
            {"port": 22, "proto": "tcp"},
            {"port": 80, "proto": "tcp"},
        ]
        assert dedup_ports(ports) == [22, 80, 443]

    def test_empty_input(self):
        assert dedup_ports([]) == []

    def test_single_port(self):
        ports = [{"port": 8080, "proto": "tcp"}]
        assert dedup_ports(ports) == [8080]


class TestForceIP:
    def test_replaces_wrong_ip(self):
        result = force_ip("nmap 10.0.0.99 -sV", "192.168.1.10")
        assert "192.168.1.10" in result
        assert "10.0.0.99" not in result

    def test_preserves_lhost(self):
        result = force_ip(
            "set LHOST 10.10.10.1 set RHOSTS 10.0.0.99",
            "192.168.1.10",
            preserve=["10.10.10.1"],
        )
        assert "10.10.10.1" in result
        assert "10.0.0.99" not in result

    def test_preserves_loopback(self):
        result = force_ip(
            "nmap 10.0.0.1 -sV --proxy 127.0.0.1",
            "192.168.1.10",
            preserve=["127.0.0.1"],
        )
        assert "127.0.0.1" in result

    def test_no_op_on_empty_string(self):
        assert force_ip("", "192.168.1.10") == ""

    def test_no_op_on_invalid_correct_ip(self):
        result = force_ip("nmap 10.0.0.1", "not-an-ip")
        assert result == "nmap 10.0.0.1"

    def test_replaces_multiple_occurrences(self):
        result = force_ip(
            "nmap 10.0.0.1 && curl http://10.0.0.1/",
            "192.168.1.10",
        )
        assert result.count("192.168.1.10") == 2
        assert "10.0.0.1" not in result

    def test_does_not_alter_non_ip_text(self):
        result = force_ip("echo hello world", "192.168.1.10")
        assert result == "echo hello world"
