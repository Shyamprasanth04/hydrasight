"""Tests for Findings — thread safety and data integrity."""

import threading

import pytest

from hydrasight.models.findings import Findings


@pytest.fixture
def f() -> Findings:
    return Findings()


class TestFindingsBasic:
    def test_initial_state_empty(self, f):
        assert f.ports == []
        assert f.vulns == []
        assert f.credentials == []
        assert f.hashes == []
        assert not f.has_data

    def test_add_port(self, f):
        f.add_port(22, "tcp", "ssh", "OpenSSH 7.9")
        assert len(f.ports) == 1
        assert f.ports[0]["port"] == 22

    def test_add_port_dedup(self, f):
        f.add_port(22, "tcp", "ssh")
        f.add_port(22, "tcp", "ssh")
        assert len(f.ports) == 1

    def test_add_vuln(self, f):
        f.add_vuln("MS17-010", "CRITICAL", "SMBv1 RCE", "CVE-2017-0144", 445)
        assert len(f.vulns) == 1
        assert f.vulns[0]["severity"] == "CRITICAL"

    def test_add_vuln_dedup(self, f):
        f.add_vuln("MS17-010", "CRITICAL", "desc")
        f.add_vuln("MS17-010", "CRITICAL", "desc")
        assert len(f.vulns) == 1

    def test_severity_normalised(self, f):
        f.add_vuln("test", "critical", "desc")
        assert f.vulns[0]["severity"] == "CRITICAL"

    def test_invalid_severity_defaults_to_info(self, f):
        f.add_vuln("test", "BOGUS", "desc")
        assert f.vulns[0]["severity"] == "INFO"

    def test_add_cred(self, f):
        f.add_cred("admin", "password123", kind="bruteforce", source="hydra")
        assert len(f.credentials) == 1

    def test_add_cred_dedup(self, f):
        f.add_cred("admin", "password123")
        f.add_cred("admin", "password123")
        assert len(f.credentials) == 1

    def test_add_hash(self, f):
        f.add_hash(
            "Administrator", "aad3b435b51404eeaad3b435b51404ee", "31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        assert len(f.hashes) == 1

    def test_add_hash_dedup(self, f):
        ntlm = "31d6cfe0d16ae931b73c59d7e0c089c0"
        f.add_hash("Administrator", "aad3b435b51404eeaad3b435b51404ee", ntlm)
        f.add_hash("Administrator", "aad3b435b51404eeaad3b435b51404ee", ntlm)
        assert len(f.hashes) == 1

    def test_add_dir(self, f):
        f.add_dir("/admin", 301)
        assert len(f.dirs) == 1

    def test_add_event(self, f):
        f.add_event("RECON", "nmap completed")
        assert len(f.timeline) == 1


class TestFindingsCounts:
    def test_critical_count(self, f):
        f.add_vuln("A", "CRITICAL", "desc")
        f.add_vuln("B", "HIGH", "desc")
        assert f.critical_count == 1
        assert f.high_count == 1

    def test_overall_risk_critical(self, f):
        f.add_vuln("A", "CRITICAL", "desc")
        assert f.overall_risk == "CRITICAL"

    def test_overall_risk_none(self, f):
        assert f.overall_risk == "NONE"

    def test_overall_risk_high_when_no_critical(self, f):
        f.add_vuln("A", "HIGH", "desc")
        assert f.overall_risk == "HIGH"

    def test_has_data_with_port(self, f):
        assert not f.has_data
        f.add_port(80, "tcp", "http")
        assert f.has_data


class TestFindingsReset:
    def test_reset_clears_all(self, f):
        f.add_port(22, "tcp", "ssh")
        f.add_vuln("test", "HIGH", "desc")
        f.add_cred("user", "pass")
        f.reset()
        assert not f.has_data
        assert f.ports == []
        assert f.vulns == []

    def test_reset_preserves_lock(self, f):
        f.reset()
        # Lock still works — can add after reset
        f.add_port(22, "tcp", "ssh")
        assert len(f.ports) == 1


class TestFindingsThreadSafety:
    def test_concurrent_add_ports(self, f):
        """Concurrent port adds must not lose data or raise errors."""
        errors: list[Exception] = []

        def add_ports(start: int) -> None:
            for i in range(start, start + 50):
                try:
                    f.add_port(i, "tcp", "service")
                except Exception as exc:
                    errors.append(exc)

        threads = [threading.Thread(target=add_ports, args=(i * 50,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(f.ports) == 200

    def test_concurrent_add_vulns(self, f):
        errors: list[Exception] = []

        def add_vulns(prefix: str) -> None:
            for i in range(20):
                try:
                    f.add_vuln(f"{prefix}-{i}", "HIGH", "desc")
                except Exception as exc:
                    errors.append(exc)

        threads = [threading.Thread(target=add_vulns, args=(f"T{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(f.vulns) == 100

    def test_concurrent_reset_and_add(self, f):
        """Reset during concurrent adds must not raise RuntimeError."""
        errors: list[Exception] = []

        def add_loop() -> None:
            for _ in range(100):
                try:
                    f.add_port(80, "tcp", "http")
                except Exception as exc:
                    errors.append(exc)

        def reset_loop() -> None:
            for _ in range(10):
                try:
                    f.reset()
                except Exception as exc:
                    errors.append(exc)

        t1 = threading.Thread(target=add_loop)
        t2 = threading.Thread(target=reset_loop)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert not errors


class TestFindingsSerialisation:
    def test_to_dict_keys(self, f):
        d = f.to_dict()
        assert "meta" in d
        assert "summary" in d
        assert "ports" in d
        assert "vulns" in d

    def test_to_dict_summary_counts(self, f):
        f.add_port(22, "tcp", "ssh")
        f.add_vuln("MS17-010", "CRITICAL", "desc")
        d = f.to_dict()
        assert d["summary"]["ports"] == 1
        assert d["summary"]["vulns"] == 1
        assert d["summary"]["critical"] == 1
