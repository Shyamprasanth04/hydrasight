"""
Tests for Parser — validates regex extraction against real tool output samples.
"""
import pytest
from hydrasight.parsers import Parser


# ── nmap output samples ───────────────────────────────────────────────────────

NMAP_BASIC = """\
Starting Nmap 7.94
Nmap scan report for 192.168.1.10
Host is up (0.00050s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
80/tcp  open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian

Nmap done: 1 IP address (1 host up) scanned in 12.3s
"""

NMAP_VULN = """\
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0144
|_    Risk factor: HIGH
"""

NMAP_FTP_ANON = """\
21/tcp open  ftp     vsftpd 2.3.4
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        65534        4096 Mar 17  2010 pub
"""

NMAP_OS = """\
Running: Microsoft Windows 2008|Vista
OS details: Microsoft Windows Server 2008 R2 SP1
OS Name: Windows Server 2008 R2
"""

# ── gobuster output ───────────────────────────────────────────────────────────

GOBUSTER_OUTPUT = """\
/admin (Status: 301)
/index.php (Status: 200)
/login (Status: 200)
/backup (Status: 403)
/.git (Status: 301)
"""

# ── hashdump output ───────────────────────────────────────────────────────────

HASHDUMP_OUTPUT = """\
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
sysadmin:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
"""

# ── hydra output ──────────────────────────────────────────────────────────────

HYDRA_OUTPUT = """\
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak
[22][ssh] host: 192.168.1.10   login: admin   password: password123
[22][ssh] host: 192.168.1.10   login: root    password: toor
"""

# ── CVE output ────────────────────────────────────────────────────────────────

CVE_OUTPUT = """\
| CVE-2011-2523: vsftpd 2.3.4 Backdoor Command Execution
| CVE-2017-0144: EternalBlue RCE
| CVE-2007-2447: Samba usermap_script Command Injection
"""


# ── port parsing ──────────────────────────────────────────────────────────────

class TestPortParser:
    def test_basic_port_extraction(self):
        ports = Parser.ports(NMAP_BASIC)
        assert len(ports) == 5

    def test_port_numbers(self):
        ports = Parser.ports(NMAP_BASIC)
        nums = {p["port"] for p in ports}
        assert {21, 22, 80, 139, 445} == nums

    def test_protocols(self):
        ports = Parser.ports(NMAP_BASIC)
        assert all(p["proto"] == "tcp" for p in ports)

    def test_service_names(self):
        ports = Parser.ports(NMAP_BASIC)
        services = {p["service"] for p in ports}
        assert "ftp" in services
        assert "ssh" in services
        assert "http" in services

    def test_version_extraction(self):
        ports = Parser.ports(NMAP_BASIC)
        ftp = next(p for p in ports if p["port"] == 21)
        assert "vsftpd" in ftp["version"].lower()

    def test_no_duplicates(self):
        doubled = NMAP_BASIC + NMAP_BASIC
        ports = Parser.ports(doubled)
        seen = set()
        for p in ports:
            key = (p["port"], p["proto"])
            assert key not in seen
            seen.add(key)

    def test_empty_input(self):
        assert Parser.ports("") == []

    def test_no_open_ports(self):
        assert Parser.ports("All 1000 ports on 1.2.3.4 are filtered") == []


# ── directory parsing ─────────────────────────────────────────────────────────

class TestDirParser:
    def test_extracts_paths(self):
        dirs = Parser.dirs(GOBUSTER_OUTPUT)
        paths = {d["path"] for d in dirs}
        assert "/admin" in paths
        assert "/login" in paths

    def test_extracts_status_codes(self):
        dirs = Parser.dirs(GOBUSTER_OUTPUT)
        admin = next(d for d in dirs if d["path"] == "/admin")
        assert admin["status"] == 301

    def test_ignores_root(self):
        dirs = Parser.dirs("/ (Status: 200)\n/admin (Status: 200)")
        paths = {d["path"] for d in dirs}
        assert "/" not in paths

    def test_empty_input(self):
        assert Parser.dirs("") == []


# ── CVE parsing ───────────────────────────────────────────────────────────────

class TestCVEParser:
    def test_extracts_cves(self):
        cves = Parser.cves(CVE_OUTPUT)
        assert "CVE-2017-0144" in cves
        assert "CVE-2007-2447" in cves

    def test_deduplicates(self):
        doubled = CVE_OUTPUT + CVE_OUTPUT
        cves = Parser.cves(doubled)
        assert len(cves) == len(set(cves))

    def test_case_insensitive(self):
        cves = Parser.cves("cve-2017-0144 found")
        assert "CVE-2017-0144" in cves

    def test_empty_input(self):
        assert Parser.cves("") == []


# ── MS17 / anon FTP detection ─────────────────────────────────────────────────

class TestBooleanDetectors:
    def test_is_ms17_positive(self):
        assert Parser.is_ms17(NMAP_VULN) is True

    def test_is_ms17_negative(self):
        assert Parser.is_ms17("nothing here") is False

    def test_has_anon_ftp_positive(self):
        assert Parser.has_anon_ftp(NMAP_FTP_ANON) is True

    def test_has_anon_ftp_negative(self):
        assert Parser.has_anon_ftp("ftp login required") is False


# ── hash parsing ──────────────────────────────────────────────────────────────

class TestHashParser:
    def test_extracts_hashes(self):
        hashes = Parser.hashes(HASHDUMP_OUTPUT)
        # Administrator and Guest share the same blank NTLM → deduped to 2
        assert len(hashes) == 2

    def test_username_extraction(self):
        hashes = Parser.hashes(HASHDUMP_OUTPUT)
        names = {h["username"] for h in hashes}
        assert "sysadmin" in names

    def test_ntlm_hash_format(self):
        hashes = Parser.hashes(HASHDUMP_OUTPUT)
        for h in hashes:
            assert len(h["ntlm"]) == 32
            assert h["ntlm"] == h["ntlm"].lower()

    def test_crackable_flag(self):
        hashes = Parser.hashes(HASHDUMP_OUTPUT)
        sysadmin = next(h for h in hashes if h["username"] == "sysadmin")
        assert sysadmin["crackable"] is False  # lm is blank hash

    def test_empty_input(self):
        assert Parser.hashes("") == []


# ── hydra credential parsing ──────────────────────────────────────────────────

class TestHydraCredParser:
    def test_extracts_creds(self):
        creds = Parser.hydra_creds(HYDRA_OUTPUT)
        assert len(creds) == 2

    def test_username_password(self):
        creds = Parser.hydra_creds(HYDRA_OUTPUT)
        usernames = {c["username"] for c in creds}
        assert "admin" in usernames
        assert "root" in usernames

    def test_password_values(self):
        creds = Parser.hydra_creds(HYDRA_OUTPUT)
        admin = next(c for c in creds if c["username"] == "admin")
        assert admin["password"] == "password123"

    def test_empty_input(self):
        assert Parser.hydra_creds("") == []


# ── OS info parsing ───────────────────────────────────────────────────────────

class TestOSParser:
    def test_extracts_os(self):
        os = Parser.os_info(NMAP_OS)
        assert os is not None
        assert "Windows" in os

    def test_returns_none_on_miss(self):
        assert Parser.os_info("no os info here") is None


# ── validation ────────────────────────────────────────────────────────────────

class TestValidate:
    def test_empty_output_warning(self):
        warns = Parser.validate("nmap_scan", "", 5.0)
        assert any("empty" in w for w in warns)

    def test_error_pattern_warning(self):
        warns = Parser.validate("nmap_scan", "error: connection refused", 5.0)
        assert any("error" in w for w in warns)

    def test_fast_gobuster_warning(self):
        warns = Parser.validate("gobuster_scan", "some output", 0.5)
        assert any("completed in" in w for w in warns)

    def test_clean_output_no_warnings(self):
        warns = Parser.validate("nmap_scan", "PORT STATE SERVICE\n22/tcp open ssh", 10.0)
        assert warns == []
