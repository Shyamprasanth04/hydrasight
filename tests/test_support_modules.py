"""Tests for supporting modules: profiles, confidence enum, timeline,
remediation recommendations, exploit-db mapping, json reporter, and KaliAPI.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import requests

from hydrasight.core.profiles import PROFILES, ScanProfile
from hydrasight.integrations.exploit_db import ExploitDB
from hydrasight.integrations.kali_api import KaliAPI
from hydrasight.models.finding_confidence import FindingConfidence
from hydrasight.models.timeline import TimelineEvent
from hydrasight.reporting.json_reporter import save_json
from hydrasight.reporting.remediation import build_recommendations

# ── profiles ──────────────────────────────────────────────────────────────────


def test_profiles_table_has_expected_keys():
    for key in ("quick", "default", "deep", "web", "smb"):
        assert key in PROFILES
        assert isinstance(PROFILES[key], ScanProfile)


def test_profile_timeout_multipliers_ordering():
    assert PROFILES["quick"].timeout_multiplier < PROFILES["default"].timeout_multiplier
    assert PROFILES["deep"].timeout_multiplier > PROFILES["default"].timeout_multiplier


def test_deep_profile_is_staged_and_all_ports():
    deep = PROFILES["deep"]
    assert deep.staged is True
    assert deep.port_mode == "all"
    assert deep.stage_two_service_detection is True


def test_web_profile_targets_web_ports():
    assert 80 in PROFILES["web"].ports
    assert 443 in PROFILES["web"].ports


# ── confidence enum ───────────────────────────────────────────────────────────


def test_confidence_levels_present():
    for level in ("CANDIDATE", "OBSERVED", "PLAUSIBLE", "VERIFIED", "EXPLOITED"):
        assert FindingConfidence(level).value == level


# ── timeline ──────────────────────────────────────────────────────────────────


def test_timeline_event_defaults():
    ev = TimelineEvent(command_id="cmd-1")
    assert ev.command_id == "cmd-1"
    assert ev.phase == "UNKNOWN"
    assert ev.bytes_received == 0
    assert ev.parser_summary == {}
    assert ev.tags == []
    assert ev.timestamp is not None


def test_timeline_event_custom_fields():
    ev = TimelineEvent(command_id="c2", phase="RECON", bytes_received=1234, tags=["nmap"])
    assert ev.phase == "RECON"
    assert ev.bytes_received == 1234
    assert ev.tags == ["nmap"]


# ── remediation ───────────────────────────────────────────────────────────────


def _findings():
    f = MagicMock()
    f.vulns = []
    f.hashes = []
    f.credentials = []
    f.dirs = []
    return f


def test_remediation_default_no_findings():
    f = _findings()
    recs = build_recommendations(f)
    assert recs
    assert recs[0][0] == "INFO"


def test_remediation_cracked_credentials_critical():
    f = _findings()
    f.credentials = [{"username": "u", "secret": "p", "kind": "cracked"}]
    recs = build_recommendations(f)
    severities = {sev for sev, _ in recs}
    assert "CRITICAL" in severities


def test_remediation_bruteforce_credentials():
    f = _findings()
    f.credentials = [{"username": "u", "secret": "p", "kind": "bruteforce"}]
    recs = build_recommendations(f)
    assert any(sev == "HIGH" and "lockout" in text.lower() for sev, text in recs)


def test_remediation_hashes_triggers_rotation():
    f = _findings()
    f.hashes = [{"username": "u", "ntlm": "x"}]
    recs = build_recommendations(f)
    assert any("rotate" in text.lower() for _, text in recs)


def test_remediation_sensitive_paths():
    f = _findings()
    f.dirs = [{"path": "/.git", "status": 200}, {"path": "/admin", "status": 200}]
    recs = build_recommendations(f)
    assert any("sensitive web paths" in text.lower() for _, text in recs)


# ── exploit db mapping ────────────────────────────────────────────────────────


def test_exploit_db_eternalblue_smb():
    f = MagicMock()
    f.ports = [{"port": 445, "service": "microsoft-ds", "version": ""}]
    f.vulns = [{"name": "MS17-010 EternalBlue SMB RCE"}]
    exploits = ExploitDB.for_target(f)
    assert exploits
    assert any("ms17_010_eternalblue" in e["module"] for e in exploits)
    assert any(e["cve"] == "CVE-2017-0144" for e in exploits)


def test_exploit_db_no_ports_no_exploits():
    f = MagicMock()
    f.ports = []
    f.vulns = []
    assert ExploitDB.for_target(f) == []


def _ed_findings(ports, vulns=None):
    f = MagicMock()
    f.ports = ports
    f.vulns = vulns or []
    return f


def test_exploit_db_samba_usermap():
    f = _ed_findings([{"port": 139, "service": "netbios-ssn", "version": "Samba 3.0.20"}])
    mods = [e["module"] for e in ExploitDB.for_target(f)]
    assert any("usermap_script" in m for m in mods)


def test_exploit_db_vsftpd_backdoor():
    f = _ed_findings([{"port": 21, "service": "ftp", "version": "vsftpd 2.3.4"}])
    mods = [e["cve"] for e in ExploitDB.for_target(f)]
    assert "CVE-2011-2523" in mods


def test_exploit_db_proftpd_modcopy():
    f = _ed_findings([{"port": 21, "service": "ftp", "version": "ProFTPd 1.3.5"}])
    assert any(e["cve"] == "CVE-2015-3306" for e in ExploitDB.for_target(f))


def test_exploit_db_libssh_bypass():
    f = _ed_findings([{"port": 22, "service": "ssh", "version": "libssh 0.8.0"}])
    assert any("libssh_auth_bypass" in e["module"] for e in ExploitDB.for_target(f))


def test_exploit_db_tomcat_and_drupal():
    f = _ed_findings(
        [
            {"port": 8080, "service": "http", "version": "Apache Tomcat 9"},
            {"port": 80, "service": "http", "version": "Drupal 7"},
        ]
    )
    mods = [e["module"] for e in ExploitDB.for_target(f)]
    assert any("tomcat_mgr_login" in m for m in mods)
    assert any("drupalgeddon2" in m for m in mods)


def test_exploit_db_misc_services():
    f = _ed_findings(
        [
            {"port": 3632, "service": "distcc", "version": ""},
            {"port": 6667, "service": "irc", "version": "UnrealIRCd"},
            {"port": 1099, "service": "rmiregistry", "version": ""},
        ]
    )
    mods = [e["module"] for e in ExploitDB.for_target(f)]
    assert any("distcc_exec" in m for m in mods)
    assert any("unreal_ircd" in m for m in mods)
    assert any("java_rmi_server" in m for m in mods)


def test_exploit_db_phpmyadmin():
    f = _ed_findings([{"port": 80, "service": "http", "version": "phpMyAdmin 4.5"}])
    assert any("phpmyadmin" in e["module"] for e in ExploitDB.for_target(f))


# ── json reporter ─────────────────────────────────────────────────────────────


def test_save_json_success(tmp_path):
    # Use a real Findings object so to_dict/ReportModel work end-to-end.
    from hydrasight.models.findings import Findings

    findings = Findings()
    findings.target = "10.0.0.1"
    findings.add_port(445, "tcp", "microsoft-ds")
    out = tmp_path / "report.json"
    assert save_json(findings, str(out)) is True
    assert out.exists()


def test_save_json_failure_bad_path(tmp_path):
    from hydrasight.models.findings import Findings

    findings = Findings()
    # Embedded NUL byte raises ValueError on open() — must be caught.
    bad = str(tmp_path / "bad\x00name.json")
    assert save_json(findings, bad) is False


# ── KaliAPI ───────────────────────────────────────────────────────────────────


def _api():
    return KaliAPI("http://127.0.0.1:5000", logging.getLogger("t"))


def _resp(status_code=200, payload=None, text=""):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = payload if payload is not None else {}
    r.text = text
    r.raise_for_status.return_value = None
    return r


def test_kali_health_ready():
    api = _api()
    with patch.object(api.sess, "get", return_value=_resp(200)):
        ok, msg = api.health()
    assert ok is True
    assert msg == "ready"


def test_kali_health_http_error():
    api = _api()
    with patch.object(api.sess, "get", return_value=_resp(503)):
        ok, msg = api.health()
    assert ok is False
    assert "HTTP 503" in msg


def test_kali_health_connection_refused():
    api = _api()
    with patch.object(api.sess, "get", side_effect=requests.ConnectionError("refused")):
        ok, msg = api.health()
    assert ok is False
    assert "connection refused" in msg.lower()


def test_kali_health_timeout():
    api = _api()
    with patch.object(api.sess, "get", side_effect=requests.Timeout("slow")):
        ok, msg = api.health()
    assert ok is False
    assert "timeout" in msg.lower()


def test_kali_run_success():
    api = _api()
    payload = {"stdout": "nmap output", "stderr": "", "return_code": 0, "success": True}
    with patch.object(api.sess, "post", return_value=_resp(200, payload)):
        res = api.run("nmap -sV 10.0.0.1", timeout=10)
    assert res["success"] is True
    assert "nmap output" in res["output"]


def test_kali_run_stderr_included():
    api = _api()
    payload = {"stdout": "out", "stderr": "warning text", "return_code": 0}
    with patch.object(api.sess, "post", return_value=_resp(200, payload)):
        res = api.run("cmd")
    assert "warning text" in res["output"]


def test_kali_run_timeout():
    api = _api()
    with patch.object(api.sess, "post", side_effect=requests.Timeout("t")):
        res = api.run("slow cmd")
    assert res["success"] is False
    assert res["timed_out"] is True


def test_kali_run_connection_error():
    api = _api()
    with patch.object(api.sess, "post", side_effect=requests.ConnectionError("down")):
        res = api.run("cmd")
    assert res["success"] is False
    assert "not reachable" in res["error"]


def test_kali_run_bad_json():
    api = _api()
    resp = _resp(200)
    resp.json.side_effect = ValueError("No JSON")
    with patch.object(api.sess, "post", return_value=resp):
        res = api.run("cmd")
    assert res["success"] is False
    assert "invalid JSON" in res["error"]


def test_local_ip_parses_address():
    api = _api()
    with patch.object(
        api,
        "run",
        return_value={"output": "192.168.1.50 \n", "success": True},
    ):
        assert api.local_ip("10.0.0.1") == "192.168.1.50"


def test_local_ip_fallback_on_garbage():
    api = _api()
    with patch.object(api, "run", return_value={"output": "no route", "success": False}):
        assert api.local_ip("10.0.0.1") == "127.0.0.1"


def test_check_target_reachable():
    api = _api()
    out = "2 packets transmitted, 2 received, 0% packet loss"
    with patch.object(api, "run", return_value={"output": out}):
        assert api.check_target("10.0.0.1")["reachable"] is True


def test_check_target_100_percent_loss_not_reachable():
    api = _api()
    out = "2 packets transmitted, 0 received, +2 errors, 100% packet loss"
    with patch.object(api, "run", return_value={"output": out}):
        result = api.check_target("10.0.0.99")
    assert result["reachable"] is False
