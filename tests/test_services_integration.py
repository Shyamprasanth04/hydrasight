"""Integration-style tests for verifier, session_manager and config loader."""

from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock

from hydrasight.models.finding_record import (
    FindingRecord,
    FindingSeverity,
    FindingStage,
)
from hydrasight.models.findings import Findings
from hydrasight.services.session_manager import SessionManager
from hydrasight.services.verifier import VerifierService

# ── verifier ──────────────────────────────────────────────────────────────────


def _finding(name="MS17-010 EternalBlue", severity=FindingSeverity.CRITICAL, port=445):
    return FindingRecord(
        name=name,
        severity=severity,
        stage=FindingStage.PLAUSIBLE,
        description="test finding",
        port=port,
        service="microsoft-ds",
    )


def _verifier(kali_output, success=True):
    kali = MagicMock()
    kali.run.return_value = {"output": kali_output, "success": success, "returncode": 0}
    return VerifierService(kali, logging.getLogger("t"), "10.0.0.1"), kali


def test_verifier_confirms_vulnerable_finding():
    svc, _k = _verifier("Host is VULNERABLE to MS17-010!")
    f = _finding()
    result = svc.verify_one(f)
    assert result.verified is True
    assert f.verification_attempted is True


def test_verifier_failed_when_no_success_pattern():
    # Output without the success pattern ("vulnerable") → not verified.
    svc, _k = _verifier("scan finished; service appears patched")
    f = _finding()
    result = svc.verify_one(f)
    assert result.verified is False


def test_verifier_no_strategy_for_unknown_finding():
    svc, _k = _verifier("anything")
    f = _finding(name="Some totally unknown weirdness")
    result = svc.verify_one(f)
    # No matching strategy → not verified (NO_STRATEGY / not attempted positive)
    assert result.verified is False


def test_verifier_error_when_no_target():
    kali = MagicMock()
    svc = VerifierService(kali, logging.getLogger("t"), "")
    f = _finding()
    result = svc.verify_one(f)
    assert result.verified is False


def test_verify_findings_severity_filter():
    svc, _k = _verifier("VULNERABLE")
    findings = Findings()
    findings.target = "10.0.0.1"
    findings.add_finding_record(_finding(severity=FindingSeverity.CRITICAL))
    findings.add_finding_record(
        _finding(name="low severity banner", severity=FindingSeverity.INFO, port=80)
    )
    results = svc.verify_findings(findings, only_high_and_above=True)
    # Only the CRITICAL finding is selected for verification.
    assert len(results) == 1


def test_verify_findings_includes_low_when_filter_off():
    svc, _k = _verifier("VULNERABLE")
    findings = Findings()
    findings.target = "10.0.0.1"
    findings.add_finding_record(_finding(severity=FindingSeverity.CRITICAL))
    findings.add_finding_record(
        _finding(name="another unknown thing here", severity=FindingSeverity.INFO, port=80)
    )
    results = svc.verify_findings(findings, only_high_and_above=False)
    assert len(results) == 2


def test_verifier_command_templating_inserts_target():
    svc, kali = _verifier("VULNERABLE to ms17-010")
    f = _finding()
    svc.verify_one(f, target="192.168.5.9")
    sent = kali.run.call_args[0][0]
    assert "192.168.5.9" in sent


# ── session manager ───────────────────────────────────────────────────────────


def _make_findings(target="10.0.0.1"):
    f = Findings()
    f.target = target
    f.add_port(445, "tcp", "microsoft-ds")
    f.add_vuln(name="MS17-010 EternalBlue", severity="CRITICAL", description="rce")
    return f


def test_session_save_list_load_roundtrip(tmp_path):
    sm = SessionManager(str(tmp_path))
    findings = _make_findings()
    sid = sm.save_session(findings, None, "completed")
    assert sid

    summaries = sm.list_sessions()
    assert any(s.session_id == sid for s in summaries)

    loaded = sm.load_session(sid)
    assert loaded is not None
    lf, _ps = loaded
    assert lf.target == "10.0.0.1"
    assert lf.ports[0]["port"] == 445


def test_session_load_missing_returns_none(tmp_path):
    sm = SessionManager(str(tmp_path))
    assert sm.load_session("does-not-exist") is None


def test_session_list_skips_corrupt_file(tmp_path):
    sm = SessionManager(str(tmp_path))
    sm.save_session(_make_findings(), None, "completed")
    # Drop a corrupt json file in the sessions dir.
    (tmp_path / "sessions" / "corrupt.json").write_text("{not valid json", encoding="utf-8")
    summaries = sm.list_sessions()
    # Corrupt file skipped; the good session still listed.
    assert len(summaries) == 1


def test_session_load_corrupt_returns_none(tmp_path):
    sm = SessionManager(str(tmp_path))
    sid = sm.save_session(_make_findings(), None, "completed")
    path = tmp_path / "sessions" / f"{sid}.json"
    path.write_text("{broken", encoding="utf-8")
    assert sm.load_session(sid) is None


# ── config loader ─────────────────────────────────────────────────────────────


def _run_loader(tmp_path, monkeypatch, config_text=None, env=None):
    # Isolate from the repo's real hydrasight.json / .env.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "hydrasight.config.loader.DEFAULT_CONFIG_PATH", tmp_path / "hydrasight.json"
    )
    monkeypatch.setattr("hydrasight.config.loader.DEFAULT_ENV_PATH", tmp_path / ".env")
    # Clear relevant env vars for determinism.
    for var in (
        "HYDRA_OLLAMA_URL",
        "HYDRA_KALI_URL",
        "HYDRA_MODEL",
        "HYDRA_VERBOSITY",
        "HYDRA_LPORT",
        "HYDRA_OUTPUT_DIR",
        "HYDRA_LOG_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    if config_text is not None:
        (tmp_path / "hydrasight.json").write_text(config_text, encoding="utf-8")
    if env:
        for k, v in env.items():
            monkeypatch.setenv(k, v)
    from hydrasight.config.loader import load_config

    return load_config(str(tmp_path / "hydrasight.json"))


def test_loader_defaults(tmp_path, monkeypatch):
    cfg = _run_loader(tmp_path, monkeypatch)
    assert cfg["model"]  # some default model
    assert cfg["execution_mode"] == "confirm"
    assert cfg["verbosity"] == 1


def test_loader_json_override(tmp_path, monkeypatch):
    cfg = _run_loader(tmp_path, monkeypatch, json.dumps({"verbosity": 3, "model": "custom:tag"}))
    assert cfg["verbosity"] == 3
    assert cfg["model"] == "custom:tag"


def test_loader_rejects_unknown_keys(tmp_path, monkeypatch):
    cfg = _run_loader(
        tmp_path, monkeypatch, json.dumps({"definitely_not_a_key": "x", "lport": 9999})
    )
    assert "definitely_not_a_key" not in cfg
    assert cfg["lport"] == 9999


def test_loader_env_override(tmp_path, monkeypatch):
    cfg = _run_loader(
        tmp_path,
        monkeypatch,
        env={"HYDRA_MODEL": "env-model:latest", "HYDRA_LPORT": "5555"},
    )
    assert cfg["model"] == "env-model:latest"
    assert cfg["lport"] == 5555


def test_loader_nested_dict_merge(tmp_path, monkeypatch):
    cfg = _run_loader(
        tmp_path,
        monkeypatch,
        json.dumps({"ollama_options_orchestrator": {"temperature": 0.9}}),
    )
    # Merged: override applied, default key preserved.
    assert cfg["ollama_options_orchestrator"]["temperature"] == 0.9
    assert "num_ctx" in cfg["ollama_options_orchestrator"]


def test_loader_invalid_json_falls_back_to_defaults(tmp_path, monkeypatch):
    cfg = _run_loader(tmp_path, monkeypatch, "{ this is not json")
    # Defaults still load despite the bad file.
    assert cfg["execution_mode"] == "confirm"
    assert cfg["lport"] == 4444
