"""Tests for engagement-outcome classification (reporting/outcome.py)."""

from __future__ import annotations

from types import SimpleNamespace

from hydrasight.reporting.outcome import (
    CREDENTIAL_LED,
    EXPLOIT_CONFIRMED,
    NO_FINDINGS,
    OUTCOMES,
    POST_ACCESS,
    RECON_ONLY,
    VALIDATION,
    VULN_CANDIDATES,
    classify_outcome,
)


def _report(**kw):
    """Build a minimal ReportModel-like object defaulting to everything empty."""
    base = dict(
        sessions=[],
        credentials=[],
        exploited_findings=[],
        verified_findings=[],
        supported_candidates=[],
        no_strategy_candidates=[],
        attempted_not_confirmed_findings=[],
        ports=[],
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_outcome_table_has_all_keys():
    for key in (
        "POST_ACCESS",
        "CREDENTIAL_LED",
        "EXPLOIT_CONFIRMED",
        "VALIDATION",
        "VULN_CANDIDATES",
        "RECON_ONLY",
        "NO_FINDINGS",
    ):
        assert key in OUTCOMES


def test_no_findings():
    assert classify_outcome(_report()) == NO_FINDINGS


def test_recon_only_when_ports():
    assert classify_outcome(_report(ports=[{"port": 445}])) == RECON_ONLY


def test_vuln_candidates_supported():
    r = _report(ports=[{"port": 80}], supported_candidates=[{"name": "x"}])
    assert classify_outcome(r) == VULN_CANDIDATES


def test_vuln_candidates_no_strategy():
    r = _report(ports=[{"port": 80}], no_strategy_candidates=[{"name": "x"}])
    assert classify_outcome(r) == VULN_CANDIDATES


def test_vuln_candidates_attempted():
    r = _report(ports=[{"port": 80}], attempted_not_confirmed_findings=[{"name": "x"}])
    assert classify_outcome(r) == VULN_CANDIDATES


def test_validation_beats_candidates():
    r = _report(
        ports=[{"port": 80}],
        supported_candidates=[{"name": "x"}],
        verified_findings=[{"name": "v"}],
    )
    assert classify_outcome(r) == VALIDATION


def test_exploit_beats_validation():
    r = _report(
        ports=[{"port": 80}],
        verified_findings=[{"name": "v"}],
        exploited_findings=[{"name": "e"}],
    )
    assert classify_outcome(r) == EXPLOIT_CONFIRMED


def test_credential_led_beats_exploit_when_no_session():
    r = _report(
        credentials=[{"username": "u", "secret": "p"}],
        exploited_findings=[{"name": "e"}],
    )
    assert classify_outcome(r) == CREDENTIAL_LED


def test_post_access_is_highest_priority():
    r = _report(
        sessions=[{"id": 1}],
        credentials=[{"username": "u"}],
        exploited_findings=[{"name": "e"}],
        verified_findings=[{"name": "v"}],
    )
    assert classify_outcome(r) == POST_ACCESS


def test_outcome_labels_are_distinct():
    labels = {o.label for o in OUTCOMES.values()}
    assert len(labels) == len(OUTCOMES)
