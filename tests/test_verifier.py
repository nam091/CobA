"""Unit tests for the Verifier JSON verdict parser."""

from __future__ import annotations

from coba.agent.verifier import VerifyResult, _parse_verdict
from coba.utils.schemas import Verdict


def test_parses_valid_verdict() -> None:
    r = _parse_verdict(
        '{"verdict":"TRUE_POSITIVE","confidence":0.83,"rationale":"User input reaches eval()."}'
    )
    assert isinstance(r, VerifyResult)
    assert r.verdict == Verdict.TRUE_POSITIVE
    assert abs(r.confidence - 0.83) < 1e-9
    assert "eval" in r.rationale


def test_parses_false_positive_default_confidence_zero() -> None:
    r = _parse_verdict(
        '{"verdict":"FALSE_POSITIVE","rationale":"sanitized via parameterized query"}'
    )
    assert r.verdict == Verdict.FALSE_POSITIVE
    assert r.confidence == 0.0


def test_handles_code_fence() -> None:
    text = '```json\n{"verdict":"TRUE_POSITIVE","confidence":0.9,"rationale":"r"}\n```'
    r = _parse_verdict(text)
    assert r.verdict == Verdict.TRUE_POSITIVE
    assert r.confidence == 0.9


def test_clamps_confidence() -> None:
    r = _parse_verdict('{"verdict":"TRUE_POSITIVE","confidence":2.5,"rationale":""}')
    assert r.confidence == 1.0
    r = _parse_verdict('{"verdict":"TRUE_POSITIVE","confidence":-1,"rationale":""}')
    assert r.confidence == 0.0


def test_unknown_verdict_defaults_to_false_positive() -> None:
    r = _parse_verdict('{"verdict":"MAYBE","rationale":"unsure"}')
    assert r.verdict == Verdict.FALSE_POSITIVE


def test_bad_json_returns_unverified() -> None:
    r = _parse_verdict("not json at all")
    assert r.verdict == Verdict.UNVERIFIED
    assert "bad-json" in r.rationale


def test_non_dict_json_returns_unverified() -> None:
    r = _parse_verdict('"just a string"')
    assert r.verdict == Verdict.UNVERIFIED
