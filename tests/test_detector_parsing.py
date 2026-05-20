"""Unit tests for Detector JSON parsing (no LLM call)."""

from coba.agent.detector import _parse_findings


def test_parse_clean_json() -> None:
    text = (
        '{"findings": [{"cwe":"CWE-89","severity":"high","confidence":0.9,'
        '"line_start":10,"line_end":12,"title":"SQLi","description":"oops"}]}'
    )
    out = _parse_findings(text)
    assert len(out) == 1
    assert out[0].cwe == "CWE-89"


def test_parse_fenced_json() -> None:
    text = (
        "```json\n"
        '{"findings": [{"cwe":"89","severity":"high","confidence":0.5,'
        '"line_start":1,"line_end":2,"title":"x","description":"y"}]}\n'
        "```"
    )
    out = _parse_findings(text)
    assert len(out) == 1
    assert out[0].cwe == "CWE-89"


def test_parse_invalid_json_returns_empty() -> None:
    assert _parse_findings("not json at all") == []


def test_parse_empty_findings() -> None:
    assert _parse_findings('{"findings": []}') == []
