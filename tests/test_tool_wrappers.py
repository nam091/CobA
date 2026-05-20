"""Unit tests for SAST tool wrappers (Semgrep / Bandit / Gitleaks / Joern).

These tests mock the subprocess invocation so they run anywhere — no
external binaries required.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from coba.agent.loop import _group_hints_by_file, _normalize_file_key
from coba.tools.bandit import BanditRunner
from coba.tools.gitleaks import GitleaksRunner
from coba.tools.semgrep import SemgrepRunner
from coba.utils.schemas import Severity, StaticHint

# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------
SEMGREP_SAMPLE_JSON: dict[str, Any] = {
    "results": [
        {
            "check_id": "python.lang.security.audit.dangerous-system-call.dangerous-system-call",
            "path": "examples/vulnerable_python.py",
            "start": {"line": 12, "col": 5},
            "end": {"line": 12, "col": 40},
            "extra": {
                "message": "Detected use of subprocess with shell=True",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
            },
        },
        {
            "check_id": "javascript.express.security.audit.xss.direct-response",
            "path": "examples/vulnerable_js/xss_express.js",
            "start": {"line": 7, "col": 1},
            "end": {"line": 7, "col": 50},
            "extra": {
                "message": "User input written to response without escaping",
                "severity": "WARNING",
                "metadata": {"cwe-id": "CWE-79"},
            },
        },
        # Row without path — must be skipped, not crash.
        {"check_id": "missing.path.rule", "extra": {}},
    ]
}


def test_semgrep_parses_results() -> None:
    hints = [SemgrepRunner._to_hint(r) for r in SEMGREP_SAMPLE_JSON["results"] if "path" in r]
    assert len(hints) == 2
    h1, h2 = hints
    assert h1.tool == "semgrep"
    assert h1.cwe == "CWE-78"
    assert h1.line == 12
    assert h1.file == "examples/vulnerable_python.py"
    assert h1.severity in (Severity.MEDIUM, Severity.HIGH, Severity.LOW, Severity.CRITICAL)
    assert h2.cwe == "CWE-79"
    assert h2.file.endswith("xss_express.js")


def test_semgrep_filters_results_without_path() -> None:
    # Mimic what run() does: filter by "path" presence.
    filtered = [r for r in SEMGREP_SAMPLE_JSON["results"] if "path" in r]
    assert len(filtered) == 2


# ---------------------------------------------------------------------------
# Bandit
# ---------------------------------------------------------------------------
BANDIT_SAMPLE_JSON: dict[str, Any] = {
    "results": [
        {
            "test_id": "B602",
            "filename": "/tmp/x/vuln.py",
            "line_number": 14,
            "issue_text": "subprocess call with shell=True identified",
            "issue_severity": "HIGH",
            "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/..."},
        },
        {
            "test_id": "B105",
            "filename": "/tmp/x/secrets.py",
            "line_number": 3,
            "issue_text": "Possible hardcoded password",
            "issue_severity": "LOW",
            "issue_cwe": {"id": 259},
        },
    ]
}


def test_bandit_parses_results() -> None:
    hints = [BanditRunner._to_hint(r) for r in BANDIT_SAMPLE_JSON["results"]]
    assert hints[0].tool == "bandit"
    assert hints[0].rule_id == "B602"
    assert hints[0].cwe == "CWE-78"
    assert hints[0].line == 14
    assert hints[0].file == "/tmp/x/vuln.py"
    assert hints[0].severity == Severity.HIGH
    assert hints[1].cwe == "CWE-259"
    assert hints[1].severity == Severity.LOW


# ---------------------------------------------------------------------------
# Gitleaks
# ---------------------------------------------------------------------------
GITLEAKS_SAMPLE_JSON: list[dict[str, Any]] = [
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "File": "/tmp/repo/config.py",
        "StartLine": 11,
    },
    {
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": "/tmp/repo/secrets.json",
        "StartLine": 4,
    },
]


def test_gitleaks_parses_results() -> None:
    hints = [GitleaksRunner._to_hint(r) for r in GITLEAKS_SAMPLE_JSON]
    assert len(hints) == 2
    assert all(h.tool == "gitleaks" for h in hints)
    assert hints[0].cwe == "CWE-798"
    assert hints[0].file == "/tmp/repo/config.py"
    assert hints[0].severity == Severity.HIGH
    assert "Hard-coded secret" in hints[0].message


# ---------------------------------------------------------------------------
# Hint grouping helpers (used by Orchestrator)
# ---------------------------------------------------------------------------
def test_group_hints_by_file(tmp_path: Path) -> None:
    # Create two real files so resolve() doesn't drop them
    f1 = tmp_path / "a.py"
    f1.write_text("# a")
    f2 = tmp_path / "sub" / "b.py"
    f2.parent.mkdir()
    f2.write_text("# b")

    hints = [
        StaticHint(tool="t", rule_id="r1", file=str(f1), line=10, message="m1"),
        StaticHint(tool="t", rule_id="r2", file=str(f2), line=20, message="m2"),
        # Relative path: should resolve against the target root.
        StaticHint(tool="t", rule_id="r3", file="sub/b.py", line=25, message="m3"),
        # No file → _global bucket
        StaticHint(tool="t", rule_id="r4", file=None, line=99, message="m4"),
    ]
    grouped = _group_hints_by_file(hints, tmp_path)
    assert len(grouped["_global"]) == 1
    assert str(f1.resolve()) in grouped
    assert str(f2.resolve()) in grouped
    # r2 and r3 should be in the same bucket (both resolve to f2).
    assert len(grouped[str(f2.resolve())]) == 2


def test_normalize_file_key(tmp_path: Path) -> None:
    p = tmp_path / "x.py"
    p.write_text("# x")
    assert _normalize_file_key(str(p)) == str(p.resolve())
    # Non-existent paths still resolve (resolve() is best-effort).
    assert _normalize_file_key("/clearly/nonexistent/xx.py").endswith("xx.py")


# ---------------------------------------------------------------------------
# Subprocess mocking — verify that run() builds the right command-line
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_semgrep_run_invokes_subprocess(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = SemgrepRunner(configs=["p/security-audit"])
    monkeypatch.setattr(runner, "installed", lambda: True)
    captured: dict[str, Any] = {}

    async def fake_run(cmd: list[str], *, timeout: float = 0, cwd: Path | None = None):  # type: ignore[no-untyped-def]
        captured["cmd"] = cmd
        return 0, json.dumps(SEMGREP_SAMPLE_JSON).encode(), b""

    monkeypatch.setattr(runner, "_run_subprocess", fake_run)
    hints = await runner.run(tmp_path)
    assert "--json" in captured["cmd"]
    assert "--config" in captured["cmd"]
    assert len(hints) == 2
    assert all(isinstance(h, StaticHint) for h in hints)


@pytest.mark.asyncio
async def test_bandit_run_invokes_subprocess(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = BanditRunner()
    monkeypatch.setattr(runner, "installed", lambda: True)
    captured: dict[str, Any] = {}

    async def fake_run(cmd: list[str], *, timeout: float = 0, cwd: Path | None = None):  # type: ignore[no-untyped-def]
        captured["cmd"] = cmd
        return 1, json.dumps(BANDIT_SAMPLE_JSON).encode(), b""

    monkeypatch.setattr(runner, "_run_subprocess", fake_run)
    hints = await runner.run(tmp_path)
    assert "-f" in captured["cmd"]
    assert "json" in captured["cmd"]
    assert "-r" in captured["cmd"]
    assert len(hints) == 2


@pytest.mark.asyncio
async def test_gitleaks_run_invokes_subprocess(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = GitleaksRunner()
    monkeypatch.setattr(runner, "installed", lambda: True)
    captured: dict[str, Any] = {}

    async def fake_run(cmd: list[str], *, timeout: float = 0, cwd: Path | None = None):  # type: ignore[no-untyped-def]
        captured["cmd"] = cmd
        # Gitleaks writes to the --report-path arg; locate it and write the JSON
        report_arg = captured["cmd"][captured["cmd"].index("--report-path") + 1]
        Path(report_arg).write_text(json.dumps(GITLEAKS_SAMPLE_JSON))
        return 0, b"", b""

    monkeypatch.setattr(runner, "_run_subprocess", fake_run)
    hints = await runner.run(tmp_path)
    assert "detect" in captured["cmd"]
    assert "--report-format" in captured["cmd"]
    assert len(hints) == 2
    assert hints[0].cwe == "CWE-798"
