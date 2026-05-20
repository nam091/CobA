"""Unit tests for FewShotIndex + Detector few-shot prompt rendering."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from coba.agent.rag import FewShotExample, FewShotIndex, _load_fewshot_bank

PROMPTS_DIR = Path(__file__).resolve().parents[1] / "src" / "coba" / "prompts"


@pytest.fixture(autouse=True)
def _clear_fewshot_cache() -> None:
    _load_fewshot_bank.cache_clear()
    yield
    _load_fewshot_bank.cache_clear()


def _write_bank(path: Path, examples: list[dict]) -> None:
    path.write_text(json.dumps({"examples": examples}), encoding="utf-8")


def test_fewshot_returns_empty_for_unknown_cwe(tmp_path: Path) -> None:
    bank = tmp_path / "bank.json"
    _write_bank(bank, [{"cwe": "CWE-89", "language": "python", "vuln": "a", "safe": "b"}])
    idx = FewShotIndex(bank)
    assert idx.examples_for("CWE-9999") == []
    assert idx.examples_for("") == []


def test_fewshot_prefers_same_language(tmp_path: Path) -> None:
    bank = tmp_path / "bank.json"
    _write_bank(
        bank,
        [
            {"cwe": "CWE-89", "language": "java", "vuln": "j1", "safe": "j1s"},
            {"cwe": "CWE-89", "language": "python", "vuln": "p1", "safe": "p1s"},
            {"cwe": "CWE-89", "language": "javascript", "vuln": "js1", "safe": "js1s"},
        ],
    )
    idx = FewShotIndex(bank)
    out = idx.examples_for("CWE-89", language="python", top_k=2)
    assert [e.language for e in out] == ["python", "java"]


def test_fewshot_case_insensitive_cwe(tmp_path: Path) -> None:
    bank = tmp_path / "bank.json"
    _write_bank(bank, [{"cwe": "cwe-89", "language": "python", "vuln": "v", "safe": "s"}])
    idx = FewShotIndex(bank)
    assert len(idx.examples_for("CWE-89")) == 1


def test_fewshot_skips_malformed_rows(tmp_path: Path) -> None:
    bank = tmp_path / "bank.json"
    bank.write_text(
        json.dumps(
            {
                "examples": [
                    {"cwe": "CWE-89", "language": "python", "vuln": "v", "safe": "s"},
                    {"missing": "cwe"},  # row without 'cwe' is skipped
                    None,  # not a dict -> skipped
                ]
            }
        ),
        encoding="utf-8",
    )
    idx = FewShotIndex(bank)
    assert idx.n_examples == 1


def test_fewshot_missing_file_safe(tmp_path: Path) -> None:
    idx = FewShotIndex(tmp_path / "does_not_exist.json")
    assert idx.n_examples == 0
    assert idx.examples_for("CWE-89") == []


def test_fewshot_top_k_zero_returns_empty(tmp_path: Path) -> None:
    bank = tmp_path / "bank.json"
    _write_bank(bank, [{"cwe": "CWE-89", "language": "python", "vuln": "v", "safe": "s"}])
    idx = FewShotIndex(bank)
    assert idx.examples_for("CWE-89", top_k=0) == []


def test_default_fewshot_bank_loads_top_cwes() -> None:
    """The shipped bank must cover the headline CWEs used by docs/examples."""
    idx = FewShotIndex()
    covered = set(idx.covered_cwes())
    for cwe in ("CWE-89", "CWE-78", "CWE-22", "CWE-94", "CWE-787"):
        assert cwe in covered


def test_detector_prompt_renders_fewshot_section() -> None:
    """Detector Jinja template must surface vuln/safe examples block."""
    from coba.utils.schemas import Chunk, Language

    chunk = Chunk(
        file="demo.py",
        language=Language.PYTHON,
        function="login",
        line_start=1,
        line_end=4,
        body="password == STORED",
    )
    ex = FewShotExample(
        cwe="CWE-287",
        language="python",
        vuln="if p == STORED:",
        safe="hmac.compare_digest(p, STORED)",
        explanation="constant-time compare",
    )
    env = Environment(
        loader=FileSystemLoader(str(PROMPTS_DIR)),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
        keep_trailing_newline=True,
    )
    out = env.get_template("detector.j2").render(
        chunk=chunk,
        body=chunk.body,
        static_hints=[],
        cwe_context=[],
        fewshot_examples=[ex],
    )
    assert "EXAMPLES" in out
    assert "VULN:" in out
    assert "SAFE:" in out
    assert "hmac.compare_digest" in out
    assert "WHY: constant-time compare" in out
