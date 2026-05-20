"""Unit tests for :mod:`coba.agent.callgraph`."""

from __future__ import annotations

import json
from pathlib import Path

from coba.agent.callgraph import CallGraph


def test_from_records_basic() -> None:
    cg = CallGraph.from_records(
        [
            {
                "file": "/repo/src/a.py",
                "function": "alpha",
                "line": 10,
                "callees": ["beta", "gamma"],
                "callers": [],
            },
            {
                "file": "/repo/src/a.py",
                "function": "beta",
                "line": 30,
                "callees": ["gamma"],
                "callers": ["alpha"],
            },
        ]
    )
    assert cg.n_functions == 2
    assert cg.callees("/repo/src/a.py", "alpha") == ["beta", "gamma"]
    assert cg.callers("/repo/src/a.py", "beta") == ["alpha"]
    assert cg.callees("/repo/src/a.py", "missing") == []


def test_from_records_path_and_name_normalization() -> None:
    cg = CallGraph.from_records(
        [
            {
                "file": "./Src/A.py",
                "function": "pkg.module.foo(int)",
                "callees": ["pkg.module.bar()"],
                "callers": [],
            }
        ]
    )
    # Path lowercased + ./ stripped; function shortened to last segment.
    assert cg.callees("src/a.py", "foo") == ["bar"]
    assert cg.functions_in("SRC/a.py") == ["foo"]


def test_from_records_merges_overloads() -> None:
    cg = CallGraph.from_records(
        [
            {"file": "a.py", "function": "f", "callees": ["x"], "callers": []},
            {"file": "a.py", "function": "f", "callees": ["y", "x"], "callers": ["g"]},
        ]
    )
    # 'x' appears in both but is only listed once; 'y' is appended.
    assert cg.callees("a.py", "f") == ["x", "y"]
    assert cg.callers("a.py", "f") == ["g"]


def test_from_json_handles_bad_input() -> None:
    assert CallGraph.from_json(b"").n_functions == 0
    assert CallGraph.from_json("not json").n_functions == 0
    assert CallGraph.from_json('{"not": "a list"}').n_functions == 0


def test_from_json_roundtrip(tmp_path: Path) -> None:
    src = [
        {
            "file": "main.py",
            "function": "main",
            "line": 1,
            "callees": ["helper"],
            "callers": [],
        }
    ]
    cg = CallGraph.from_json(json.dumps(src))
    assert cg.callees("main.py", "main") == ["helper"]
    out = tmp_path / "cg.json"
    cg.write_json(out)
    cg2 = CallGraph.from_json(out.read_text(encoding="utf-8"))
    assert cg2.callees("main.py", "main") == ["helper"]
