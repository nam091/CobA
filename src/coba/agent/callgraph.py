"""In-memory call graph extracted from a Joern CPG.

Used by :mod:`coba.agent.chunker` to enrich function-level :class:`Chunk`
instances with ``callers`` / ``callees`` lists. The graph format is JSON,
emitted by ``src/coba/tools/joern_queries/call_graph.sc``.

Module is deliberately *side-effect free*: it can be loaded and tested
even on machines without Joern installed. Production callers build the
graph via :meth:`coba.tools.joern.JoernRunner.extract_call_graph`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import TypedDict

from coba.utils.logging import get_logger

log = get_logger("coba.agent.callgraph")


class _Edge(TypedDict):
    file: str
    function: str
    line: int
    callees: list[str]
    callers: list[str]


def _norm_path(p: str) -> str:
    p = p.replace("\\", "/").lstrip("./")
    return p.lower()


def _norm_fn(name: str) -> str:
    name = name.strip()
    # Strip Joern's <init> / <clinit> braces and parameter info — they
    # would otherwise prevent matching against tree-sitter function names.
    name = re.sub(r"<[^>]+>", "", name)
    name = name.split("(", 1)[0]
    name = name.split("$", 1)[0]
    # Take the last segment of a dotted qualified name (a.b.foo → foo).
    if "." in name:
        name = name.rsplit(".", 1)[-1]
    return name


class CallGraph:
    """Lookup callers / callees for a (file, function) pair.

    Keys are ``(_norm_path(file), _norm_fn(function))``. Multiple Joern
    methods sharing a name (overloads, generated wrappers) are merged.
    """

    def __init__(self) -> None:
        self._callees: dict[tuple[str, str], list[str]] = {}
        self._callers: dict[tuple[str, str], list[str]] = {}
        self._functions_by_file: dict[str, list[str]] = {}

    @classmethod
    def from_records(cls, records: Iterable[_Edge]) -> CallGraph:
        g = cls()
        for r in records:
            file = _norm_path(str(r.get("file") or ""))
            fn = _norm_fn(str(r.get("function") or ""))
            if not file or not fn:
                continue
            key = (file, fn)
            existing_callees = g._callees.setdefault(key, [])
            existing_callers = g._callers.setdefault(key, [])
            for c in r.get("callees", []) or []:
                normalized = _norm_fn(str(c))
                if normalized and normalized not in existing_callees:
                    existing_callees.append(normalized)
            for c in r.get("callers", []) or []:
                normalized = _norm_fn(str(c))
                if normalized and normalized not in existing_callers:
                    existing_callers.append(normalized)
            existing_fns = g._functions_by_file.setdefault(file, [])
            if fn not in existing_fns:
                existing_fns.append(fn)
        return g

    @classmethod
    def from_json(cls, data: str | bytes) -> CallGraph:
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="ignore")
        if not data.strip():
            return cls()
        try:
            records = json.loads(data)
        except json.JSONDecodeError as exc:
            log.warning("callgraph.bad_json", error=str(exc))
            return cls()
        if not isinstance(records, list):
            return cls()
        return cls.from_records(records)

    def callees(self, file: str, function: str | None) -> list[str]:
        if not function:
            return []
        return list(self._callees.get((_norm_path(file), _norm_fn(function)), []))

    def callers(self, file: str, function: str | None) -> list[str]:
        if not function:
            return []
        return list(self._callers.get((_norm_path(file), _norm_fn(function)), []))

    def functions_in(self, file: str) -> list[str]:
        return list(self._functions_by_file.get(_norm_path(file), []))

    @property
    def n_functions(self) -> int:
        return len(self._callees)

    def write_json(self, path: Path) -> None:
        out = []
        for key, callees in self._callees.items():
            file, fn = key
            out.append(
                {
                    "file": file,
                    "function": fn,
                    "callees": callees,
                    "callers": self._callers.get(key, []),
                }
            )
        path.write_text(json.dumps(out, indent=2), encoding="utf-8")


EMPTY_CALL_GRAPH = CallGraph()
