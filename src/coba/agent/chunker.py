"""CPG-aware chunker (Tree-sitter based, language-aware).

Strategy:
- Try to parse the file with the language-specific Tree-sitter parser.
- Walk the AST and emit one Chunk per function (or class method).
- For files without functions (config, scripts), fall back to a sliding
  window of ``window_lines`` with overlap.

The chunker is best-effort: if Tree-sitter is not installed for a language,
we degrade gracefully to the window-based fallback.
"""

from __future__ import annotations

from pathlib import Path

from coba.agent.callgraph import CallGraph
from coba.utils.logging import get_logger
from coba.utils.schemas import Chunk, Language

log = get_logger("coba.agent.chunker")

# Tree-sitter node types that we treat as "function-like" per language.
_FUNCTION_NODE_TYPES: dict[Language, tuple[str, ...]] = {
    Language.PYTHON: ("function_definition",),
    Language.JAVA: ("method_declaration", "constructor_declaration"),
    Language.C: ("function_definition",),
    Language.CPP: ("function_definition",),
    Language.JAVASCRIPT: (
        "function_declaration",
        "method_definition",
        "arrow_function",
    ),
    Language.TYPESCRIPT: (
        "function_declaration",
        "method_definition",
        "arrow_function",
    ),
}

_IMPORT_NODE_TYPES: dict[Language, tuple[str, ...]] = {
    Language.PYTHON: ("import_statement", "import_from_statement"),
    Language.JAVA: ("import_declaration",),
    Language.C: ("preproc_include",),
    Language.CPP: ("preproc_include",),
    Language.JAVASCRIPT: ("import_statement",),
    Language.TYPESCRIPT: ("import_statement",),
}


def _try_get_parser(lang: Language):  # pragma: no cover
    """Return a tree-sitter parser for the given language, or None."""
    try:
        from tree_sitter_languages import get_parser

        ts_name = {
            Language.PYTHON: "python",
            Language.JAVA: "java",
            Language.C: "c",
            Language.CPP: "cpp",
            Language.JAVASCRIPT: "javascript",
            Language.TYPESCRIPT: "typescript",
        }.get(lang)
        if ts_name is None:
            return None
        return get_parser(ts_name)
    except Exception as exc:
        log.debug("chunker.parser_unavailable", lang=lang.value, error=str(exc))
        return None


def _walk(node):  # pragma: no cover - traversal helper
    yield node
    for child in node.children:
        yield from _walk(child)


def _function_name(node, src: bytes, lang: Language) -> str | None:
    # Look for an "identifier" or "name" child node.
    for child in node.children:
        if child.type in ("identifier", "name", "property_identifier"):
            return src[child.start_byte : child.end_byte].decode(errors="ignore")
    return None


def _extract_imports(root, src: bytes, lang: Language) -> list[str]:
    imports: list[str] = []
    types = _IMPORT_NODE_TYPES.get(lang, ())
    if not types:
        return imports
    for node in _walk(root):  # pragma: no cover
        if node.type in types:
            line = src[node.start_byte : node.end_byte].decode(errors="ignore").strip()
            if line and len(line) < 200:
                imports.append(line)
            if len(imports) >= 30:
                break
    return imports


def _window_chunks(
    file: Path, lang: Language, text: str, lines_per_chunk: int, overlap: int
) -> list[Chunk]:
    lines = text.splitlines()
    chunks: list[Chunk] = []
    i = 0
    while i < len(lines):
        end = min(i + lines_per_chunk, len(lines))
        body = "\n".join(lines[i:end])
        chunks.append(
            Chunk(
                file=str(file),
                language=lang,
                function=None,
                line_start=i + 1,
                line_end=end,
                body=body,
            )
        )
        if end >= len(lines):
            break
        i = end - overlap
    return chunks


def _enrich_with_callgraph(chunks: list[Chunk], cg: CallGraph | None) -> None:
    """Populate ``callers`` and ``callees`` in-place on function chunks."""
    if cg is None:
        return
    for ch in chunks:
        if ch.function is None:
            continue
        callees = cg.callees(ch.file, ch.function)
        callers = cg.callers(ch.file, ch.function)
        if callees:
            ch.callees = callees[:20]
        if callers:
            ch.callers = callers[:20]


def chunk_file(
    file: Path,
    *,
    max_chars: int = 8000,
    window_lines: int = 200,
    window_overlap: int = 30,
    call_graph: CallGraph | None = None,
) -> list[Chunk]:
    """Chunk a source file into LLM-friendly units.

    When ``call_graph`` is provided, each function-level :class:`Chunk`
    is enriched with ``callers`` / ``callees`` so the Detector LLM gets
    inter-procedural context. The window-based fallback chunks remain
    unenriched (no function identity to look up).
    """
    lang = Language.from_path(str(file))
    try:
        text = file.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        log.warning("chunker.read_failed", file=str(file), error=str(exc))
        return []

    parser = _try_get_parser(lang) if lang != Language.UNKNOWN else None
    if parser is None:
        return _window_chunks(file, lang, text, window_lines, window_overlap)

    src = text.encode("utf-8", errors="ignore")
    tree = parser.parse(src)
    fn_types = _FUNCTION_NODE_TYPES.get(lang, ())

    imports = _extract_imports(tree.root_node, src, lang)
    chunks: list[Chunk] = []
    for node in _walk(tree.root_node):
        if node.type in fn_types:
            body = src[node.start_byte : node.end_byte].decode(errors="ignore")
            if not body.strip():
                continue
            if len(body) > max_chars:
                body = body[:max_chars] + "\n// ... [truncated] ..."
            chunks.append(
                Chunk(
                    file=str(file),
                    language=lang,
                    function=_function_name(node, src, lang),
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    body=body,
                    imports=imports[:20],
                )
            )

    if not chunks:
        chunks = _window_chunks(file, lang, text, window_lines, window_overlap)
    _enrich_with_callgraph(chunks, call_graph)
    return chunks
