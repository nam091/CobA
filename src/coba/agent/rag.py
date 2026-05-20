"""RAG retrieval — ChromaDB-backed CWE + few-shot knowledge base.

For the v0 prototype we ship a tiny built-in CWE index (top-25). The
``scripts/build_cwe_kb.py`` script populates a larger ChromaDB collection
from the MITRE CWE XML.

The :class:`FewShotIndex` is independent: it loads hand-curated
(vuln, safe) code pairs from ``src/coba/data/fewshot_examples.json``
and serves them to the Detector prompt for in-context learning.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from coba.utils.logging import get_logger

log = get_logger("coba.agent.rag")


@dataclass
class RagSnippet:
    kind: str  # "cwe" | "example"
    cwe_id: str
    title: str
    text: str


@dataclass
class FewShotExample:
    cwe: str
    language: str
    vuln: str
    safe: str
    explanation: str = ""

    @property
    def title(self) -> str:
        return f"{self.cwe} · {self.language}"


@dataclass
class _FewShotBank:
    examples: list[FewShotExample] = field(default_factory=list)


# Tiny built-in CWE table — used until the full Chroma KB is built.
# Source: MITRE CWE Top 25 2024 (paraphrased; full descriptions in the KB).
_BUILTIN_CWES: list[RagSnippet] = [
    RagSnippet(
        "cwe",
        "CWE-79",
        "Cross-site Scripting (XSS)",
        "Reflected/Stored/DOM XSS: user input rendered as HTML without escaping.",
    ),
    RagSnippet(
        "cwe",
        "CWE-89",
        "SQL Injection",
        "Untrusted input concatenated into SQL query enables injection. Use parameterized queries.",
    ),
    RagSnippet(
        "cwe",
        "CWE-78",
        "OS Command Injection",
        "Untrusted input passed to OS shell. Avoid shell=True; pass args as a list.",
    ),
    RagSnippet(
        "cwe",
        "CWE-22",
        "Path Traversal",
        "Untrusted path joined with filesystem ops. Canonicalize, then check against allowed root.",
    ),
    RagSnippet(
        "cwe",
        "CWE-94",
        "Code Injection",
        "Dynamic eval/exec of untrusted input. Eliminate eval; use a parser/whitelist.",
    ),
    RagSnippet(
        "cwe",
        "CWE-502",
        "Deserialization of Untrusted Data",
        "pickle/yaml.load/ObjectInputStream on untrusted data. Use safe loaders.",
    ),
    RagSnippet(
        "cwe",
        "CWE-611",
        "XML External Entity (XXE)",
        "XML parser resolves external entities. Disable DTD/entity resolution.",
    ),
    RagSnippet(
        "cwe",
        "CWE-918",
        "Server-Side Request Forgery (SSRF)",
        "Server fetches an URL from user input. Allow-list hosts; block link-local.",
    ),
    RagSnippet(
        "cwe",
        "CWE-327",
        "Broken/Risky Crypto",
        "MD5/SHA1/DES/ECB usage. Switch to AES-GCM, SHA-256+, Argon2id.",
    ),
    RagSnippet(
        "cwe",
        "CWE-330",
        "Weak Random",
        "random.random / Math.random for security. Use secrets / SecureRandom.",
    ),
    RagSnippet(
        "cwe",
        "CWE-798",
        "Hard-coded Credentials",
        "API key / password in source. Use a secret manager; rotate keys.",
    ),
    RagSnippet(
        "cwe",
        "CWE-352",
        "Cross-Site Request Forgery (CSRF)",
        "State-changing request without anti-CSRF token. Use SameSite cookies + tokens.",
    ),
    RagSnippet(
        "cwe",
        "CWE-862",
        "Missing Authorization",
        "Endpoint accessible without permission check. Add deny-by-default authz middleware.",
    ),
    RagSnippet(
        "cwe",
        "CWE-863",
        "Incorrect Authorization",
        "Authz logic flawed (off-by-one role, IDOR). Centralize policy; test boundary.",
    ),
    RagSnippet(
        "cwe",
        "CWE-287",
        "Improper Authentication",
        "Weak/missing auth, e.g. password compare with == leaks timing.",
    ),
    RagSnippet(
        "cwe",
        "CWE-434",
        "Unrestricted Upload",
        "Uploads not validated by content-type/extension/size. Store outside webroot.",
    ),
    RagSnippet(
        "cwe",
        "CWE-787",
        "Out-of-bounds Write",
        "Buffer overflow via strcpy/sprintf. Use snprintf with bounds; prefer safer APIs.",
    ),
    RagSnippet(
        "cwe",
        "CWE-125",
        "Out-of-bounds Read",
        "Read past buffer end. Validate index < len before access.",
    ),
    RagSnippet(
        "cwe",
        "CWE-416",
        "Use After Free",
        "Pointer dereferenced after free(). Null out pointer; use smart pointers.",
    ),
    RagSnippet(
        "cwe",
        "CWE-476",
        "NULL Pointer Dereference",
        "Dereferencing a possibly-NULL pointer. Add null checks.",
    ),
]


_FEWSHOT_FILE = Path(__file__).resolve().parent.parent / "data" / "fewshot_examples.json"


@lru_cache(maxsize=1)
def _load_fewshot_bank(path: str = str(_FEWSHOT_FILE)) -> _FewShotBank:
    """Load and cache the few-shot example bank from JSON.

    Caching is keyed on the resolved file path so tests can swap the
    file via ``FewShotIndex(path=...)`` without polluting other tests.
    """
    p = Path(path)
    if not p.exists():
        log.warning("rag.fewshot_missing", path=str(p))
        return _FewShotBank()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("rag.fewshot_load_failed", path=str(p), error=str(exc))
        return _FewShotBank()
    raw_examples = data.get("examples", []) if isinstance(data, dict) else []
    bank = _FewShotBank()
    for item in raw_examples:
        try:
            bank.examples.append(
                FewShotExample(
                    cwe=str(item["cwe"]).upper(),
                    language=str(item["language"]).lower(),
                    vuln=str(item.get("vuln", "")),
                    safe=str(item.get("safe", "")),
                    explanation=str(item.get("explanation", "")),
                )
            )
        except (KeyError, TypeError) as exc:
            log.debug("rag.fewshot_bad_row", error=str(exc), row=item)
    log.info("rag.fewshot_loaded", path=str(p), n=len(bank.examples))
    return bank


class FewShotIndex:
    """Look up few-shot (vuln, safe) code pairs for a CWE / language combo.

    The index is fully in-memory and deterministic: examples sharing the
    same (CWE, language) are returned in the order they appear in the
    underlying JSON file, so prompt rendering is reproducible.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._bank = _load_fewshot_bank(str(path) if path else str(_FEWSHOT_FILE))

    def examples_for(
        self,
        cwe: str,
        language: str | None = None,
        *,
        top_k: int = 2,
    ) -> list[FewShotExample]:
        """Return up to ``top_k`` examples matching the CWE.

        When ``language`` is given, prefer examples in that language and
        then fall back to other languages so the LLM always sees at
        least one example when the CWE is covered.
        """
        if not cwe:
            return []
        cwe = cwe.upper()
        same_lang: list[FewShotExample] = []
        other_lang: list[FewShotExample] = []
        for ex in self._bank.examples:
            if ex.cwe != cwe:
                continue
            if language and ex.language == language.lower():
                same_lang.append(ex)
            else:
                other_lang.append(ex)
        # Same-language first, then everything else, capped at top_k.
        return (same_lang + other_lang)[: max(0, top_k)]

    @property
    def n_examples(self) -> int:
        return len(self._bank.examples)

    def covered_cwes(self) -> list[str]:
        return sorted({ex.cwe for ex in self._bank.examples})


class RagIndex:
    """Lookup CWE entries by id or text similarity.

    Default is a tiny in-memory built-in. Call :func:`load_rag_index` to get a
    Chroma-backed index if the KB has been built with ``scripts/build_cwe_kb.py``.
    """

    def __init__(self, entries: list[RagSnippet] | None = None) -> None:
        self._cwes = {c.cwe_id: c for c in (entries or _BUILTIN_CWES)}

    def by_cwe(self, cwe_id: str) -> RagSnippet | None:
        return self._cwes.get(cwe_id)

    def query(self, hints: list[str], top_k: int = 3) -> list[RagSnippet]:
        """Return top-k CWE entries that loosely match the hints (substring match)."""
        if not hints:
            return list(self._cwes.values())[:top_k]
        scored: list[tuple[int, RagSnippet]] = []
        for cwe in self._cwes.values():
            score = 0
            blob = f"{cwe.title} {cwe.text}".lower()
            for h in hints:
                if h.lower() in blob:
                    score += 1
            if score:
                scored.append((score, cwe))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored[:top_k]] or list(self._cwes.values())[:top_k]


class ChromaRagIndex(RagIndex):
    """RAG index backed by a persistent ChromaDB collection.

    Falls back to the in-memory builtin when chroma is unavailable so the
    Agent loop never crashes during tests / offline development.
    """

    COLLECTION_NAME = "coba_cwe"

    def __init__(self, persist_dir: str, embedding_model: str) -> None:
        super().__init__()
        self._collection = None
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
            from chromadb.utils.embedding_functions import (
                SentenceTransformerEmbeddingFunction,
            )

            client = chromadb.PersistentClient(
                path=persist_dir,
                settings=ChromaSettings(anonymized_telemetry=False),
            )
            embedder = SentenceTransformerEmbeddingFunction(model_name=embedding_model)
            self._collection = client.get_or_create_collection(
                self.COLLECTION_NAME,
                embedding_function=embedder,  # type: ignore[arg-type]
            )
            log.info("rag.chroma_loaded", persist_dir=persist_dir)
        except Exception as exc:  # pragma: no cover - depends on optional deps
            log.warning("rag.chroma_unavailable", error=str(exc))
            self._collection = None

    def query(self, hints: list[str], top_k: int = 3) -> list[RagSnippet]:
        if self._collection is None or not hints:
            return super().query(hints, top_k)
        try:
            results = self._collection.query(query_texts=[" ".join(hints)], n_results=top_k)
        except Exception as exc:  # pragma: no cover
            log.warning("rag.chroma_query_failed", error=str(exc))
            return super().query(hints, top_k)
        ids = (results.get("ids") or [[]])[0]
        documents = (results.get("documents") or [[]])[0]
        metadatas = (results.get("metadatas") or [[]])[0]
        out: list[RagSnippet] = []
        for cid, doc, meta in zip(ids, documents, metadatas, strict=False):
            out.append(
                RagSnippet(
                    kind="cwe",
                    cwe_id=str(meta.get("cwe_id") or cid),
                    title=str(meta.get("name") or cid),
                    text=str(doc or ""),
                )
            )
        return out or super().query(hints, top_k)


def load_rag_index() -> RagIndex:
    """Return a Chroma-backed index if the KB exists, else the in-memory builtin.

    The Chroma KB is produced by ``scripts/build_cwe_kb.py`` and persisted to
    ``settings.chroma_persist_dir``.
    """
    from coba.config.settings import get_settings

    settings = get_settings()
    persist_dir = settings.chroma_persist_dir
    if not persist_dir.exists() or not any(persist_dir.iterdir()):
        log.info("rag.fallback_builtin", reason="chroma_dir_empty")
        return RagIndex()
    return ChromaRagIndex(str(persist_dir), settings.embedding_model)
