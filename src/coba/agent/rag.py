"""RAG retrieval — ChromaDB-backed CWE + few-shot knowledge base.

For the v0 prototype we ship a tiny built-in CWE index (top-25). The
``scripts/build_cwe_kb.py`` script populates a larger ChromaDB collection
from the MITRE CWE XML.
"""

from __future__ import annotations

from dataclasses import dataclass

from coba.utils.logging import get_logger

log = get_logger("coba.agent.rag")


@dataclass
class RagSnippet:
    kind: str  # "cwe" | "example"
    cwe_id: str
    title: str
    text: str


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


class RagIndex:
    """Lookup CWE entries by id or text similarity (substring for the v0 builtin)."""

    def __init__(self) -> None:
        self._cwes = {c.cwe_id: c for c in _BUILTIN_CWES}

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
