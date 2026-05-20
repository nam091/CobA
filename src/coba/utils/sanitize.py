"""Input sanitization utilities — prevent prompt injection from scanned code.

The agent reads untrusted source code and embeds it in LLM prompts. We strip
or escape known prompt-injection sentinels and oversized inputs.
"""

from __future__ import annotations

import re

_PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore (the |all )?(previous|prior|above) instructions?"),
    re.compile(r"(?i)you are now [a-zA-Z ]{0,40}"),
    re.compile(r"(?i)act as [a-zA-Z ]{0,40}"),
    re.compile(r"(?i)disregard (the |any )?(rules|guidelines|policy)"),
]

# Markers we use ourselves in prompts; if seen in code, neutralize them.
_OUR_MARKERS = ("<cwe_context>", "</cwe_context>", "<examples>", "</examples>")


def sanitize_code_for_prompt(code: str, max_chars: int = 8000) -> str:
    """Lightly sanitize a code snippet before embedding in an LLM prompt.

    - Truncate to ``max_chars`` characters.
    - Neutralize known prompt-injection patterns.
    - Escape our own template markers.
    """
    if len(code) > max_chars:
        code = code[:max_chars] + "\n# ... [truncated by CobA sanitizer] ..."

    for marker in _OUR_MARKERS:
        code = code.replace(marker, marker.replace("<", "&lt;").replace(">", "&gt;"))

    for pat in _PROMPT_INJECTION_PATTERNS:
        code = pat.sub("[REDACTED-PROMPT-INJECTION]", code)

    return code


def count_tokens_estimate(text: str) -> int:
    """Cheap token estimator (chars / 4)."""
    return max(1, len(text) // 4)
