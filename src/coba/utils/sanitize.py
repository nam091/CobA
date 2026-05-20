"""Input sanitization utilities — prevent prompt injection from scanned code.

The agent reads untrusted source code and embeds it in LLM prompts. We strip
or escape known prompt-injection sentinels and oversized inputs.
"""

from __future__ import annotations

import re

_PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore (the |all |any )?(previous|prior|above|earlier) instructions?"),
    re.compile(
        r"(?i)forget (the |all |any )?(previous|prior|above|earlier) (instructions?|prompts?)"
    ),
    re.compile(r"(?i)you are now [a-zA-Z0-9 _,-]{0,80}"),
    re.compile(r"(?i)you('?re|'? are) now [a-zA-Z0-9 _,-]{0,80}"),
    re.compile(r"(?i)act as (a|an|the)? ?[a-zA-Z0-9 _-]{0,60}"),
    re.compile(r"(?i)disregard (the |any |all )?(rules|guidelines|policy|policies|safety)"),
    re.compile(r"(?i)system prompt(?: is)?:[^\n]{0,200}"),
    re.compile(r"(?i)\[/?(?:system|assistant|user)\]"),
    re.compile(r"(?i)<\|im_(?:start|end)\|>[^\n]{0,40}"),
    re.compile(r"(?i)<\|(?:system|user|assistant)\|>"),
    re.compile(r"(?i)```\s*system\b[^`]{0,200}```"),
    re.compile(r"(?i)respond (only )?with[^\n]{0,80}(true_positive|false_positive)"),
    re.compile(r"(?i)reveal (your |the )?(system )?prompt"),
    re.compile(r"(?i)print (your |the )?(system )?(prompt|instructions?)"),
]

# Markers we use ourselves in prompts; if seen in code, neutralize them.
_OUR_MARKERS = (
    "<cwe_context>",
    "</cwe_context>",
    "<examples>",
    "</examples>",
    "<chunk>",
    "</chunk>",
    "<finding>",
    "</finding>",
)


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
