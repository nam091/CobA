"""Example safe Python code — should produce zero findings."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from pathlib import Path


def safe_lookup_user(user_id: int) -> list[tuple]:
    """Parameterized query — safe from SQLi."""
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchall()


def safe_read_file(filename: str) -> str:
    """Path traversal mitigated by anchoring to base + checking parent."""
    base = Path("/var/data").resolve()
    full = (base / filename).resolve()
    if not str(full).startswith(str(base)):
        raise ValueError("path traversal")
    return full.read_text()


def safe_hash_password(pw: str, salt: bytes) -> str:
    """Argon2id or scrypt would be even better, but SHA-256 with salt is OK here."""
    return hashlib.sha256(salt + pw.encode()).hexdigest()


def safe_token() -> str:
    return secrets.token_urlsafe(16)
