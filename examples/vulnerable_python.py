"""Example vulnerable Python code for CobA smoke testing.

DO NOT run any of these functions on real input. Each one demonstrates a
specific CWE so the agent has something to find.
"""

from __future__ import annotations

import hashlib
import os
import pickle
import sqlite3
import subprocess
from pathlib import Path


# CWE-89: SQL Injection
def sqli_lookup_user(user_id: str) -> list[tuple]:
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cur.execute(query)
    return cur.fetchall()


# CWE-78: OS Command Injection
def cmdi_ping(host: str) -> str:
    return subprocess.check_output(f"ping -c1 {host}", shell=True).decode()


# CWE-94: Code Injection via eval
def evil_eval(expr: str) -> object:
    return eval(expr)


# CWE-502: Deserialization of untrusted data
def load_session(blob: bytes) -> object:
    return pickle.loads(blob)


# CWE-22: Path Traversal
def read_user_file(filename: str) -> str:
    path = Path("/var/data") / filename
    return path.read_text()


# CWE-327: Use of broken hash
def hash_password(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()


# CWE-798: Hard-coded credentials
API_KEY = "sk-proj-DO_NOT_USE_THIS_KEY_AT_ALL_1234567890ABCDEFGH"
DB_PASSWORD = "admin12345"


# CWE-330: Use of insufficiently random
import random  # noqa: E402


def generate_token() -> str:
    return "".join(str(random.randint(0, 9)) for _ in range(8))


# CWE-918: SSRF
def fetch_url(url: str) -> bytes:
    import urllib.request

    return urllib.request.urlopen(url).read()


# CWE-732: Insecure permissions
def write_secret(path: str, secret: str) -> None:
    with open(path, "w") as f:
        f.write(secret)
    os.chmod(path, 0o777)
