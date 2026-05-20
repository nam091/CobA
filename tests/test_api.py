"""Smoke tests for the FastAPI app — endpoints respond, no LLM calls."""

from fastapi.testclient import TestClient

from coba.api.app import create_app


def test_health_ok() -> None:
    client = TestClient(create_app())
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_models_list() -> None:
    client = TestClient(create_app())
    r = client.get("/models")
    assert r.status_code == 200
    body = r.json()
    assert "configured" in body
    assert "models" in body
    assert len(body["models"]) > 0


def test_tools_list() -> None:
    client = TestClient(create_app())
    r = client.get("/tools")
    assert r.status_code == 200
    body = r.json()
    assert "tools" in body
    names = {t["name"] for t in body["tools"]}
    assert {"semgrep", "bandit", "gitleaks", "joern"} <= names


def test_scan_requires_target() -> None:
    client = TestClient(create_app())
    r = client.post("/scan", json={})
    assert r.status_code == 400
