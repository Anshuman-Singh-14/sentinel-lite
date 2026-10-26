"""CORS: only the origins in ALLOWED_ORIGINS may call the API with the session cookie."""

import pytest
from pydantic import ValidationError

from backend.config import Settings


def preflight(client, origin: str):
    return client.options(
        "/api/auth/login",
        headers={"Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"},
    )


def test_allowed_origin_gets_credentials(client):
    response = preflight(client, "https://app.example.com")
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://app.example.com"
    assert response.headers["access-control-allow-credentials"] == "true"


def test_other_origin_is_refused(client):
    response = preflight(client, "https://evil.example.net")
    assert "access-control-allow-origin" not in response.headers
    plain = client.get("/api/health", headers={"Origin": "https://evil.example.net"})
    assert "access-control-allow-origin" not in plain.headers


def test_origins_are_parsed_and_wildcard_is_rejected(monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", " https://a.example.com/ ,https://b.example.com,")
    assert Settings().cors_origins == ["https://a.example.com", "https://b.example.com"]
    monkeypatch.setenv("ALLOWED_ORIGINS", "*")
    with pytest.raises(ValidationError):
        Settings()
