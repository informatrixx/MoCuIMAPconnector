from __future__ import annotations

import pytest

from mocu_imap_mcp.config import Settings, _split_csv
from mocu_imap_mcp.security import AttachmentTooLargeError, redact


def test_settings_does_not_serialize_password_plain() -> None:
    settings = Settings(imap_username="user@example.com", imap_password="super-secret-123")
    assert "super-secret-123" not in repr(settings)
    assert "super-secret-123" not in settings.model_dump_json()
    assert "***redacted***" in settings.model_dump_json()
    assert "super-secret-123" not in str(settings)
    assert "super-secret-123" not in settings.model_dump().get("imap_password", "")


def test_redact_function_removes_secret() -> None:
    assert redact("token=super-secret-123", ["super-secret-123"]) == "token=***REDACTED***"


def test_security_error_type_name() -> None:
    err = AttachmentTooLargeError("too_large")
    assert str(err) == "too_large"


def test_split_csv_accepts_comma_and_json_inputs() -> None:
    assert _split_csv("a,b,c") == ["a", "b", "c"]
    assert _split_csv('["a", "b", "c"]') == ["a", "b", "c"]


def test_settings_parses_csv_lists_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IMAP_USERNAME", "u")
    monkeypatch.setenv("IMAP_PASSWORD", "p")
    monkeypatch.setenv("CURSOR_SIGNING_KEY", "secret")
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", "127.0.0.1,127.0.0.1:*")
    monkeypatch.setenv("MCP_ALLOWED_ORIGINS", "https://127.0.0.1,https://localhost")

    settings = Settings()
    assert settings.mcp_allowed_hosts == ["127.0.0.1", "127.0.0.1:*"]
    assert settings.mcp_allowed_origins == ["https://127.0.0.1", "https://localhost"]
