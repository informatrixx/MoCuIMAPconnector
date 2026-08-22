from __future__ import annotations

from mocu_imap_mcp.config import Settings
from mocu_imap_mcp.security import AttachmentTooLargeError, redact


def test_settings_does_not_serialize_password_plain() -> None:
    settings = Settings(imap_username="user@example.com", imap_password="super-secret-123")
    assert "super-secret-123" not in repr(settings)
    assert "super-secret-123" not in settings.model_dump_json()
    assert "***redacted***" in settings.model_dump_json()


def test_redact_function_removes_secret() -> None:
    assert redact("token=super-secret-123", ["super-secret-123"]) == "token=***REDACTED***"


def test_security_error_type_name() -> None:
    err = AttachmentTooLargeError("too_large")
    assert str(err) == "too_large"
