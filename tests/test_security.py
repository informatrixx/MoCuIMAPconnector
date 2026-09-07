from __future__ import annotations

import pytest

from mocu_imap_mcp.config import Settings, _split_csv
from mocu_imap_mcp.imap_client import SearchCursorState, build_search_cursor, parse_search_cursor
from mocu_imap_mcp.security import AttachmentTooLargeError, InvalidSearchParameterError, redact

_TEST_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def test_settings_does_not_serialize_password_plain() -> None:
    settings = Settings(
        imap_username="user@example.com",
        imap_password="super-secret-123",
        cursor_signing_key=_TEST_KEY,
    )
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
    monkeypatch.setenv("CURSOR_SIGNING_KEY", _TEST_KEY)
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", "127.0.0.1,127.0.0.1:*")
    monkeypatch.setenv("MCP_ALLOWED_ORIGINS", "https://127.0.0.1,https://localhost")

    settings = Settings()
    assert settings.mcp_allowed_hosts == ["127.0.0.1", "127.0.0.1:*"]
    assert settings.mcp_allowed_origins == ["https://127.0.0.1", "https://localhost"]


def test_cursor_signing_key_rejected_if_too_short() -> None:
    with pytest.raises(ValueError):
        Settings(
            imap_username="u",
            imap_password="p",
            cursor_signing_key="0123456789abcdef",
        )


def test_cursor_signing_key_secret_not_serialized_plain() -> None:
    key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    settings = Settings(
        imap_username="u",
        imap_password="p",
        cursor_signing_key=key,
    )
    assert key not in repr(settings)
    assert key not in str(settings)
    assert key not in settings.model_dump_json()


def test_cursor_hmac_integrity_and_key_validation() -> None:
    key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    payload = build_search_cursor(
        state=SearchCursorState(
            version=3,
            mailbox_index=0,
            mailbox="INBOX",
            before_uid=None,
            query_hash="qhash",
        ),
        signing_key=bytes.fromhex(key),
    )
    parsed = parse_search_cursor(
        payload,
        expected_query_hash="qhash",
        signing_key=bytes.fromhex(key),
    )
    assert parsed.mailbox == "INBOX"
    body, _sig = payload.split(".")
    with pytest.raises(InvalidSearchParameterError):
        parse_search_cursor(
            f"{body}.AAAA",
            expected_query_hash="qhash",
            signing_key=bytes.fromhex(key),
        )

    with pytest.raises(InvalidSearchParameterError):
        parse_search_cursor(
            payload,
            expected_query_hash="other",
            signing_key=bytes.fromhex(key),
        )
