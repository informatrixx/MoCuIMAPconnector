from __future__ import annotations

import base64

import pytest

from mocu_imap_mcp.config import CursorSigningKeyError, Settings, _split_csv, decode_cursor_signing_key
from mocu_imap_mcp.imap_client import SearchCursorState, build_search_cursor, parse_search_cursor
from mocu_imap_mcp.security import (
    AttachmentTooLargeError,
    InvalidSearchParameterError,
    redact,
    sanitize_validation_error,
)

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


def test_cursor_signing_key_direct_init_and_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    base64_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    settings = Settings(imap_host="imap.example", imap_username="u", imap_password="p", cursor_signing_key=base64_key)
    assert settings.cursor_signing_key.get_secret_value() == base64_key

    monkeypatch.setenv("IMAP_USERNAME", "u")
    monkeypatch.setenv("IMAP_PASSWORD", "p")
    monkeypatch.setenv("CURSOR_SIGNING_KEY_HEX", base64_key)
    env_settings_hex = Settings()
    assert env_settings_hex.cursor_signing_key.get_secret_value() == base64_key

    monkeypatch.delenv("CURSOR_SIGNING_KEY_HEX", raising=False)
    monkeypatch.setenv("CURSOR_SIGNING_KEY", base64_key)
    env_settings_alias = Settings()
    assert env_settings_alias.cursor_signing_key.get_secret_value() == base64_key


def test_decode_cursor_signing_key() -> None:
    hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    assert decode_cursor_signing_key(hex_key) == bytes.fromhex(hex_key)

    b64 = base64.b64encode(b"SuperSecretTestKey________123456".ljust(32, b"\x01")).decode()
    decoded = decode_cursor_signing_key(b64)
    assert decoded == b"SuperSecretTestKey________123456".ljust(32, b"\x01")

    with pytest.raises(CursorSigningKeyError):
        decode_cursor_signing_key("not-a-valid-key")


def test_cursor_signing_key_missing_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        Settings(
            imap_username="u",
            imap_password="p",
            imap_host="imap.example",
        )


def test_validation_error_secret_is_sanitized() -> None:
    class _FakeValidationError(Exception):
        def errors(self) -> list[dict[str, object]]:
            return [
                {
                    "loc": ("cursor_signing_key",),
                    "msg": "Ungültiger Key: super-secret-pass",
                    "type": "value_error",
                    "input": "super-secret-pass",
                }
            ]

    sanitized = sanitize_validation_error(_FakeValidationError())
    assert "super-secret-pass" not in str(sanitized)
    assert isinstance(sanitized, dict)
    assert sanitized["errors"][0]["field"] == "cursor_signing_key"  # type: ignore[index]
    assert sanitized["errors"][0]["type"] == "value_error"  # type: ignore[index]

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
