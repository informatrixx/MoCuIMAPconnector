from __future__ import annotations

import pytest

from mocu_imap_mcp.config import Settings
from mocu_imap_mcp.security import MessageTooLargeError
from mocu_imap_mcp.tools.messages import get_email_impl

_TEST_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class _FakeImapClient:
    def __init__(self, size: int) -> None:
        self.size = size
        self.assert_calls = 0
        self.full_fetch_calls = 0

    def __enter__(self) -> _FakeImapClient:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def assert_message_size_limit(self, mailbox: str, uid: int) -> int:
        self.assert_calls += 1
        if self.size > 1024 * 1024:
            raise MessageTooLargeError("Nachricht 4711 überschreitet die Konfigurationsgrenze von 1 MB")
        return self.size

    def fetch_headers(self, _mailbox: str, _uid: int, *, include_all_headers: bool = False) -> tuple[bytes, str | None]:
        return b"Subject: Hallo\r\n\r\n", "2025-03-01T00:00:00"

    def fetch_full_message(self, _mailbox: str, _uid: int) -> tuple[bytes, str | None]:
        self.full_fetch_calls += 1
        body = ("Langer Text " * 300_000).encode()
        return body, "2025-03-01T00:00:00"

    def fetch_message_size(self, mailbox: str, uid: int) -> int:  # pragma: no cover - compatibility
        return self.size

    def close(self) -> None:  # pragma: no cover - compatibility
        return None


def test_message_too_large_stops_full_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = _FakeImapClient(size=2 * 1024 * 1024)
    settings = Settings(
        imap_host="localhost",
        imap_port=143,
        imap_username="user",
        imap_password="password",
        imap_tls_mode="starttls",
        cursor_signing_key=_TEST_KEY,
        max_message_size_mb=1,
    )
    monkeypatch.setattr("mocu_imap_mcp.tools.messages.ImapClient", lambda _settings: fake_client)  # type: ignore[assignment]
    result = get_email_impl(settings, "INBOX", 4711, include_body=True)
    assert result == {"error": "Nachricht 4711 überschreitet die Konfigurationsgrenze von 1 MB"}
    assert fake_client.assert_calls == 1
    assert fake_client.full_fetch_calls == 0


def test_text_body_is_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = _FakeImapClient(size=10)
    settings = Settings(
        imap_host="localhost",
        imap_port=143,
        imap_username="user",
        imap_password="password",
        imap_tls_mode="starttls",
        cursor_signing_key=_TEST_KEY,
        max_message_size_mb=10,
        max_body_chars=20,
    )
    monkeypatch.setattr("mocu_imap_mcp.tools.messages.ImapClient", lambda _settings: fake_client)  # type: ignore[assignment]
    result = get_email_impl(settings, "INBOX", 4711, include_body=True)
    assert result["text_body_truncated"] is True
    assert len(result["text_body"]) == 20
