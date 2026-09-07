from __future__ import annotations

import pytest

from mocu_imap_mcp.config import Settings
from mocu_imap_mcp.imap_client import ImapClient
from mocu_imap_mcp.security import (
    ImapProtocolError,
    InvalidSearchParameterError,
    MailboxNotFoundError,
    MessageNotFoundError,
)

_TEST_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def _build_client_for_failure(fake_imap: object) -> ImapClient:
    settings = Settings(
        imap_host="test",
        imap_port=993,
        imap_username="user",
        imap_password="pass",
        imap_connection_retries=1,
        cursor_signing_key=_TEST_KEY,
    )
    client = ImapClient(settings)
    client._imap = fake_imap
    return client


def test_missing_mailbox_kept_as_domain_error() -> None:
    class _FakeImap:
        def select(self, *_args: object, **_kwargs: object) -> tuple[str, list[bytes]]:
            return "NO", [b""]

        def uid(self, *_args: object) -> tuple[str, list[bytes]]:
            raise AssertionError("uid should not be called")

    client = _build_client_for_failure(_FakeImap())
    with pytest.raises(MailboxNotFoundError):
        client.fetch_headers("MISSING", 1)


def test_invalid_uid_stays_invalid_parameter() -> None:
    class _FakeImap:
        def select(self, *_args: object, **_kwargs: object) -> tuple[str, list[bytes]]:
            return "OK", [b""]

        def uid(self, *_args: object) -> tuple[str, list[bytes]]:
            return "OK", [b""]

    client = _build_client_for_failure(_FakeImap())
    with pytest.raises(InvalidSearchParameterError):
        client.fetch_headers("INBOX", 0)


def test_fetch_missing_message_keeps_message_not_found() -> None:
    class _FakeImap:
        def select(self, _mailbox: str, readonly: bool = True) -> tuple[str, list[bytes]]:
            return "OK", [b""]

        def uid(self, command: str, *args: object) -> tuple[str, list[bytes]]:
            return "NO", []

    client = _build_client_for_failure(_FakeImap())
    with pytest.raises(MessageNotFoundError):
        client.fetch_headers("INBOX", 1)


def test_protocol_error_is_not_wrapped() -> None:
    class _FakeImap:
        def select(self, _mailbox: str, readonly: bool = True) -> tuple[str, list[bytes]]:
            return "OK", [b""]

        def uid(self, _command: str, *_args: object) -> tuple[str, list[bytes]]:
            return "BAD", [b"command unknown"]

    client = _build_client_for_failure(_FakeImap())
    with pytest.raises(ImapProtocolError):
        client.fetch_headers("INBOX", 1)
