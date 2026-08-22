from __future__ import annotations

import imaplib

from mocu_imap_mcp.config import Settings
from mocu_imap_mcp.imap_client import ImapClient, _quote_imap_string


class _MockImap:
    def __init__(self) -> None:
        self.select_calls: list[tuple[str, bool]] = []
        self.uid_calls: list[tuple[str, tuple[object, ...]]] = []
        self.logout_calls = 0
        self.search_returns = [("OK", [b"1 2 3"]), ("OK", [b"4 5 6"])]
        self.uid_called = 0

    def select(self, mailbox: str, readonly: bool = True) -> tuple[str, list[bytes]]:
        self.select_calls.append((mailbox, readonly))
        return "OK", [b""]

    def login(self, _username: str, _password: str) -> tuple[str, list[bytes]]:
        return "OK", [b""]

    def noop(self) -> tuple[str, list[bytes]]:
        return "OK", [b""]

    def uid(self, command: str, *args: object) -> tuple[str, list[bytes]]:
        self.uid_calls.append((command, args))
        if command == "FETCH" and self.uid_called == 0:
            self.uid_called += 1
            raise imaplib.IMAP4.abort("simulated abort")
        if command == "FETCH":
            self.uid_called += 1
        return "OK", [
            b'1 (UID 1 BODY[HEADER] {5}',
            b"hello",
            b")",
            b' INTERNALDATE "1-Jan-2000 00:00:00 +0000")',
        ]

    def logout(self) -> tuple[str, list[bytes]]:
        self.logout_calls += 1
        return "OK", [b""]


def test_reconnect_reselects_mailbox_after_abort() -> None:
    settings = Settings(
        imap_host="test",
        imap_port=993,
        imap_username="user",
        imap_password="pass",
        imap_connection_retries=2,
    )
    client = ImapClient(settings)
    fake = _MockImap()
    client._imap = fake

    def _reconnect() -> None:
        client._imap = fake

    client.connect = _reconnect  # type: ignore[method-assign]
    payload, _ = client.fetch_headers("INBOX", 1)
    assert payload == b"hello"
    assert len(fake.uid_calls) >= 2
    assert fake.select_calls[0] == ("INBOX", True)
    assert fake.select_calls[1] == ("INBOX", True)


def test_uid_search_passes_charset_for_utf8_query() -> None:
    class _SearchMock(_MockImap):
        def __init__(self) -> None:
            super().__init__()
            self.uid_calls = []

    settings = Settings(imap_host="test", imap_port=993, imap_username="user", imap_password="pass")
    client = ImapClient(settings)
    fake = _SearchMock()
    client._imap = fake
    client.connect = lambda: setattr(client, "_imap", fake)  # type: ignore[method-assign]
    uids = ["UID", "1:4711"]  # noqa: F841
    client.search_uids("INBOX", ["FROM", _quote_imap_string("Rechnung März")], limit=5)
    command, args = fake.uid_calls[-1]
    assert command == "SEARCH"
    assert args[0] == b"CHARSET"
    assert args[1] == b"UTF-8"
    assert args[2] == b"FROM"
