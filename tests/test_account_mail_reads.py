from __future__ import annotations

import asyncio
from contextlib import contextmanager
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError

from mocu_imap_mcp.config import Settings
from mocu_imap_mcp.imap_client import ImapClient
from mocu_imap_mcp.mail_content import read_email
from mocu_imap_mcp.models import AttachmentMeta
from mocu_imap_mcp.multi_tools import register
from mocu_imap_mcp.runtime import Runtime
from mocu_imap_mcp.security import MessageNotFoundError
from test_accounts_runtime import add_account


@pytest.mark.parametrize("include_body", [True, False])
def test_body_only_fetches_textparts(include_body: bool) -> None:
    calls = []

    class Client:
        settings = Settings(cursor_signing_key="ab" * 32)

        def fetch_headers(self, mailbox: str, uid: int) -> tuple[bytes, None]:
            return b"Subject: Fixture\r\n\r\n", None

        def fetch_bodystructure(self, mailbox: str, uid: int) -> tuple[str, None]:
            return ('(("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 5 1)'
                    '("APPLICATION" "PDF" ("NAME" "invoice.pdf") NIL NIL "BASE64" 100 NIL '
                    '("ATTACHMENT" ("FILENAME" "invoice.pdf"))) "MIXED")'), None

        def fetch_message_part_mime(self, mailbox: str, uid: int, part_id: str) -> bytes:
            assert part_id == "1"
            calls.append("mime")
            return b"Content-Type: text/plain; charset=utf-8\r\n\r\n"

        def fetch_message_part_body(self, mailbox: str, uid: int, part_id: str) -> bytes:
            assert part_id == "1"
            calls.append("body")
            return b"Hello"

    result = read_email(Client(), "INBOX", 7, include_body)  # type: ignore[arg-type]
    assert result["text_body"] == ("Hello" if include_body else "")
    assert result["attachments"][0]["filename"] == "invoice.pdf"
    assert calls == (["mime", "body"] if include_body else [])


def test_uidvalidity_stale_before_fetch() -> None:
    class Connection:
        def select(self, mailbox: str, readonly: bool) -> tuple[str, list[bytes]]:
            assert readonly is True
            return "OK", [b"1"]

        def response(self, name: str) -> tuple[str, list[bytes]]:
            return "UIDVALIDITY", [b"200"]

    client = ImapClient(Settings(cursor_signing_key="ab" * 32), connector=lambda *args: Connection())
    client._imap = Connection()  # type: ignore[assignment]
    with pytest.raises(MessageNotFoundError, match="stale"):
        client.pin_mailbox("INBOX", 100)


def test_search_wire_uses_bounded_uid_window() -> None:
    calls = []

    class Connection:
        def select(self, mailbox: str, readonly: bool) -> tuple[str, list[bytes]]:
            assert readonly is True
            return "OK", [b"1"]

        def response(self, name: str) -> tuple[str, list[bytes]]:
            return name, [b"200" if name == "UIDVALIDITY" else b"50001"]

        def uid(self, command: str, *args: bytes) -> tuple[str, list[bytes]]:
            calls.append((command, args))
            return "OK", [b""]

    client = ImapClient(Settings(cursor_signing_key="ab" * 32), connector=lambda *args: Connection())
    client._imap = Connection()  # type: ignore[assignment]
    uids, cursor = client.search_uids("INBOX", ["ALL"], limit=100)
    assert uids == []
    assert cursor == 49000
    assert calls == [("SEARCH", (b"ALL", b"UID", b"49001:50000", b"UID", b"1:50000"))]


def test_account_resource_real_sdk_read(runtime: Runtime, monkeypatch: pytest.MonkeyPatch) -> None:
    account_id = add_account(runtime)
    reads = []

    class Client:
        def pin_mailbox(self, mailbox: str, uidvalidity: int) -> int:
            assert mailbox == "INBOX" and uidvalidity == 123
            return 123

        def list_attachments(self, mailbox: str, uid: int) -> list[AttachmentMeta]:
            return [AttachmentMeta(part_id="2", filename="invoice.pdf", content_type="application/pdf", size=4)]

        def read_attachment(self, mailbox: str, uid: int, part_id: str) -> bytes:
            reads.append(part_id)
            return b"%PDF-fixture"

    @contextmanager
    def client(account: str) -> Any:
        runtime.store.get(account)
        yield Client()

    monkeypatch.setattr(runtime, "client", client)

    async def check() -> None:
        server = MCPServer("Fixture")
        register(server, runtime)
        uri = f"mocu://attachment-pdf/{account_id}/INBOX/123/7/2"
        contents = list(await server.read_resource(uri))
        assert contents[0].content == b"%PDF-fixture"
        assert contents[0].mime_type == "application/pdf"
        with pytest.raises(ResourceError, match="Resource-MIME-Prefix"):
            await server.read_resource(uri.replace("attachment-pdf", "attachment-octet"))
        assert reads == ["2"]
        runtime.store.delete(account_id)
        with pytest.raises(ResourceError, match="Konto unbekannt"):
            await server.read_resource(uri)
        assert reads == ["2"]

    asyncio.run(check())
