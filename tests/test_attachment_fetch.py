from __future__ import annotations

import base64

import pytest

from mocu_imap_mcp.config import Settings
from mocu_imap_mcp.imap_client import ImapClient
from mocu_imap_mcp.models import AttachmentMeta
from mocu_imap_mcp.security import AttachmentTooLargeError
from mocu_imap_mcp.tools.attachments import _resource_prefix


def test_attachment_decode_base64() -> None:
    client = ImapClient(Settings(imap_username="u", imap_password="p"))
    payload = base64.b64encode(b"Hello")
    decoded = client._decode_attachment_bytes(payload, "BASE64")
    assert decoded == b"Hello"


def test_attachment_decode_quoted_printable() -> None:
    client = ImapClient(Settings(imap_username="u", imap_password="p"))
    assert client._decode_attachment_bytes(b"Hallo=20Welt", "quoted-printable") == b"Hallo Welt"


def test_attachment_decode_7bit_passthrough() -> None:
    client = ImapClient(Settings(imap_username="u", imap_password="p"))
    assert client._decode_attachment_bytes(b"Raw", "7BIT") == b"Raw"


def test_attachment_size_limit_prevents_fetch() -> None:
    settings = Settings(imap_username="u", imap_password="p", max_attachment_size_mb=1)
    client = ImapClient(settings)

    def fake_list_attachments(_mailbox: str, _uid: int) -> list[AttachmentMeta]:
        return [AttachmentMeta(part_id="2", filename="big.pdf", content_type="application/pdf", size=5 * 1024 * 1024)]

    client.list_attachments = fake_list_attachments  # type: ignore[method-assign]
    with pytest.raises(AttachmentTooLargeError):
        client.read_attachment("INBOX", 1, "2")


def test_attachment_resource_prefix_from_mime_type() -> None:
    assert _resource_prefix("application/pdf") == "pdf"
    assert _resource_prefix("image/jpeg") == "jpeg"
    assert _resource_prefix("image/png") == "png"
    assert _resource_prefix("application/octet-stream") == "octet"
