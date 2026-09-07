from __future__ import annotations

import base64

import pytest

from mocu_imap_mcp.bodystructure import iter_attachments_from_bodystructure
from mocu_imap_mcp.config import Settings
from mocu_imap_mcp.imap_client import ImapClient, extract_bodystructure_from_fetch
from mocu_imap_mcp.models import AttachmentMeta
from mocu_imap_mcp.security import AttachmentTooLargeError
from mocu_imap_mcp.tools.attachments import _read_attachment, _resource_prefix

_TEST_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def test_attachment_decode_base64() -> None:
    client = ImapClient(Settings(imap_username="u", imap_password="p", cursor_signing_key=_TEST_KEY))
    payload = base64.b64encode(b"Hello")
    decoded = client._decode_attachment_bytes(payload, "BASE64")
    assert decoded == b"Hello"


def test_attachment_decode_quoted_printable() -> None:
    client = ImapClient(Settings(imap_username="u", imap_password="p", cursor_signing_key=_TEST_KEY))
    assert client._decode_attachment_bytes(b"Hallo=20Welt", "quoted-printable") == b"Hallo Welt"


def test_attachment_decode_7bit_passthrough() -> None:
    client = ImapClient(Settings(imap_username="u", imap_password="p", cursor_signing_key=_TEST_KEY))
    assert client._decode_attachment_bytes(b"Raw", "7BIT") == b"Raw"


def test_attachment_size_limit_prevents_fetch() -> None:
    settings = Settings(imap_username="u", imap_password="p", max_attachment_size_mb=1, cursor_signing_key=_TEST_KEY)
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


def test_read_attachment_decodes_from_bodystructure_fetch_with_literal_filename() -> None:
    filename = 'rechnung)2025".pdf'
    encoded_name = filename.encode("utf-8")
    response = [
        b'1 (UID 99 BODYSTRUCTURE (("APPLICATION" "PDF" ("NAME" {'
        + str(len(encoded_name)).encode("utf-8")
        + b'}'
        + filename.encode("utf-8")
        + b') NIL NIL "BASE64" 5 NIL ("ATTACHMENT" ("FILENAME" {'
        + str(len(encoded_name)).encode("utf-8")
        + b'}'
        + filename.encode("utf-8")
        + b')) NIL) "MIXED")) INTERNALDATE "15-Mar-2025 11:30:00 +0100")',
    ]

    client = ImapClient(Settings(imap_username="u", imap_password="p", cursor_signing_key=_TEST_KEY))
    bodystructure = extract_bodystructure_from_fetch(response)
    assert bodystructure is not None
    attachments = iter_attachments_from_bodystructure(bodystructure)
    assert attachments[0].filename == filename
    assert attachments[0].part_id in {"1", "2"}

    client.list_attachments = lambda _mailbox, _uid: attachments  # type: ignore[method-assign]
    client.fetch_message_part_body = lambda *_args, **_kwargs: base64.b64encode(b"Hello")  # type: ignore[method-assign]

    decoded = client.read_attachment("INBOX", 99, attachments[0].part_id)
    assert decoded == b"Hello"


def test_read_attachment_resource_prefix_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeClient:
        def list_attachments(self, _mailbox: str, _uid: int) -> list[AttachmentMeta]:
            return [
                AttachmentMeta(
                    part_id="1",
                    filename="rechnung)2025.pdf",
                    content_type="image/png",
                    size=5,
                    inline=False,
                    transfer_encoding="BASE64",
                )
            ]

        def read_attachment(self, _mailbox: str, _uid: int, _part_id: str) -> bytes:
            return base64.b64decode(b"SGVsbG8=")

    monkeypatch.setattr(
        "mocu_imap_mcp.tools.attachments.ImapClient",
        lambda _settings: _FakeClient(),  # type: ignore[assignment]
    )
    with pytest.raises(ValueError):
        _read_attachment(
            "INBOX",
            99,
            "1",
            Settings(imap_username="u", imap_password="p", cursor_signing_key=_TEST_KEY),
            expected_prefix="pdf",
        )

    assert _resource_prefix("image/png") == "png"
    result = _read_attachment(
        "INBOX",
        99,
        "1",
        Settings(imap_username="u", imap_password="p", cursor_signing_key=_TEST_KEY),
        expected_prefix="png",
    )
    assert result == b"Hello"

    class _FakeClientUnknown:
        def list_attachments(self, _mailbox: str, _uid: int) -> list[AttachmentMeta]:
            return [
                AttachmentMeta(
                    part_id="2",
                    filename="blob.bin",
                    content_type="application/x-unknown",
                    size=5,
                    inline=False,
                    transfer_encoding="BASE64",
                )
            ]

        def read_attachment(self, _mailbox: str, _uid: int, _part_id: str) -> bytes:
            return base64.b64decode(b"SGVsbG8=")

    monkeypatch.setattr(
        "mocu_imap_mcp.tools.attachments.ImapClient",
        lambda _settings: _FakeClientUnknown(),  # type: ignore[assignment]
    )
    result = _read_attachment(
        "INBOX",
        99,
        "2",
        Settings(imap_username="u", imap_password="p", cursor_signing_key=_TEST_KEY),
        expected_prefix="octet",
    )
    assert result == b"Hello"
