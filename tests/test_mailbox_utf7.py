from __future__ import annotations

import pytest

from mocu_imap_mcp.imap_client import decode_mailbox_name, encode_mailbox_name


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("INBOX", "INBOX"),
        ("Sent", "Sent"),
        ("Entwürfe", "Entwürfe"),
        ("Rechnungen März", "Rechnungen März"),
        ("Ärzte", "Ärzte"),
        ("&", "&"),
    ],
)
def test_mailbox_name_utf7_roundtrip(name: str, expected: str) -> None:
    encoded = encode_mailbox_name(name)
    assert decode_mailbox_name(encoded) == expected


def test_mailbox_ampersand_encoded_as_dash() -> None:
    assert encode_mailbox_name("&") == "&-"
