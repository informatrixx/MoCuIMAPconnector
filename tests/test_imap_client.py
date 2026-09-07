from __future__ import annotations

import pytest

import mocu_imap_mcp.imap_client as imap_client_module
from mocu_imap_mcp.config import Settings
from mocu_imap_mcp.imap_client import (
    InvalidSearchParameterError,
    _build_uid_search_query,
    _quote_imap_string,
    extract_bodystructure_from_fetch,
    extract_fetch_literal,
    extract_fetch_literals,
    extract_fetch_metadata,
    extract_internal_date,
    parse_search_criteria,
)


def test_quote_imap_string() -> None:
    assert _quote_imap_string('Foo "bar"') == '"Foo \\"bar\\""'
    assert _quote_imap_string(r"foo\bar") == '"foo\\\\bar"'


def test_quote_imap_string_rejects_control_chars() -> None:
    with pytest.raises(InvalidSearchParameterError):
        _quote_imap_string("line\nbreak")


def test_uid_search_query_includes_charset_for_utf8() -> None:
    query = _build_uid_search_query(["FROM", _quote_imap_string("Rechnung März")])
    assert query[0] == "CHARSET"
    assert query[1] == "UTF-8"


def test_uid_search_query_no_charset_for_ascii() -> None:
    assert _build_uid_search_query(["FROM", _quote_imap_string("Alice")]) == ("FROM", '"Alice"')


def test_extract_fetch_metadata_and_literals() -> None:
    response = [
        (
            b'123 (UID 4711 BODY[HEADER] {85}',
            b"Subject: Rechnung 123\r\nFrom: billing@example.org\r\n\r\n",
        ),
        b')',
    ]
    metadata = extract_fetch_metadata(response)
    assert metadata
    assert metadata[0].startswith(b"123 (UID 4711 BODY[HEADER]")
    literals = extract_fetch_literals(response)
    assert literals == [b"Subject: Rechnung 123\r\nFrom: billing@example.org\r\n\r\n"]
    assert extract_fetch_literal(response) == b"Subject: Rechnung 123\r\nFrom: billing@example.org\r\n\r\n"


def test_extract_bodystructure_from_fetch() -> None:
    response = [
        b'1 (UID 4711 BODYSTRUCTURE (("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 128 4)'
        b'("APPLICATION" "PDF" ("NAME" "invoice.pdf") NIL NIL "BASE64" 2048 NIL'
        b'("ATTACHMENT" ("FILENAME" "invoice.pdf")) NIL) "MIXED") INTERNALDATE "15-Mar-2025 11:30:00 +0100")',
    ]
    structure = extract_bodystructure_from_fetch(response)
    assert structure is not None
    assert structure.startswith("((")
    assert "invoice.pdf" in structure


def test_search_criteria_date_range_inclusive() -> None:
    criteria = parse_search_criteria(date_from="2025-01-01", date_to="2025-12-31")
    assert criteria == ["SINCE", "01-Jan-2025", "BEFORE", "01-Jan-2026"]


def test_extract_internal_date_reads_raw_internaldate() -> None:
    data = [
        b'1 (UID 1 BODY[HEADER] {5}',
        b"hello",
        b")",
        b' INTERNALDATE "1-Jan-2000 00:00:00 +0000")',
    ]
    from mocu_imap_mcp.imap_client import extract_internal_date

    assert extract_internal_date(data) == "2000-01-01T00:00:00+00:00"


def test_extract_internal_date_ignores_internaldate_in_header_body() -> None:
    response = [
        b'1 (UID 4711 BODY[HEADER] {53}',
        b'Subject: INTERNALDATE "01-Jan-1999 00:00:00 +0000"\r\n\r\n',
        b') INTERNALDATE "15-Mar-2025 11:30:00 +0100")',
    ]
    assert extract_internal_date(response) == "2025-03-15T11:30:00+01:00"


def test_extract_bodystructure_from_fetch_ignores_bodystructure_marker_in_body_text() -> None:
    response = [
        b'1 (UID 4711 BODY[TEXT] {33}',
        b'Body contains BODYSTRUCTURE keyword only',
        b') INTERNALDATE "01-Jan-2025 00:00:00 +0000")',
    ]
    assert extract_bodystructure_from_fetch(response) is None


def test_extract_fetch_response_multiple_literals() -> None:
    response = [
        b'1 (UID 4711 BODY[HEADER] {54}',
        b'INTERNALDATE "01-Jan-1999 00:00:00 +0000"',
        b' BODY[1] {4}',
        b'ABCD',
        b') INTERNALDATE "15-Mar-2025 11:30:00 +0100")',
    ]
    assert extract_fetch_literals(response) == [
        b'INTERNALDATE "01-Jan-1999 00:00:00 +0000"',
        b"ABCD",
    ]
    assert extract_internal_date(response) == "2025-03-15T11:30:00+01:00"
    assert extract_fetch_literal(response) == b'INTERNALDATE "01-Jan-1999 00:00:00 +0000"'


def test_search_query_uses_bytes_payload_for_utf8_criteria() -> None:
    calls: list[tuple[object, ...]] = []
    original_imap4_ssl = imap_client_module.imaplib.IMAP4_SSL

    class _FakeImap:
        def __init__(self, _host: str, _port: int, timeout: int, **_kwargs: object) -> None:
            self.timeout = timeout

        def login(self, _user: str, _password: str) -> tuple[str, list[bytes]]:
            return "OK", []

        def select(self, _mailbox: str, readonly: bool = True) -> tuple[str, list[bytes]]:
            return "OK", []

        def uid(self, _command: str, *args: object) -> tuple[str, list[bytes]]:
            calls.append(tuple(args))
            return "OK", [b"1 2 3"]

        def logout(self) -> tuple[str, list[bytes]]:
            return "OK", []

    try:
        imap_client_module.imaplib.IMAP4_SSL = _FakeImap  # type: ignore[assignment]
        client = imap_client_module.ImapClient(
            Settings(
                imap_host="imap.example",
                imap_port=993,
                imap_username="u",
                imap_password="p",
                cursor_signing_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
        )
        client.search_uids("INBOX", ["FROM", _quote_imap_string("Rechnung März")], limit=1)
    finally:
        imap_client_module.imaplib.IMAP4_SSL = original_imap4_ssl  # type: ignore[assignment]

    assert calls, "IMAP uid() wurde nicht aufgerufen"
    query_args = calls[0]
    assert all(isinstance(item, bytes) for item in query_args)
    assert query_args[:3] == (b"CHARSET", b"UTF-8", b"FROM")
    assert query_args[3] == '"Rechnung März"'.encode()


def test_build_uid_search_query_allows_binary_payload() -> None:
    query = _build_uid_search_query(["FROM", _quote_imap_string("Rechnung März")])
    assert query[:2] == ("CHARSET", "UTF-8")
