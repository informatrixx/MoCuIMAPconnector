from __future__ import annotations

import pytest

from mocu_imap_mcp.imap_client import (
    _build_uid_search_query,
    _quote_imap_string,
    extract_fetch_literal,
    extract_fetch_literals,
    extract_fetch_metadata,
    parse_search_criteria,
)
from mocu_imap_mcp.security import InvalidSearchParameterError


def test_quote_imap_string_with_special_characters() -> None:
    assert _quote_imap_string('Foo "bar"') == '"Foo \\\\\\"bar\\\\\\""'
    assert _quote_imap_string(r"foo\\bar") == '"foo\\\\\\\\bar"'


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
        (b'123 (UID 4711 BODY[HEADER] {85}', b"Subject: Rechnung 123\r\nFrom: billing@example.org\r\n\r\n"),
        b')',
    ]
    metadata = extract_fetch_metadata(response)
    assert metadata
    assert metadata[0].startswith(b'123 (UID 4711 BODY[HEADER]')
    literals = extract_fetch_literals(response)
    assert literals == [b"Subject: Rechnung 123\r\nFrom: billing@example.org\r\n\r\n"]
    assert extract_fetch_literal(response) == b"Subject: Rechnung 123\r\nFrom: billing@example.org\r\n\r\n"


def test_search_criteria_date_range_inclusive() -> None:
    criteria = parse_search_criteria(date_from="2025-01-01", date_to="2025-12-31")
    assert criteria == ["SINCE", "01-Jan-2025", "BEFORE", "01-Jan-2026"]
