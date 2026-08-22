from __future__ import annotations

from mocu_imap_mcp.imap_client import (
    _format_imap_date,
    _next_day,
    build_search_cursor,
    parse_search_criteria,
    parse_search_cursor,
)
from mocu_imap_mcp.tools.search import _match_has_attachment_flag


def test_search_criteria_date_range_is_inclusive() -> None:
    criteria = parse_search_criteria(date_from="2025-01-01", date_to="2025-12-31")
    assert criteria == ["SINCE", "01-Jan-2025", "BEFORE", "01-Jan-2026"]


def test_next_day_and_imap_date_format() -> None:
    assert _next_day("2025-12-31") == "2026-01-01"
    assert _format_imap_date("2025-01-01") == "01-Jan-2025"


def test_cursor_roundtrip() -> None:
    cursor = build_search_cursor("INBOX", 4711)
    mailbox, uid = parse_search_cursor(cursor) or ("", None)
    assert mailbox == "INBOX"
    assert uid == 4711


def test_has_attachment_filter_semantics() -> None:
    assert _match_has_attachment_flag([], None) is True
    assert _match_has_attachment_flag([], True) is False
    assert _match_has_attachment_flag([], False) is True
    assert _match_has_attachment_flag([1], None) is True
    assert _match_has_attachment_flag([1], True) is True
    assert _match_has_attachment_flag([1], False) is False
