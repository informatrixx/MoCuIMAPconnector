from __future__ import annotations

from dataclasses import dataclass

from mocu_imap_mcp.imap_client import (
    _format_imap_date,
    _next_day,
    build_search_cursor,
    parse_search_criteria,
    parse_search_cursor,
)
from mocu_imap_mcp.tools.search import (
    _build_search_hash,
    _match_has_attachment_flag,
    _scan_matching_messages,
)


@dataclass
class _FakeAttachment:
    filename: str | None
    part_id: str = "1"
    content_type: str = "application/pdf"


class _FakeImapClient:
    def __init__(self) -> None:
        self.mailbox_uids: dict[str, list[int]] = {
            "INBOX": list(range(100, 0, -1)),
        }

    def search_uids(
        self,
        mailbox: str,
        _criteria: list[str],
        *,
        cursor: str | int | None = None,
        limit: int,
    ) -> tuple[list[int], str | None]:
        uids = self.mailbox_uids.get(mailbox, [])
        if cursor is not None:
            max_uid = int(cursor)
            uids = [uid for uid in uids if uid <= max_uid]
        page = uids[:limit]
        next_cursor = str(page[-1] - 1) if page and len(page) >= limit and page[-1] > 1 else None
        return page, next_cursor

    def fetch_headers(self, _mailbox: str, uid: int, *, include_all_headers: bool = False) -> tuple[bytes, str | None]:
        payload = (
            f"Subject: Rechnung {uid}\\r\\n\\r\\n"
            if uid % 20 == 0
            else f"Subject: Nachricht {uid}\\r\\n\\r\\n"
        )
        return payload.encode(), "2025-01-01T00:00:00"

    def list_attachments(self, _mailbox: str, uid: int) -> list[_FakeAttachment]:
        if uid % 20 == 0:
            return [_FakeAttachment(filename=f"Rechnung-{uid}.pdf")]
        return []

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


def test_cursor_hash_validation() -> None:
    payload = build_search_cursor("INBOX", 4711, query_hash="abc")
    parsed = parse_search_cursor(payload, expected_query_hash="abc")
    assert parsed == ("INBOX", 4711)
    assert parse_search_cursor(payload, expected_query_hash="wrong") is None


def test_search_cursor_can_scan_batches_for_matches() -> None:
    client = _FakeImapClient()
    query_hash = _build_search_hash(
        mailboxes=["INBOX"],
        date_from=None,
        date_to=None,
        from_address=None,
        to_address=None,
        subject=None,
        text=None,
        has_attachment=None,
        attachment_filename=None,
        attachment_extension=None,
    )

    def build_match(_mailbox: str, uid: int) -> dict[str, int] | None:
        if uid % 20 == 0:
            return {"uid": uid}
        return None

    results, cursor = _scan_matching_messages(
        client=client,
        mailboxes=["INBOX"],
        criteria=["ALL"],
        limit=3,
        scan_batch_size=10,
        cursor=None,
        query_hash=query_hash,
        match_builder=build_match,
    )

    assert [item["uid"] for item in results] == [100, 80, 60]
    assert parse_search_cursor(cursor, expected_query_hash=query_hash) == ("INBOX", 59)
