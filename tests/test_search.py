from __future__ import annotations

from dataclasses import dataclass

import pytest

from mocu_imap_mcp.imap_client import (
    _format_imap_date,
    _next_day,
    build_search_cursor,
    parse_search_criteria,
    parse_search_cursor,
)
from mocu_imap_mcp.security import InvalidSearchParameterError
from mocu_imap_mcp.tools.search import (
    _build_search_hash,
    _scan_matching_messages,
)


@dataclass
class _FakeAttachment:
    filename: str | None
    part_id: str = "1"
    content_type: str = "application/pdf"


class _FakeImapClient:
    def __init__(self, data: dict[str, list[int]]) -> None:
        self.mailbox_uids = data

    def search_uids(
        self,
        mailbox: str,
        _criteria: list[str],
        *,
        before_uid: int | None = None,
        limit: int,
    ) -> tuple[list[int], int | None]:
        uids = self.mailbox_uids.get(mailbox, [])
        if before_uid is not None:
            uids = [uid for uid in uids if uid <= before_uid]
        if not uids:
            return [], None
        batch = uids[:limit]
        next_uid = batch[-1] - 1 if len(uids) > limit and batch else None
        return batch, next_uid

    def fetch_headers(self, _mailbox: str, uid: int, *, include_all_headers: bool = False) -> tuple[bytes, str | None]:
        payload = (
            f"Subject: Rechnung {uid}\r\n\r\n" if uid % 20 == 0 else f"Subject: Nachricht {uid}\r\n\r\n"
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
    secret = "test-key"
    payload = build_search_cursor("INBOX", uid=4711, query_hash="abc", signing_key=secret)
    mailbox, uid = parse_search_cursor(payload, expected_query_hash="abc", signing_key=secret)
    assert mailbox == "INBOX"
    assert uid == 4711


def test_cursor_without_signing_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        build_search_cursor("INBOX", uid=1, query_hash="abc", signing_key="")
    payload = build_search_cursor("INBOX", uid=1, query_hash="abc", signing_key="k")
    with pytest.raises(ValueError):
        parse_search_cursor(payload, expected_query_hash="abc", signing_key="")


def test_cursor_invalid_signature_rejected() -> None:
    secret = "test-key"
    payload = build_search_cursor("INBOX", uid=4711, query_hash="abc", signing_key=secret)
    body, signature = payload.split(".", 1)
    tampered_body = ("x" + body[1:]) if body else "x"
    payload = f"{tampered_body}.{signature}"
    with pytest.raises(InvalidSearchParameterError):
        parse_search_cursor(payload, expected_query_hash="abc", signing_key=secret)


def test_cursor_query_mismatch_rejected() -> None:
    secret = "test-key"
    payload = build_search_cursor("INBOX", uid=4711, query_hash="abc", signing_key=secret)
    with pytest.raises(InvalidSearchParameterError):
        parse_search_cursor(payload, expected_query_hash="wrong", signing_key=secret)


def test_cursor_security_hash_validation_round_trip() -> None:
    payload = build_search_cursor(
        "INBOX",
        uid=4711,
        query_hash="q",
        signing_key="cursor-signing-key",
    )
    parsed = parse_search_cursor(payload, expected_query_hash="q", signing_key="cursor-signing-key")
    assert parsed == ("INBOX", 4711)


def test_search_cursor_can_scan_batches_for_matches() -> None:
    client = _FakeImapClient({"INBOX": list(range(500, 0, -1))})
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
        limit=10,
        scan_batch_size=10,
        cursor=None,
        signing_key="secret",
        query_hash=query_hash,
        match_builder=build_match,
    )

    assert [item["uid"] for item in results] == [500, 480, 460, 440, 420, 400, 380, 360, 340, 320]
    assert cursor is not None
    assert parse_search_cursor(cursor, expected_query_hash=query_hash, signing_key="secret") == ("INBOX", 319)


def test_search_cursor_does_not_regress_to_zero() -> None:
    client = _FakeImapClient({"INBOX": list(range(12, 0, -1))})

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
        if uid in (4, 2, 1):
            return {"uid": uid}
        return None

    _, cursor = _scan_matching_messages(
        client=client,
        mailboxes=["INBOX"],
        criteria=["ALL"],
        limit=3,
        scan_batch_size=3,
        cursor=None,
        signing_key="secret",
        query_hash=query_hash,
        match_builder=build_match,
    )
    # UID 1 is matched on page-boundary and must not produce a cursor to UID 0.
    assert cursor is None
