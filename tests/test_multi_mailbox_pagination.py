from __future__ import annotations

from mocu_imap_mcp.imap_client import parse_search_cursor
from mocu_imap_mcp.tools.search import (
    _build_search_hash,
    _scan_matching_messages,
    canonicalize_mailboxes,
)

_TEST_KEY = bytes.fromhex(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)


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
        next_cursor = batch[-1] - 1 if len(uids) > limit and batch else None
        return batch, next_cursor

    def fetch_headers(self, _mailbox: str, uid: int, *, include_all_headers: bool = False) -> tuple[bytes, str | None]:
        return f"Subject: {uid}\r\n\r\n".encode(), None

    def list_attachments(self, _mailbox: str, _uid: int) -> list[object]:
        return []


def _match(_mailbox: str, uid: int) -> dict[str, object] | None:
    return {"mailbox": _mailbox, "uid": uid}


def test_cursor_advances_to_next_mailbox_when_uid_one_is_last_on_page() -> None:
    client = _FakeImapClient({"A": [2, 1], "B": [50, 40, 30]})
    query_hash = _build_search_hash(
        mailboxes=canonicalize_mailboxes(["A", "B"]),
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

    results, cursor = _scan_matching_messages(
        client=client,
        mailboxes=canonicalize_mailboxes(["A", "B"]),
        criteria=["ALL"],
        limit=2,
        scan_batch_size=2,
        cursor=None,
        signing_key=_TEST_KEY,
        query_hash=query_hash,
        match_builder=_match,
    )
    assert [(item["mailbox"], item["uid"]) for item in results] == [("A", 2), ("A", 1)]
    assert cursor is not None
    state = parse_search_cursor(cursor, expected_query_hash=query_hash, signing_key=_TEST_KEY)
    assert state.mailbox_index == 1
    assert state.mailbox == "B"
    assert state.before_uid is None


def test_sparse_hits_and_duplicate_free_pagination() -> None:
    client = _FakeImapClient({"INBOX": list(range(500, 0, -1))})
    query_hash = _build_search_hash(
        mailboxes=canonicalize_mailboxes(["INBOX"]),
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

    def match_mailbox(mailbox: str, uid: int) -> dict[str, object] | None:
        if uid % 20 != 0:
            return None
        return {"mailbox": mailbox, "uid": uid}

    all_hits: set[int] = set()
    cursor: str | None = None
    while True:
        page, next_cursor = _scan_matching_messages(
            client=client,
            mailboxes=canonicalize_mailboxes(["INBOX"]),
            criteria=["ALL"],
            limit=10,
            scan_batch_size=10,
            cursor=cursor,
            signing_key=_TEST_KEY,
            query_hash=query_hash,
            match_builder=match_mailbox,
        )
        uids = [int(item["uid"]) for item in page]
        assert len(uids) == len(set(uids))
        all_hits.update(uids)
        if next_cursor is None:
            break
        cursor = next_cursor

    assert all_hits == {uid for uid in range(20, 501, 20)}


def test_canonicalized_mailbox_order_is_deterministic() -> None:
    ordered = canonicalize_mailboxes(["Archive", "INBOX"])
    ordered_reverse = canonicalize_mailboxes(["INBOX", "Archive"])
    assert ordered == ordered_reverse == ["Archive", "INBOX"]
