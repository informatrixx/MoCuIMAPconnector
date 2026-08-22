from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable
from typing import Any, Protocol

from mcp.server.mcpserver import MCPServer

from ..config import Settings
from ..imap_client import ImapClient, build_search_cursor, parse_search_criteria, parse_search_cursor
from ..mail_parser import decode_header_value, extract_summary, message_from_bytes, parse_imap_date
from ..security import PROMPT_INJECTION_WARNING


class _SearchClientProtocol(Protocol):
    def search_uids(
        self,
        mailbox: str,
        criteria: list[str],
        *,
        before_uid: int | None = None,
        limit: int,
    ) -> tuple[list[int], int | None]:
        ...

    def fetch_headers(
        self,
        mailbox: str,
        uid: int,
        *,
        include_all_headers: bool = False,
    ) -> tuple[bytes, str | None]:
        ...

    def list_attachments(self, mailbox: str, uid: int) -> list[Any]:
        ...


def _apply_invoice_match(
    *,
    subject: str,
    from_header: str,
    attachment_filenames: list[str],
    attachment_types: list[str],
    invoice_terms: list[str],
    attachment_terms: list[str],
) -> list[str]:
    matched: list[str] = []
    subject_lower = subject.lower()
    from_lower = from_header.lower()
    for term in invoice_terms:
        lower = term.lower()
        if lower in subject_lower or lower in from_lower:
            matched.append(f"subject:{lower}")
            break

    if any(typ.lower() == "pdf" or typ.lower().endswith("/pdf") for typ in attachment_types):
        matched.append("attachment:pdf")

    for filename in attachment_filenames:
        filename_lower = filename.lower()
        if any(term in filename_lower for term in attachment_terms):
            if "attachment:filename" not in matched:
                matched.append("attachment:filename")
            break
    return matched


def _match_has_attachment_flag(attachments: list[Any], has_attachment: bool | None) -> bool:
    if has_attachment is None:
        return True
    if has_attachment:
        return bool(attachments)
    return not bool(attachments)


def _build_query_hash(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _build_search_hash(
    *,
    mailboxes: list[str] | None,
    date_from: str | None,
    date_to: str | None,
    from_address: str | None,
    to_address: str | None,
    subject: str | None,
    text: str | None,
    has_attachment: bool | None,
    attachment_filename: str | None,
    attachment_extension: str | None,
) -> str:
    return _build_query_hash(
        {
            "mailboxes": sorted(mailboxes or []),
            "date_from": date_from or "",
            "date_to": date_to or "",
            "from_address": from_address or "",
            "to_address": to_address or "",
            "subject": subject or "",
            "text": text or "",
            "has_attachment": has_attachment,
            "attachment_filename": attachment_filename or "",
            "attachment_extension": attachment_extension or "",
            "tool": "search_emails",
        },
    )


def _build_invoice_query_hash(date_from: str | None, date_to: str | None, mailboxes: list[str] | None) -> str:
    return _build_query_hash(
        {
            "date_from": date_from or "",
            "date_to": date_to or "",
            "mailboxes": sorted(mailboxes or []),
            "tool": "find_invoice_candidates",
        },
    )


def _scan_matching_messages(
    *,
    client: _SearchClientProtocol,
    mailboxes: list[str],
    criteria: list[str],
    limit: int,
    scan_batch_size: int,
    cursor: str | None,
    signing_key: str,
    query_hash: str,
    match_builder: Callable[[str, int], dict[str, Any] | None],
) -> tuple[list[dict[str, Any]], str | None]:
    cursor_state = (
        parse_search_cursor(cursor, expected_query_hash=query_hash, signing_key=signing_key) if cursor else None
    )
    cursor_mailbox = cursor_state[0] if cursor_state else None
    cursor_uid = cursor_state[1] if cursor_state else None

    try:
        start_index = mailboxes.index(cursor_mailbox) if cursor_mailbox in mailboxes else 0
    except ValueError:
        start_index = 0
        cursor_uid = None

    if cursor_state and cursor_uid is not None and cursor_mailbox not in mailboxes:
        # ignore cursor for incompatible mailbox sets to avoid surprising reuse.
        cursor_uid = None

    results: list[dict[str, Any]] = []
    next_cursor: str | None = None

    for mailbox in mailboxes[start_index:]:
        current_cursor = cursor_uid if mailbox == cursor_mailbox else None

        while len(results) < limit:
            uids, batch_cursor = client.search_uids(
                mailbox,
                criteria,
                limit=scan_batch_size,
                before_uid=current_cursor,
            )
            if not uids:
                break

            for uid in uids:
                entry = match_builder(mailbox, uid)
                if entry is not None:
                    results.append(entry)
                    if len(results) >= limit:
                        next_uid = uid - 1
                        if next_uid < 1:
                            return results, None
                        next_cursor = build_search_cursor(
                            mailbox,
                            uid=next_uid,
                            query_hash=query_hash,
                            signing_key=signing_key,
                        )
                        return results, next_cursor

            if not batch_cursor:
                break

            current_cursor = batch_cursor
            if current_cursor is None or current_cursor <= 0:
                break

        if len(results) >= limit:
            break

        # move to next mailbox on next run
        cursor_uid = None
        cursor_mailbox = mailbox

    return results, next_cursor


def register_search_tools(server: MCPServer, settings: Settings) -> None:
    logger = logging.getLogger("mocu_imap_mcp.tools")

    @server.tool(
        name="search_emails",
        description=(
            "Durchsucht E-Mails im IMAP mit serverseitiger Suche und gibt nur Header-Metadaten zurück.\n"
            "Keine Mails, Flags oder Labels werden verändert.\n\n"
            f"{PROMPT_INJECTION_WARNING}"
        ),
    )
    def search_emails(
        mailboxes: list[str] | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        from_address: str | None = None,
        to_address: str | None = None,
        subject: str | None = None,
        text: str | None = None,
        has_attachment: bool | None = None,
        attachment_filename: str | None = None,
        attachment_extension: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        limit = max(1, min(limit, settings.max_search_results))

        with ImapClient(settings) as client:
            if not mailboxes:
                mailboxes = [item.name for item in client.list_mailboxes() if item.selectable]

            criteria = parse_search_criteria(
                date_from=date_from,
                date_to=date_to,
                from_address=from_address,
                to_address=to_address,
                subject=subject,
                text=text,
                has_attachment=has_attachment,
            )

            query_hash = _build_search_hash(
                mailboxes=mailboxes,
                date_from=date_from,
                date_to=date_to,
                from_address=from_address,
                to_address=to_address,
                subject=subject,
                text=text,
                has_attachment=has_attachment,
                attachment_filename=attachment_filename,
                attachment_extension=attachment_extension,
            )

            def _match(mailbox: str, uid: int) -> dict[str, Any] | None:
                headers_raw, internal_date = client.fetch_headers(mailbox, uid)
                message = message_from_bytes(headers_raw)
                summary = extract_summary(message, mailbox=mailbox, uid=uid, internal_date=internal_date)
                attachments = client.list_attachments(mailbox, uid)

                attachment_names = [item.filename for item in attachments if item.filename]
                if not _match_has_attachment_flag(attachments, has_attachment):
                    return None
                if attachment_filename:
                    needle = attachment_filename.lower()
                    if not any(name and needle in name.lower() for name in attachment_names):
                        return None
                if attachment_extension:
                    ext = attachment_extension.lower().lstrip(".")
                    if not any(name and name.lower().endswith(f".{ext}") for name in attachment_names):
                        return None

                return {
                    "mailbox": summary.mailbox,
                    "uid": summary.uid,
                    "message_id": summary.message_id,
                    "date": summary.date,
                    "internal_date": summary.internal_date,
                    "from": summary.from_.model_dump(by_alias=True) if summary.from_ else None,
                    "to": [item.model_dump(by_alias=True) for item in summary.to],
                    "subject": summary.subject,
                    "has_attachments": bool(attachments),
                    "attachment_count": len(attachments),
                    "attachment_names": attachment_names,
                }

            items, next_cursor = _scan_matching_messages(
                client=client,
                mailboxes=mailboxes,
                criteria=criteria,
                limit=limit,
                scan_batch_size=max(1, min(settings.search_scan_batch_size, settings.max_search_results)),
                cursor=cursor,
                signing_key=settings.cursor_signing_key,
                query_hash=query_hash,
                match_builder=_match,
            )

        logger.info(
            "tool=search_emails duration=%.3fs count=%s next_cursor=%s",
            time.perf_counter() - start,
            len(items),
            next_cursor,
        )
        return {"items": items, "count": len(items), "next_cursor": next_cursor}

    @server.tool(
        name="find_invoice_candidates",
        description=(
            "Findet wahrscheinliche Rechnungs-/Beleg-E-Mails als Vorfilterung "
            "ohne KI-Klassifikation.\n"
            f"{PROMPT_INJECTION_WARNING}"
        ),
    )
    def find_invoice_candidates(
        date_from: str | None = None,
        date_to: str | None = None,
        mailboxes: list[str] | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        limit = max(1, min(limit, settings.max_search_results))
        invoice_terms = [
            "rechnung",
            "rechnungsnummer",
            "beleg",
            "quittung",
            "gutschrift",
            "zahlungsbeleg",
            "abrechnung",
            "bestellung",
            "invoice",
            "receipt",
            "billing",
            "payment receipt",
            "credit note",
        ]
        attachment_terms = ["rechnung", "invoice", "receipt", "beleg"]

        with ImapClient(settings) as client:
            if not mailboxes:
                mailboxes = [item.name for item in client.list_mailboxes() if item.selectable]

            criteria = parse_search_criteria(date_from=date_from, date_to=date_to)
            query_hash = _build_invoice_query_hash(mailboxes=mailboxes, date_from=date_from, date_to=date_to)

            def _match(mailbox: str, uid: int) -> dict[str, Any] | None:
                headers_raw, _internal_date = client.fetch_headers(mailbox, uid, include_all_headers=True)
                message = message_from_bytes(headers_raw)
                subject = decode_header_value(message.get("Subject"))
                from_header = decode_header_value(message.get("From"))
                attachments = client.list_attachments(mailbox, uid)
                attachment_filenames = [item.filename or "" for item in attachments if item.filename]
                attachment_types = [item.content_type or "" for item in attachments]
                matched_by = _apply_invoice_match(
                    subject=subject or "",
                    from_header=from_header or "",
                    attachment_filenames=attachment_filenames,
                    attachment_types=attachment_types,
                    invoice_terms=invoice_terms,
                    attachment_terms=attachment_terms,
                )
                if not matched_by:
                    return None
                return {
                    "mailbox": mailbox,
                    "uid": uid,
                    "date": parse_imap_date(message.get("Date")),
                    "from": from_header,
                    "subject": subject,
                    "attachments": attachment_filenames,
                    "matched_by": matched_by,
                }

            candidates, next_cursor = _scan_matching_messages(
                client=client,
                mailboxes=mailboxes,
                criteria=criteria,
                limit=limit,
                scan_batch_size=max(1, min(settings.search_scan_batch_size, settings.max_search_results)),
                cursor=cursor,
                signing_key=settings.cursor_signing_key,
                query_hash=query_hash,
                match_builder=_match,
            )

        logger.info(
            "tool=find_invoice_candidates duration=%.3fs count=%s next_cursor=%s",
            time.perf_counter() - start,
            len(candidates),
            next_cursor,
        )
        return {"candidates": candidates, "count": len(candidates), "next_cursor": next_cursor}
