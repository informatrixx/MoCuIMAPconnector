from __future__ import annotations

import logging
import time
from typing import Any

from mcp.server.mcpserver import MCPServer

from ..config import Settings
from ..imap_client import ImapClient, parse_search_criteria, parse_search_cursor
from ..mail_parser import decode_header_value, extract_summary, message_from_bytes, parse_imap_date
from ..security import PROMPT_INJECTION_WARNING


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

            cursor_state = parse_search_cursor(cursor)
            cursor_mailbox = cursor_state[0] if cursor_state else None
            cursor_uid = cursor_state[1] if cursor_state else None

            criteria = parse_search_criteria(
                date_from=date_from,
                date_to=date_to,
                from_address=from_address,
                to_address=to_address,
                subject=subject,
                text=text,
                has_attachment=has_attachment,
            )

            started = cursor is None or cursor_mailbox is None
            results: list[dict[str, Any]] = []
            next_cursor: str | None = None

            for mailbox in mailboxes:
                if not started and mailbox != cursor_mailbox:
                    continue
                started = True

                mailbox_criteria = list(criteria)
                if cursor_uid and cursor_uid > 0 and mailbox == cursor_mailbox:
                    mailbox_criteria.extend(["UID", f"1:{cursor_uid}"])

                remaining = max(1, limit - len(results))
                uids, local_cursor = client.search_uids(mailbox, mailbox_criteria, limit=remaining, cursor=None)

                for uid in uids:
                    headers_raw, internal_date = client.fetch_headers(mailbox, uid)
                    message = message_from_bytes(headers_raw)
                    summary = extract_summary(message, mailbox=mailbox, uid=uid, internal_date=internal_date)
                    attachments = client.list_attachments(mailbox, uid)

                    attachment_names = [item.filename for item in attachments if item.filename]
                    if has_attachment is True and not attachments:
                        continue
                    if attachment_filename:
                        needle = attachment_filename.lower()
                        if not any(name and needle in name.lower() for name in attachment_names):
                            continue
                    if attachment_extension:
                        ext = attachment_extension.lower().lstrip(".")
                        if not any(name and name.lower().endswith(f".{ext}") for name in attachment_names):
                            continue

                    results.append(
                        {
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
                    )

                    if len(results) >= limit:
                        break

                if len(results) >= limit:
                    if local_cursor:
                        next_cursor = local_cursor
                    break

            logger.info(
                "tool=search_emails duration=%.3fs count=%s next_cursor=%s",
                time.perf_counter() - start,
                len(results),
                next_cursor,
            )
            return {
                "items": results,
                "count": len(results),
                "next_cursor": next_cursor,
            }

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

            cursor_state = parse_search_cursor(cursor)
            cursor_mailbox = cursor_state[0] if cursor_state else None
            cursor_uid = cursor_state[1] if cursor_state else None

            criteria = parse_search_criteria(date_from=date_from, date_to=date_to)

            started = cursor is None or cursor_mailbox is None
            candidates: list[dict[str, Any]] = []
            next_cursor: str | None = None

            for mailbox in mailboxes:
                if not started and mailbox != cursor_mailbox:
                    continue
                started = True

                mailbox_criteria = list(criteria)
                if cursor_uid and cursor_uid > 0 and mailbox == cursor_mailbox:
                    mailbox_criteria.extend(["UID", f"1:{cursor_uid}"])

                uids, local_cursor = client.search_uids(mailbox, mailbox_criteria, limit=limit, cursor=None)

                for uid in uids:
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
                        continue

                    candidates.append(
                        {
                            "mailbox": mailbox,
                            "uid": uid,
                            "date": parse_imap_date(message.get("Date")),
                            "from": from_header,
                            "subject": subject,
                            "attachments": attachment_filenames,
                            "matched_by": matched_by,
                        }
                    )
                    if len(candidates) >= limit:
                        break

                if len(candidates) >= limit:
                    next_cursor = local_cursor
                    break
            logger.info(
                "tool=find_invoice_candidates duration=%.3fs count=%s next_cursor=%s",
                time.perf_counter() - start,
                len(candidates),
                next_cursor,
            )
            return {
                "candidates": candidates,
                "count": len(candidates),
                "next_cursor": next_cursor,
            }
