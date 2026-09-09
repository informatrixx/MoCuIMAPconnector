from __future__ import annotations

import time
from typing import Any

from .account_cursor import decode_cursor, encode_cursor, fingerprint
from .accounts import AccountError
from .imap_client import parse_search_criteria
from .mail_parser import extract_summary, message_from_bytes
from .runtime import Runtime
from .tools.search import _apply_invoice_match, canonicalize_mailboxes

_TERMS = ["rechnung", "rechnungsnummer", "beleg", "quittung", "gutschrift", "zahlungsbeleg",
          "abrechnung", "bestellung", "invoice", "receipt", "billing", "payment receipt", "credit note"]


def search(runtime: Runtime, *, account_ids: list[str] | None = None, mailboxes: list[str] | None = None,
           date_from: str | None = None, date_to: str | None = None, from_address: str | None = None,
           to_address: str | None = None, subject: str | None = None, text: str | None = None,
           has_attachment: bool | None = None, attachment_filename: str | None = None,
           attachment_extension: str | None = None, limit: int = 50, cursor: str | None = None,
           invoices: bool = False) -> dict[str, Any]:
    if not 1 <= limit <= 100 or account_ids == [] or mailboxes == []:
        raise AccountError("Limit oder Auswahl ungueltig")
    if date_from and date_to and date_from > date_to:
        raise AccountError("Datumsbereich ungueltig")
    accounts = [a for a in runtime.store.list() if a.enabled]
    if account_ids is not None:
        requested = set(account_ids)
        if not requested.issubset({a.id for a in accounts}):
            raise AccountError("Konto unbekannt oder deaktiviert")
        accounts = [a for a in accounts if a.id in requested]
    criteria = parse_search_criteria(date_from=date_from, date_to=date_to, from_address=from_address,
                                    to_address=to_address, subject=subject, text=text)
    selected = canonicalize_mailboxes(mailboxes)
    query = fingerprint([[(a.id, a.revision) for a in accounts], selected, criteria, invoices,
                         has_attachment, attachment_filename, attachment_extension])
    state = decode_cursor(cursor, runtime.store.vault.cursor_key, query) if cursor else {}
    start = state.get("position", 0)
    before = state.get("before")
    validity = state.get("validity")
    rows: list[dict[str, Any]] = []
    locations: list[tuple[str, str]] = []
    # Establish a stable account/mailbox plan without downloading message content.
    for account in accounts:
        with runtime.client(account.id) as client:
            available = sorted(m.name for m in client.list_mailboxes() if m.selectable)
            if selected and not set(selected).issubset(available):
                raise AccountError("Ausgewaehlte Mailbox fehlt")
            locations.extend((account.id, m) for m in (selected or available))
    plan = fingerprint(locations)
    if cursor and state.get("plan") != plan:
        raise AccountError("Mailbox-Auswahl geaendert; Suche neu starten")
    if type(start) is not int or start < 0 or (cursor and start >= len(locations)):
        raise AccountError("Cursor-Position ungueltig")
    if before is not None and (type(before) is not int or before < 1):
        raise AccountError("Cursor-UID ungueltig")
    scanned = 0
    deadline = time.monotonic() + runtime.settings.search_time_budget

    def finish(position: int, next_uid: int | None, uidvalidity: int | None,
               exhausted: bool) -> dict[str, Any]:
        next_cursor = None
        if position < len(locations):
            next_cursor = encode_cursor({"q": query, "plan": plan, "position": position,
                                         "before": next_uid, "validity": uidvalidity}, runtime.store.vault.cursor_key)
        return {"candidates" if invoices else "items": rows, "count": len(rows),
                "next_cursor": next_cursor, "scan_budget_exhausted": exhausted}

    for position in range(start, len(locations)):
        account_id, mailbox = locations[position]
        with runtime.client(account_id) as client:
            current_validity = client.pin_mailbox(mailbox, validity if position == start else None)
            upper = before if position == start else None
            while True:
                uids, next_batch = client.search_uids(mailbox, criteria, before_uid=upper, limit=100)
                if not uids:
                    if next_batch is None:
                        break
                    scanned += 100
                    if scanned >= runtime.settings.search_scan_budget or time.monotonic() >= deadline:
                        return finish(position, next_batch, current_validity, True)
                    upper = next_batch
                    continue
                for offset, uid in enumerate(uids):
                    headers, internal_date = client.fetch_headers(mailbox, uid)
                    summary = extract_summary(message_from_bytes(headers), mailbox=mailbox, uid=uid,
                                              internal_date=internal_date)
                    attachments = client.list_attachments(mailbox, uid)
                    names = [a.filename for a in attachments if a.filename]
                    matched = _apply_invoice_match(subject=summary.subject or "", from_header="",
                                                   attachment_filenames=names,
                                                   attachment_types=[a.content_type for a in attachments],
                                                   invoice_terms=_TERMS, attachment_terms=_TERMS)
                    keep = has_attachment is None or bool(attachments) == has_attachment
                    if attachment_filename:
                        keep = keep and any(attachment_filename.casefold() in n.casefold() for n in names)
                    if attachment_extension:
                        keep = keep and any(n.casefold().endswith("." + attachment_extension.lstrip(".").casefold())
                                            for n in names)
                    if keep and (not invoices or matched):
                        row = summary.model_dump(mode="json", by_alias=True)
                        row.update(account_id=account_id, account_name=runtime.store.get(account_id).display_name,
                                   uidvalidity=current_validity, has_attachments=bool(attachments),
                                   attachment_count=len(attachments), attachment_names=names)
                        if invoices:
                            row.update(matched_by=matched, attachments=names)
                        rows.append(row)
                    scanned += 1
                    exhausted = scanned >= runtime.settings.search_scan_budget or time.monotonic() >= deadline
                    if len(rows) == limit or exhausted:
                        if uid > 1 and (offset + 1 < len(uids) or next_batch is not None):
                            return finish(position, uid - 1, current_validity, exhausted)
                        return finish(position + 1, None, None, exhausted)
                if next_batch is None:
                    break
                upper = next_batch
    return finish(len(locations), None, None, False)
