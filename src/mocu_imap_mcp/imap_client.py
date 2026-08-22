from __future__ import annotations

import base64
import contextlib
import imaplib
import json
import logging
import re
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from .bodystructure import iter_attachments_from_bodystructure
from .config import Settings
from .mail_parser import message_from_bytes, parse_internal_imap_date
from .models import AttachmentMeta
from .security import (
    AttachmentNotFoundError,
    AttachmentTooLargeError,
    AuthenticationError,
    ImapConnectionError,
    InvalidSearchParameterError,
    MailboxNotFoundError,
    MessageNotFoundError,
)

logger = logging.getLogger("mocu_imap_mcp.imap")


@dataclass(frozen=True)
class MailboxInfo:
    name: str
    selectable: bool


def _as_text(data: bytes | str) -> str:
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data


def _decode_fetch_payload(data: list[Any]) -> bytes:
    """
    Extract literal payload bytes from IMAP FETCH return data.
    """
    if not data:
        return b""

    merged = b""
    for item in data:
        if isinstance(item, tuple):
            for part in item:
                if isinstance(part, bytes):
                    merged += part
        elif isinstance(item, bytes):
            merged += item

    marker = re.search(rb"\{(\d+)\}\r\n", merged)
    if not marker:
        # fallback for already plain-byte payloads
        return merged

    expected = int(marker.group(1))
    start = marker.end()
    return merged[start : start + expected]


def _parse_list_line(line: str) -> MailboxInfo | None:
    # Example:
    # (\HasNoChildren) "/" "INBOX"
    # (\\Noselect) "." "Trash"
    if not line.startswith("("):
        return None
    flags_end = line.find(")")
    if flags_end == -1:
        return None

    flags_raw = line[1:flags_end].split()
    selectable = not any(flag.lower() == "\\noselect" for flag in flags_raw)

    tail = line[flags_end + 1 :].lstrip()
    # skip delimiter token
    if not tail:
        return None
    if tail[0] == '"':
        match = re.match(r'\"([^\"]*)\"', tail)
        if not match:
            return None
        rest = tail[match.end() :].lstrip()
    else:
        parts = tail.split(maxsplit=1)
        if not parts:
            return None
        rest = parts[1] if len(parts) == 2 else ""
    if not rest:
        return None

    name_token_match = re.match(r'"((?:\\.|[^"])*)"', rest) if rest.startswith('"') else re.match(r"(\S+)", rest)
    if not name_token_match:
        return None
    raw_name = name_token_match.group(1)
    if raw_name == "NIL":
        return None
    try:
        name = raw_name.encode("utf-8").decode("imap4-utf-7")
    except Exception:
        name = unquote(raw_name)
    return MailboxInfo(name=name, selectable=selectable)


def _extract_uids(data: list[Any]) -> list[int]:
    if not data:
        return []
    first = data[0]
    if not isinstance(first, (bytes, str)):
        return []
    text = _as_text(first)
    ids: list[int] = []
    for token in text.split():
        if token.isdigit():
            ids.append(int(token))
    return ids


def build_search_cursor(mailbox: str, next_uid: int | None = None) -> str:
    payload = {"mailbox": mailbox}
    if next_uid is not None:
        payload["uid"] = next_uid
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def parse_search_cursor(cursor: str | None) -> tuple[str, int | None] | None:
    if not cursor:
        return None
    try:
        payload_raw = base64.urlsafe_b64decode(cursor.encode() + b"=").decode()
        payload = json.loads(payload_raw)
        mailbox = payload.get("mailbox")
        if not isinstance(mailbox, str):
            return None
        uid = payload.get("uid")
        return mailbox, int(uid) if uid is not None else None
    except Exception:
        try:
            # legacy support for plain int cursor
            uid = int(cursor)
            return "", uid
        except ValueError:
            return None


def parse_search_criteria(
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    from_address: str | None = None,
    to_address: str | None = None,
    subject: str | None = None,
    text: str | None = None,
    has_attachment: bool | None = None,
) -> list[str]:
    criteria: list[str] = []

    if date_from:
        _validate_date(date_from)
        criteria.extend(["SINCE", _format_imap_date(date_from)])
    if date_to:
        _validate_date(date_to)
        criteria.extend(["BEFORE", _format_imap_date(_next_day(date_to))])

    if from_address:
        criteria.extend(["FROM", _escape_search_term(from_address)])
    if to_address:
        criteria.extend(["TO", _escape_search_term(to_address)])
    if subject:
        criteria.extend(["SUBJECT", _escape_search_term(subject)])
    if text:
        criteria.extend(["TEXT", _escape_search_term(text)])

    if has_attachment:
        # IMAP search does not provide universal attachment operator.
        # Keep for later client-side filtering.
        pass

    if not criteria:
        return ["ALL"]
    return criteria


def _escape_search_term(term: str) -> str:
    return term.replace('"', '\\"')


def _validate_date(value: str) -> None:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise InvalidSearchParameterError("Datumsformat muss YYYY-MM-DD sein")


def _format_imap_date(value: str) -> str:
    _validate_date(value)
    from datetime import datetime

    return datetime.strptime(value, "%Y-%m-%d").strftime("%d-%b-%Y")


def _next_day(value: str) -> str:
    _validate_date(value)
    from datetime import datetime, timedelta

    parsed = datetime.strptime(value, "%Y-%m-%d")
    return (parsed + timedelta(days=1)).strftime("%Y-%m-%d")


class ImapClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        self._selected_mailbox: str | None = None

    def __enter__(self) -> ImapClient:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc: Exception | None, tb: Any) -> None:
        self.disconnect()

    def connect(self) -> None:
        last_error: Exception | None = None
        for _attempt in range(1, self.settings.imap_connection_retries + 1):
            try:
                if self._imap is not None:
                    self._imap.noop()
                    logger.debug("IMAP keepalive NOOP success")
                    return

                if self.settings.imap_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = True
                    self._imap = imaplib.IMAP4_SSL(
                        host=self.settings.imap_host,
                        port=self.settings.imap_port,
                        timeout=self.settings.imap_connection_timeout,
                        ssl_context=context,
                    )
                else:
                    self._imap = imaplib.IMAP4(
                        host=self.settings.imap_host,
                        port=self.settings.imap_port,
                        timeout=self.settings.imap_connection_timeout,
                )

                typ, _response = self._imap.login(self.settings.imap_username, self.settings.imap_password)
                logger.info("IMAP login succeeded host=%s ssl=%s", self.settings.imap_host, self.settings.imap_ssl)
                if typ != "OK":
                    raise AuthenticationError("IMAP-Authentifizierung fehlgeschlagen")
                return
            except Exception as exc:
                last_error = exc
                self._close()
                if _attempt < self.settings.imap_connection_retries:
                    time.sleep(self.settings.imap_retry_delay)
                    continue
                raise ImapConnectionError("IMAP-Verbindung fehlgeschlagen") from last_error

    def disconnect(self) -> None:
        self._close()

    def _close(self) -> None:
        if self._imap is None:
            return
        with contextlib.suppress(Exception):
            self._imap.logout()
        logger.info("IMAP disconnect")
        self._imap = None
        self._selected_mailbox = None

    def _ensure_connection(self) -> None:
        if self._imap is None:
            self.connect()

    def _run(self, action: Callable[[imaplib.IMAP4 | imaplib.IMAP4_SSL], Any]) -> Any:
        last_error: Exception | None = None
        for _attempt in range(1, self.settings.imap_connection_retries + 1):
            try:
                self._ensure_connection()
                assert self._imap is not None
                return action(self._imap)
            except (TimeoutError, OSError, imaplib.IMAP4.abort, imaplib.IMAP4.error) as exc:
                last_error = exc
                self._close()
                if _attempt < self.settings.imap_connection_retries:
                    time.sleep(self.settings.imap_retry_delay)
                    continue
                raise ImapConnectionError("IMAP-Befehl fehlgeschlagen") from last_error

        raise ImapConnectionError("IMAP-Befehl fehlgeschlagen") from last_error

    def list_mailboxes(self) -> list[MailboxInfo]:
        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> list[MailboxInfo]:
            typ, data = client.list()
            if typ != "OK":
                raise ImapConnectionError("Mailbox-Liste kann nicht gelesen werden")

            mailboxes: list[MailboxInfo] = []
            for entry in data or []:
                parsed = _parse_list_line(_as_text(entry))
                if parsed is not None:
                    mailboxes.append(parsed)
            return mailboxes

        return self._run(action)

    def ensure_mailbox(self, mailbox: str) -> None:
        if self._selected_mailbox == mailbox:
            return
        if not mailbox:
            raise MailboxNotFoundError("Mailbox darf nicht leer sein")

        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> None:
            typ, _data = client.select(f'"{mailbox}"' if " " in mailbox else mailbox, readonly=True)
            if typ != "OK":
                raise MailboxNotFoundError(f"Mailbox '{mailbox}' wurde nicht gefunden")
            self._selected_mailbox = mailbox

        self._run(action)

    def search_uids(
        self,
        mailbox: str,
        criteria: list[str],
        *,
        cursor: str | None = None,
        limit: int,
    ) -> tuple[list[int], str | None]:
        if limit <= 0:
            raise InvalidSearchParameterError("limit muss > 0 sein")
        self.ensure_mailbox(mailbox)

        if cursor:
            cursor_state = parse_search_cursor(cursor)
            if cursor_state is not None and cursor_state[1] is not None:
                cursor_uid = cursor_state[1]
                if cursor_uid > 0:
                    criteria = [*criteria, "UID", f"1:{cursor_uid}"]

        if not criteria:
            criteria = ["ALL"]

        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> tuple[list[int], str | None]:
            typ, data = client.uid("search", "UTF-8", *criteria)
            if typ != "OK":
                raise MessageNotFoundError("IMAP SEARCH fehlgeschlagen")
            uids = _extract_uids(data or [])
            uids.sort(reverse=True)
            if not uids:
                return [], None

            selected = uids[:limit]
            next_cursor: str | None = None
            if len(uids) > limit:
                next_cursor = build_search_cursor(mailbox, max(selected[-1] - 1, 0))
            return selected, next_cursor

        return self._run(action)

    def fetch_headers(self, mailbox: str, uid: int, *, include_all_headers: bool = False) -> tuple[bytes, str | None]:
        if uid <= 0:
            raise InvalidSearchParameterError("Ungültige UID")
        self.ensure_mailbox(mailbox)

        fields = "ALL" if include_all_headers else "DATE FROM TO CC SUBJECT MESSAGE-ID"
        query = f"(BODY.PEEK[HEADER.FIELDS ({fields})] INTERNALDATE)"

        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> tuple[bytes, str | None]:
            typ, data = client.uid("fetch", str(uid), query)
            if typ != "OK":
                raise MessageNotFoundError(f"Nachricht {uid} nicht gefunden")
            merged = b""
            for item in data or []:
                if isinstance(item, tuple):
                    for part in item:
                        if isinstance(part, bytes):
                            merged += part
                elif isinstance(item, bytes):
                    merged += item

            if not merged:
                raise MessageNotFoundError(f"Nachricht {uid} ist leer")

            internal = None
            text = merged.decode("utf-8", errors="replace")
            internal_match = re.search(r'INTERNALDATE "([^"]+)"', text)
            if internal_match:
                internal = parse_internal_imap_date(internal_match.group(1))

            payload = _decode_fetch_payload(data or [])
            if not payload:
                return b"", internal

            # remove possible wrapping tokens from literal payloads
            if payload.startswith(b"INTERNALDATE"):
                payload = payload[payload.find(b"\r\n\r\n") + 4 :]
            return payload, internal

        return self._run(action)

    def fetch_full_message(self, mailbox: str, uid: int) -> tuple[bytes, str | None]:
        if uid <= 0:
            raise InvalidSearchParameterError("Ungültige UID")
        self.ensure_mailbox(mailbox)

        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> tuple[bytes, str | None]:
            typ, data = client.uid("fetch", str(uid), "(RFC822 INTERNALDATE)")
            if typ != "OK":
                raise MessageNotFoundError(f"Nachricht {uid} nicht gefunden")
            merged = b""
            for item in data or []:
                if isinstance(item, tuple):
                    for part in item:
                        if isinstance(part, bytes):
                            merged += part
                elif isinstance(item, bytes):
                    merged += item
            if not merged:
                raise MessageNotFoundError(f"Nachricht {uid} ist leer")

            internal = None
            text = merged.decode("utf-8", errors="replace")
            internal_match = re.search(r'INTERNALDATE "([^"]+)"', text)
            if internal_match:
                internal = parse_internal_imap_date(internal_match.group(1))
            payload = _decode_fetch_payload(data or [])
            if not payload:
                # fallback on stripped response
                match = re.search(r"\{(\d+)\}\r\n(.*)", text, re.DOTALL)
                if match:
                    payload = match.group(1).encode()
            if not payload:
                raise MessageNotFoundError(f"Nachricht {uid} ist leer")
            return payload, internal

        return self._run(action)

    def fetch_bodystructure(self, mailbox: str, uid: int) -> tuple[str, str | None]:
        if uid <= 0:
            raise InvalidSearchParameterError("Ungültige UID")
        self.ensure_mailbox(mailbox)

        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> tuple[str, str | None]:
            typ, data = client.uid("fetch", str(uid), "(BODYSTRUCTURE INTERNALDATE)")
            if typ != "OK":
                raise MessageNotFoundError(f"Nachricht {uid} nicht gefunden")

            merged = b""
            for item in data or []:
                if isinstance(item, tuple):
                    for part in item:
                        if isinstance(part, bytes):
                            merged += part
                elif isinstance(item, bytes):
                    merged += item
            if not merged:
                raise MessageNotFoundError(f"Nachricht {uid} ist leer")

            internal = None
            text = merged.decode("utf-8", errors="replace")
            internal_match = re.search(r'INTERNALDATE "([^"]+)"', text)
            if internal_match:
                internal = parse_internal_imap_date(internal_match.group(1))

            payload = _decode_fetch_payload(data or [])
            if not payload:
                raise MessageNotFoundError(f"Nachricht {uid} hat keine BODYSTRUCTURE")
            return payload.decode("utf-8", errors="replace"), internal

        return self._run(action)

    def list_attachments(self, mailbox: str, uid: int) -> list[AttachmentMeta]:
        if uid <= 0:
            raise InvalidSearchParameterError("Ungültige UID")
        bodystructure, _ = self.fetch_bodystructure(mailbox, uid)
        return iter_attachments_from_bodystructure(bodystructure)

    def read_attachment(self, mailbox: str, uid: int, part_id: str) -> bytes:
        if uid <= 0:
            raise InvalidSearchParameterError("Ungültige UID")
        if not re.fullmatch(r"\d+(?:\.\d+)*", part_id):
            raise InvalidSearchParameterError("Ungültige part_id")
        self.ensure_mailbox(mailbox)

        # Validate part and enforce size limit before reading part body
        attachments = self.list_attachments(mailbox, uid)
        matched = next((a for a in attachments if a.part_id == part_id), None)
        if matched is None:
            raise AttachmentNotFoundError(f"Anhang {part_id} nicht gefunden")

        max_bytes = self.settings.max_attachment_size_mb * 1024 * 1024
        if matched.size is not None and matched.size > max_bytes:
            raise AttachmentTooLargeError(f"Anhang zu groß: {matched.size} B")

        full_message, _ = self.fetch_full_message(mailbox, uid)
        message = message_from_bytes(full_message)

        # resolve by part id using email parser
        from .mail_parser import select_attachment_part

        selected = select_attachment_part(message, part_id)
        if selected is None:
            raise AttachmentNotFoundError(f"Anhang {part_id} nicht im Message-Body gefunden")
        part, _ = selected
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = b""
            text_payload = part.get_payload()
            if isinstance(text_payload, str):
                payload = text_payload.encode("utf-8", errors="replace")
            elif isinstance(text_payload, bytes):
                payload = text_payload
        assert isinstance(payload, bytes)
        if len(payload) > max_bytes:
            raise AttachmentTooLargeError(f"Anhang zu groß: {len(payload)} B")
        return payload
