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
from enum import StrEnum
from typing import Any, TypeVar
from urllib.parse import unquote

from .bodystructure import iter_attachments_from_bodystructure
from .config import Settings
from .mail_parser import parse_internal_imap_date
from .models import AttachmentMeta
from .security import (
    AttachmentNotFoundError,
    AttachmentTooLargeError,
    AuthenticationError,
    ImapConnectionError,
    ImapProtocolError,
    InvalidSearchParameterError,
    MailboxNotFoundError,
    MessageNotFoundError,
)

logger = logging.getLogger("mocu_imap_mcp.imap")


_LITERAL_RE = re.compile(rb"\{(\d+)\}\s*$")
_INVALID_SEARCH_CHARS = re.compile(r"[\x00\r\n]")
_INTERNAL_DATE_RE = re.compile(r'INTERNALDATE\s+"([^"]+)"', flags=re.IGNORECASE)
_R = TypeVar("_R")


class RetryCause(StrEnum):
    RETRYABLE = "retryable"
    FATAL = "fatal"


@dataclass(frozen=True)
class MailboxInfo:
    name: str
    selectable: bool


def _as_text(data: bytes | str) -> str:
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data


def _to_bytes(data: bytes | str) -> bytes:
    return data if isinstance(data, bytes) else data.encode("utf-8", errors="replace")


def _safe_text_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def decode_mailbox_name(value: str) -> str:
    if not value:
        return value
    try:
        return value.encode("utf-8").decode("imap4-utf-7")
    except Exception:
        return value


def encode_mailbox_name(value: str) -> str:
    """Encode mailbox names for IMAP folder references."""
    if not value:
        return value
    try:
        # Some Python builds expose utf-7 only as decode-only alias; keep fallback path.
        return value.encode("imap4-utf-7").decode("utf-8")
    except Exception:
        return value


def extract_fetch_metadata(data: list[Any]) -> list[bytes]:
    """Extract plain FETCH metadata blocks from imaplib response tuples."""
    metadata: list[bytes] = []
    for item in data or []:
        if isinstance(item, tuple):
            parts = [_to_bytes(part) for part in item if isinstance(part, (bytes, str))]
            for index, part in enumerate(parts):
                if _LITERAL_RE.search(part) and index + 1 < len(parts):
                    metadata.append(part)
                    continue
                if part.strip() == b")":
                    continue
                metadata.append(part)
            continue

        if isinstance(item, (bytes, str)):
            value = _to_bytes(item)
            if _LITERAL_RE.search(value):
                continue
            if value.strip() not in {b")", b""}:
                metadata.append(value)
    return metadata


def extract_fetch_literals(data: list[Any]) -> list[bytes]:
    """Return all detected literal payload blocks from FETCH data."""
    literals: list[bytes] = []
    for item in data or []:
        if not isinstance(item, tuple):
            continue
        parts = [_to_bytes(part) for part in item if isinstance(part, (bytes, str))]
        for index, part in enumerate(parts):
            marker = _LITERAL_RE.search(part)
            if not marker:
                continue
            if index + 1 >= len(parts):
                continue
            literal = parts[index + 1]
            expected = int(marker.group(1))
            if expected != len(literal):
                logger.debug("extract_fetch_literals size mismatch expected=%s actual=%s", expected, len(literal))
            literals.append(literal)
    return literals


def extract_fetch_literal(data: list[Any]) -> bytes | None:
    literals = extract_fetch_literals(data)
    if not literals:
        return None
    return literals[0]


def extract_internal_date(data: list[Any]) -> str | None:
    for metadata in extract_fetch_metadata(data):
        match = _INTERNAL_DATE_RE.search(_safe_text_decode(metadata))
        if match:
            return parse_internal_imap_date(match.group(1))
    return None


def _parse_list_line(line: str) -> MailboxInfo | None:
    if not line.startswith("("):
        return None
    flags_end = line.find(")")
    if flags_end == -1:
        return None

    flags_raw = line[1:flags_end].split()
    selectable = not any(flag.lower() == "\\noselect" for flag in flags_raw)

    tail = line[flags_end + 1 :].lstrip()
    if not tail:
        return None

    # Skip hierarchy delimiter token
    if tail.startswith('"'):
        match = re.match(r'"([^"]*)"', tail)
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

    name_token_match = re.match(r'"((?:\\.|[^"]*)*)"', rest) if rest.startswith('"') else re.match(r"(\S+)", rest)
    if not name_token_match:
        return None

    raw_name = name_token_match.group(1)
    if raw_name == "NIL":
        return None

    try:
        name = decode_mailbox_name(raw_name)
    except Exception:
        try:
            name = unquote(raw_name)
        except Exception:
            name = raw_name

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


def _quote_imap_string(value: str) -> str:
    if _INVALID_SEARCH_CHARS.search(value):
        raise InvalidSearchParameterError("Suchbegriff enthält ungültige Steuerzeichen")
    return '"' + value.replace("\\", r"\\").replace('"', r"\\\"") + '"'


def build_search_cursor(
    mailbox: str,
    next_uid: int | None = None,
    query_hash: str | None = None,
) -> str:
    payload: dict[str, str | int] = {"v": 1, "mailbox": mailbox}
    if next_uid is not None:
        payload["uid"] = next_uid
    if query_hash:
        payload["q"] = query_hash
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def parse_search_cursor(
    cursor: str | None,
    *,
    expected_query_hash: str | None = None,
) -> tuple[str, int | None] | None:
    if not cursor:
        return None
    try:
        padded = cursor.encode() + b"=" * ((4 - len(cursor) % 4) % 4)
        payload_raw = base64.urlsafe_b64decode(padded).decode()
        payload = json.loads(payload_raw)
        if not isinstance(payload, dict):
            return None
        mailbox = payload.get("mailbox")
        if not isinstance(mailbox, str):
            return None
        if expected_query_hash is not None and payload.get("q") != expected_query_hash:
            return None
        version = payload.get("v", 1)
        if version is not None and version != 1:
            return None
        uid = payload.get("uid")
        return mailbox, int(uid) if uid is not None else None
    except Exception:
        try:
            uid = int(cursor)
            return "", uid
        except ValueError:
            return None


def _needs_utf8_criteria(criteria: list[str]) -> bool:
    return any(any(ord(ch) > 127 for ch in token) for token in criteria if isinstance(token, str))


def _build_uid_search_query(criteria: list[str]) -> tuple[str, ...]:
    normalized = tuple(criteria) if criteria else ("ALL",)
    if normalized == ("ALL",):
        return normalized
    if _needs_utf8_criteria(list(normalized)):
        return ("CHARSET", "UTF-8", *normalized)
    return normalized


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
        criteria.extend(["FROM", _quote_imap_string(from_address)])
    if to_address:
        criteria.extend(["TO", _quote_imap_string(to_address)])
    if subject:
        criteria.extend(["SUBJECT", _quote_imap_string(subject)])
    if text:
        criteria.extend(["TEXT", _quote_imap_string(text)])

    if has_attachment is not None:
        # IMAP has no standard server-side has-attachment operator.
        # Keep this flag for client-side post-filtering.
        pass

    if not criteria:
        return ["ALL"]
    return criteria


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
        for attempt in range(1, self.settings.imap_connection_retries + 1):
            try:
                if self._imap is not None:
                    self._imap.noop()
                    logger.debug("IMAP keepalive NOOP success")
                    return

                if self.settings.imap_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = True
                    context.verify_mode = ssl.CERT_REQUIRED
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
                if attempt < self.settings.imap_connection_retries:
                    time.sleep(self.settings.imap_retry_delay)
                    continue
                if isinstance(exc, imaplib.IMAP4.error):
                    raise ImapProtocolError(str(exc)) from last_error
                if isinstance(exc, (imaplib.IMAP4.abort, imaplib.IMAP4.error)):
                    raise AuthenticationError("IMAP-Authentifizierung fehlgeschlagen") from last_error
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

    def _classify_error(self, error: Exception) -> RetryCause:
        message = str(error)
        if isinstance(error, imaplib.IMAP4.abort):
            return RetryCause.RETRYABLE
        if isinstance(error, (TimeoutError, OSError)):
            return RetryCause.RETRYABLE
        if any(token in message.upper() for token in ("BYE", "CONNECTION", "TIMEOUT", "EOF")):
            return RetryCause.RETRYABLE
        return RetryCause.FATAL

    def _run(self, action: Callable[[imaplib.IMAP4 | imaplib.IMAP4_SSL], _R]) -> _R:
        last_error: Exception | None = None
        for attempt in range(1, self.settings.imap_connection_retries + 1):
            try:
                self._ensure_connection()
                assert self._imap is not None
                return action(self._imap)
            except (TimeoutError, OSError, imaplib.IMAP4.abort) as exc:
                last_error = exc
                if (
                    self._classify_error(exc) is RetryCause.RETRYABLE
                    and attempt < self.settings.imap_connection_retries
                ):
                    self._close()
                    time.sleep(self.settings.imap_retry_delay)
                    continue
                raise ImapConnectionError("IMAP-Befehl fehlgeschlagen") from last_error
            except imaplib.IMAP4.error as exc:
                message = str(exc)
                if "BYE" in message.upper() and attempt < self.settings.imap_connection_retries:
                    self._close()
                    time.sleep(self.settings.imap_retry_delay)
                    continue
                raise ImapProtocolError(message) from exc
            except Exception as exc:
                last_error = exc
                raise ImapConnectionError("IMAP-Befehl fehlgeschlagen") from last_error

        if last_error is not None:
            raise ImapConnectionError("IMAP-Befehl fehlgeschlagen") from last_error
        raise ImapConnectionError("IMAP-Befehl fehlgeschlagen")

    def list_mailboxes(self) -> list[MailboxInfo]:
        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> list[MailboxInfo]:
            typ, data = client.list()
            if typ != "OK":
                raise ImapConnectionError("Mailbox-Liste kann nicht gelesen werden")
            mailboxes: list[MailboxInfo] = []
            for entry in data or []:
                if not isinstance(entry, (bytes, str)):
                    continue
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
            encoded_mailbox = encode_mailbox_name(mailbox)
            typ, _data = client.select(encoded_mailbox, readonly=True)
            if typ != "OK":
                raise MailboxNotFoundError(f"Mailbox '{mailbox}' wurde nicht gefunden")
            self._selected_mailbox = mailbox

        self._run(action)

    def search_uids(
        self,
        mailbox: str,
        criteria: list[str],
        *,
        cursor: str | int | None = None,
        limit: int,
    ) -> tuple[list[int], str | None]:
        if limit <= 0:
            raise InvalidSearchParameterError("limit muss > 0 sein")
        self.ensure_mailbox(mailbox)

        if cursor:
            cursor_state = parse_search_cursor(str(cursor) if isinstance(cursor, int) else cursor)
            if cursor_state is None and isinstance(cursor, int):
                cursor_state = (mailbox, cursor)
            if cursor_state is not None and cursor_state[1] is not None:
                cursor_uid = cursor_state[1]
                if cursor_uid > 0:
                    criteria = [*criteria, "UID", f"1:{cursor_uid}"]

        if not criteria:
            criteria = ["ALL"]

        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> tuple[list[int], str | None]:
            query = _build_uid_search_query(criteria)
            typ, data = client.uid("SEARCH", *query)
            if typ != "OK":
                raise MessageNotFoundError("IMAP SEARCH fehlgeschlagen")
            uids = _extract_uids(data or [])
            uids.sort(reverse=True)
            if not uids:
                return [], None

            selected: list[int] = uids[:limit]
            next_cursor: str | None = None
            if len(uids) > limit:
                next_cursor = build_search_cursor(mailbox, max(selected[-1] - 1, 0))
            return selected, next_cursor

        return self._run(action)

    def _fetch(self, mailbox: str, uid: int, query: str) -> tuple[bytes, str | None]:
        if uid <= 0:
            raise InvalidSearchParameterError("Ungültige UID")
        self.ensure_mailbox(mailbox)

        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> tuple[bytes, str | None]:
            typ, data = client.uid("FETCH", str(uid), query)
            if typ != "OK":
                raise MessageNotFoundError(f"Nachricht {uid} nicht gefunden")
            metadata = extract_fetch_metadata(data or [])
            payload = extract_fetch_literal(data or [])
            if payload is None:
                raise MessageNotFoundError(f"Nachricht {uid} ist leer")
            return payload, extract_internal_date(metadata)

        return self._run(action)

    def fetch_headers(self, mailbox: str, uid: int, *, include_all_headers: bool = False) -> tuple[bytes, str | None]:
        fields = "HEADER" if include_all_headers else "HEADER.FIELDS (DATE FROM TO CC SUBJECT MESSAGE-ID)"
        return self._fetch(mailbox, uid, f"(BODY.PEEK[{fields}] INTERNALDATE)")

    def fetch_full_message(self, mailbox: str, uid: int) -> tuple[bytes, str | None]:
        return self._fetch(mailbox, uid, "(RFC822 INTERNALDATE)")

    def fetch_message_part_mime(self, mailbox: str, uid: int, part_id: str) -> bytes:
        if not part_id:
            raise InvalidSearchParameterError("Ungültige part_id")
        return self._fetch(mailbox, uid, f"(BODY.PEEK[{part_id}.MIME])")[0]

    def fetch_message_part_body(self, mailbox: str, uid: int, part_id: str) -> bytes:
        if not part_id:
            raise InvalidSearchParameterError("Ungültige part_id")
        return self._fetch(mailbox, uid, f"(BODY.PEEK[{part_id}])")[0]

    def fetch_bodystructure(self, mailbox: str, uid: int) -> tuple[str, str | None]:
        payload, internal_date = self._fetch(mailbox, uid, "(BODYSTRUCTURE INTERNALDATE)")
        if not payload:
            raise MessageNotFoundError(f"Nachricht {uid} hat keine BODYSTRUCTURE")
        return payload.decode("utf-8", errors="replace"), internal_date

    def list_attachments(self, mailbox: str, uid: int) -> list[AttachmentMeta]:
        if uid <= 0:
            raise InvalidSearchParameterError("Ungültige UID")
        bodystructure, _ = self.fetch_bodystructure(mailbox, uid)
        return iter_attachments_from_bodystructure(bodystructure)

    def _decode_attachment_bytes(self, raw: bytes, transfer_encoding: str | None) -> bytes:
        encoding = (transfer_encoding or "").upper().strip()
        if encoding == "BASE64":
            return base64.b64decode(raw, validate=False)
        if encoding in {"QUOTED-PRINTABLE", "QPRINTABLE", "QUOTEDPRINTABLE", "QP"}:
            import quopri
            return quopri.decodestring(raw)
        return raw

    def read_attachment(self, mailbox: str, uid: int, part_id: str) -> bytes:
        if uid <= 0:
            raise InvalidSearchParameterError("Ungültige UID")
        if not re.fullmatch(r"\d+(?:\.\d+)*", part_id):
            raise InvalidSearchParameterError("Ungültige part_id")

        attachments = self.list_attachments(mailbox, uid)
        matched = next((a for a in attachments if a.part_id == part_id), None)
        if matched is None:
            raise AttachmentNotFoundError(f"Anhang {part_id} nicht gefunden")

        max_bytes = self.settings.max_attachment_size_mb * 1024 * 1024
        if matched.size is not None and matched.size > max_bytes:
            raise AttachmentTooLargeError(f"Anhang zu groß: {matched.size} B")

        encoded_body = self.fetch_message_part_body(mailbox, uid, part_id)
        if not encoded_body:
            raise AttachmentNotFoundError(f"Anhang {part_id} nicht gefunden")

        decoded = self._decode_attachment_bytes(encoded_body, matched.transfer_encoding)
        if len(decoded) > max_bytes:
            raise AttachmentTooLargeError(f"Anhang zu groß: {len(decoded)} B")
        return decoded
