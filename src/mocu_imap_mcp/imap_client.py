from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import imaplib
import json
import logging
import re
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, TypeVar

from .bodystructure import iter_attachments_from_bodystructure
from .config import Settings, get_settings
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
_INTERNAL_DATE_RE = re.compile(r"INTERNALDATE\s+\"([^\"]+)\"", flags=re.IGNORECASE)
_INVALID_SEARCH_CHARS = re.compile(r"[\x00\r\n]")
_UNSAFE_CURSOR_CHARS = re.compile(r"[^A-Za-z0-9._-]")
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


def _safe_text_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _to_bytes(data: bytes | str) -> bytes:
    return data if isinstance(data, bytes) else data.encode("utf-8", errors="replace")


def _decode_modified_utf7(value: str) -> str:
    """Decode IMAP modified UTF-7 mailbox names without external dependencies."""
    if "&" not in value:
        return value

    output: list[str] = []
    index = 0
    length = len(value)

    while index < length:
        char = value[index]
        if char != "&":
            output.append(char)
            index += 1
            continue

        end = value.find("-", index + 1)
        if end < 0:
            output.append("&")
            break

        token = value[index + 1 : end]
        index = end + 1

        if token == "":
            output.append("&")
            continue

        payload = token.replace(",", "/")
        padded = payload + "=" * ((4 - len(payload) % 4) % 4)
        try:
            decoded = base64.b64decode(padded.encode("ascii"), altchars=None)
            output.append(decoded.decode("utf-16-be"))
        except Exception:
            output.append(value[index - len(token) - 2 : index - 1])

    return "".join(output)


def _encode_modified_utf7(value: str) -> str:
    """Encode IMAP modified UTF-7 mailbox names."""
    output: list[str] = []
    buffer: list[str] = []

    def flush_buffer() -> None:
        if not buffer:
            return
        chunk = "".join(buffer)
        raw = chunk.encode("utf-16-be")
        encoded = base64.b64encode(raw).decode("ascii").rstrip("=")
        output.append("&" + encoded.replace("/", ",") + "-")
        buffer.clear()

    for char in value:
        if char == "&":
            flush_buffer()
            output.append("&-")
            continue
        if 0x20 <= ord(char) <= 0x7E:
            flush_buffer()
            output.append(char)
        else:
            buffer.append(char)

    flush_buffer()
    return "".join(output)


def decode_mailbox_name(value: str) -> str:
    if not value:
        return value
    try:
        return _decode_modified_utf7(value)
    except Exception:
        return value


def encode_mailbox_name(value: str) -> str:
    if not value:
        return value
    try:
        return _encode_modified_utf7(value)
    except Exception:
        return value


def extract_fetch_metadata(data: list[Any]) -> list[bytes]:
    """Extract plain FETCH metadata blocks from imaplib response tuples."""
    metadata: list[bytes] = []
    if not data:
        return metadata

    skip_next = False
    for item_index, item in enumerate(data or []):
        if isinstance(item, tuple):
            parts = [_to_bytes(part) for part in item if isinstance(part, (bytes, str))]
            skip_next_tuple = False
            for part in parts:
                if skip_next_tuple:
                    skip_next_tuple = False
                    continue
                if _LITERAL_RE.search(part):
                    metadata.append(part)
                    skip_next_tuple = True
                    continue
                if part.strip() in {b")", b""}:
                    continue
                metadata.append(part)
            continue

        if isinstance(item, (bytes, str)):
            value = _to_bytes(item)
            if skip_next:
                skip_next = False
                continue
            if _LITERAL_RE.search(value):
                metadata.append(value)
                if _LITERAL_RE.search(value) and item_index + 1 < len(data):
                    next_item = data[item_index + 1]
                    if isinstance(next_item, (bytes, str)):
                        skip_next = True
                continue
            if value.strip() not in {b")", b""}:
                metadata.append(value)
    return metadata


def extract_fetch_literals(data: list[Any]) -> list[bytes]:
    """Return all detected literal payload blocks from FETCH data."""
    literals: list[bytes] = []
    if not data:
        return literals

    for item_index, item in enumerate(data):
        if not isinstance(item, (tuple, bytes, str)):
            continue

        if isinstance(item, tuple):
            parts = [_to_bytes(part) for part in item if isinstance(part, (bytes, str))]
        else:
            parts = [_to_bytes(item)]

        for index, part in enumerate(parts):
            if not _LITERAL_RE.search(part):
                continue

            if isinstance(item, tuple):
                if index + 1 >= len(parts):
                    continue
                literal = parts[index + 1]
            elif item_index + 1 < len(data) and isinstance(data[item_index + 1], (bytes, str)):
                literal = _to_bytes(data[item_index + 1])
            else:
                continue

            expected_match = _LITERAL_RE.search(part)
            expected = int(expected_match.group(1)) if expected_match else len(literal)
            if expected != len(literal):
                logger.debug(
                    "extract_fetch_literals size mismatch expected=%s actual=%s",
                    expected,
                    len(literal),
                )
            literals.append(literal)

    return literals


def extract_fetch_literal(data: list[Any]) -> bytes | None:
    literals = extract_fetch_literals(data)
    if not literals:
        return None
    return literals[0]


def extract_bodystructure_from_fetch(data: list[Any]) -> str | None:
    metadata = extract_fetch_metadata(data)
    if not metadata:
        return None

    joined = b" ".join(metadata).decode("utf-8", errors="replace")
    marker = "BODYSTRUCTURE"
    index = joined.find(marker)
    if index < 0:
        return None

    body = joined[index + len(marker) :]
    bracket_start = body.find("(")
    if bracket_start < 0:
        return None

    start = index + len(marker) + bracket_start
    position = start
    depth = 0
    in_quote = False
    escaped = False

    while position < len(joined):
        char = joined[position]
        if in_quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "\"":
                in_quote = False
        else:
            if char == "\"":
                in_quote = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return joined[start : position + 1].strip()
        position += 1

    return None


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
    if tail.startswith("\""):
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

    name = decode_mailbox_name(raw_name)
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
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_search_cursor(
    mailbox: str,
    *,
    uid: int | None = None,
    query_hash: str,
    signing_key: str | None = None,
) -> str:
    payload = {"v": 2, "mailbox": mailbox, "q": query_hash}
    if uid is not None:
        payload["uid"] = uid
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signing = signing_key or get_settings().cursor_signing_key
    secret = signing.encode("utf-8", errors="replace")
    signature = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    sig = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{token}.{sig}"


def _b64url_decode(payload: str) -> bytes:
    return base64.urlsafe_b64decode(payload + "=" * ((4 - len(payload) % 4) % 4))


def parse_search_cursor(
    cursor: str | None,
    *,
    expected_query_hash: str | None = None,
    expected_mailbox: str | None = None,
    signing_key: str | None = None,
) -> tuple[str, int | None]:
    if not cursor:
        raise InvalidSearchParameterError("Cursor fehlt")

    parts = cursor.split(".")
    if len(parts) != 2:
        raise InvalidSearchParameterError("Ungültiger Cursor")

    payload_raw, signature_raw = parts
    try:
        payload_data = _b64url_decode(payload_raw)
    except Exception as exc:
        raise InvalidSearchParameterError("Ungültiger Cursor") from exc

    try:
        payload = json.loads(payload_data.decode("utf-8"))
    except Exception as exc:
        raise InvalidSearchParameterError("Ungültiger Cursor") from exc

    if not isinstance(payload, dict):
        raise InvalidSearchParameterError("Ungültiger Cursor")

    if payload.get("v") != 2:
        raise InvalidSearchParameterError("Ungültiger Cursor")

    mailbox = payload.get("mailbox")
    if not isinstance(mailbox, str) or not mailbox:
        raise InvalidSearchParameterError("Ungültiger Cursor")
    if expected_mailbox is not None and mailbox != expected_mailbox:
        raise InvalidSearchParameterError("Ungültiger Cursor")

    if expected_query_hash is not None and payload.get("q") != expected_query_hash:
        raise InvalidSearchParameterError("Cursor passt nicht zur aktuellen Suche")

    if payload.get("q") is None:
        raise InvalidSearchParameterError("Cursor enthält keinen Such-Hash")

    signature = _b64url_decode(signature_raw)
    expected = hmac.new(
        (signing_key or get_settings().cursor_signing_key).encode("utf-8", errors="replace"),
        payload_data,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(signature, expected):
        raise InvalidSearchParameterError("Ungültiger Cursor")

    uid = payload.get("uid")
    if uid is None:
        return mailbox, None
    if not isinstance(uid, int):
        raise InvalidSearchParameterError("Ungültiger Cursor")
    if uid < 0:
        raise InvalidSearchParameterError("Ungültiger Cursor")

    return mailbox, uid


def _needs_utf8_criteria(criteria: list[str]) -> bool:
    return any(any(ord(ch) > 127 for ch in token) for token in criteria if isinstance(token, str))


def _build_uid_search_query(criteria: list[str]) -> tuple[str, ...]:
    normalized = tuple(criteria) if criteria else ("ALL",)
    if normalized == ("ALL",):
        return normalized
    if _needs_utf8_criteria(list(normalized)):
        return ("CHARSET", "UTF-8", *normalized)
    return normalized


def _format_imap_date(value: str) -> str:
    _validate_date(value)
    return datetime.strptime(value, "%Y-%m-%d").strftime("%d-%b-%Y")


def _validate_date(value: str) -> None:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise InvalidSearchParameterError("Datumsformat muss YYYY-MM-DD sein")


def _next_day(value: str) -> str:
    _validate_date(value)
    from datetime import timedelta

    parsed = datetime.strptime(value, "%Y-%m-%d")
    return (parsed + timedelta(days=1)).strftime("%Y-%m-%d")


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
        # Keep for post-filtering on the parsed headers/parts.
        pass

    if not criteria:
        return ["ALL"]
    return criteria


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

                password = self.settings.imap_password.get_secret_value()
                typ, _response = self._imap.login(self.settings.imap_username, password)
                if typ != "OK":
                    raise AuthenticationError("IMAP-Authentifizierung fehlgeschlagen")
                logger.info("IMAP login succeeded host=%s ssl=%s", self.settings.imap_host, self.settings.imap_ssl)
                return
            except Exception as exc:
                last_error = exc
                self._close()
                if attempt < self.settings.imap_connection_retries and self._is_retryable_connect_error(exc):
                    time.sleep(self.settings.imap_retry_delay)
                    continue

                if isinstance(exc, AuthenticationError):
                    raise
                if self._is_protocol_error(exc):
                    raise ImapProtocolError(
                        "IMAP-Protokollfehler: AUTH fehlgeschlagen oder Befehl abgelehnt"
                    ) from last_error
                raise ImapConnectionError("IMAP-Verbindung fehlgeschlagen") from last_error

    def _is_retryable_connect_error(self, error: Exception) -> bool:
        if isinstance(error, (imaplib.IMAP4.abort, TimeoutError, OSError)):
            return True
        message = str(error).upper()
        return any(token in message for token in ("CONNECTION", "TIMEOUT", "EOF", "BYE"))

    def _is_protocol_error(self, error: Exception) -> bool:
        if isinstance(error, imaplib.IMAP4.error):
            message = str(error).upper()
            return any(
                token in message
                for token in ("NO", "AUTHENTICATION", "BAD", "AUTH FAILED", "AUTHENTICATIONFAILED", "LOGIN")
            )
        return False

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
        message = str(error).upper()
        if isinstance(error, (TimeoutError, OSError, imaplib.IMAP4.abort)):
            return RetryCause.RETRYABLE
        if isinstance(error, imaplib.IMAP4.error) and "BYE" in message:
            return RetryCause.RETRYABLE
        if "CONNECTION" in message or "TIMEOUT" in message or "EOF" in message:
            return RetryCause.RETRYABLE
        return RetryCause.FATAL

    def _select_mailbox_no_retry(self, mailbox: str) -> None:
        if self._imap is None:
            raise ImapProtocolError("No IMAP connection for mailbox select")
        encoded_mailbox = encode_mailbox_name(mailbox)
        typ, _data = self._imap.select(encoded_mailbox, readonly=True)
        if typ != "OK":
            raise MailboxNotFoundError(f"Mailbox '{mailbox}' wurde nicht gefunden")
        self._selected_mailbox = mailbox

    def _run(
        self,
        action: Callable[[imaplib.IMAP4 | imaplib.IMAP4_SSL], _R],
        *,
        mailbox: str | None = None,
    ) -> _R:
        last_error: Exception | None = None
        for attempt in range(1, self.settings.imap_connection_retries + 1):
            try:
                self._ensure_connection()
                if self._imap is None:
                    raise ImapConnectionError("IMAP-Verbindung nicht aktiv")

                if mailbox and self._selected_mailbox != mailbox:
                    self._select_mailbox_no_retry(mailbox)

                return action(self._imap)
            except (TimeoutError, OSError, imaplib.IMAP4.abort) as exc:
                last_error = exc
                cause = self._classify_error(exc)
                if cause is RetryCause.RETRYABLE and attempt < self.settings.imap_connection_retries:
                    self._close()
                    time.sleep(self.settings.imap_retry_delay)
                    continue
                raise ImapConnectionError("IMAP-Befehl fehlgeschlagen") from last_error
            except imaplib.IMAP4.error as exc:
                last_error = exc
                if (
                    self._classify_error(exc) is RetryCause.RETRYABLE
                    and attempt < self.settings.imap_connection_retries
                ):
                    self._close()
                    time.sleep(self.settings.imap_retry_delay)
                    continue
                raise ImapProtocolError(str(exc)) from exc
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
        self._run(lambda _client: self._select_mailbox_no_retry(mailbox), mailbox=mailbox)

    def search_uids(
        self,
        mailbox: str,
        criteria: list[str],
        *,
        before_uid: int | None = None,
        limit: int,
    ) -> tuple[list[int], int | None]:
        if limit <= 0:
            raise InvalidSearchParameterError("limit muss > 0 sein")

        self.ensure_mailbox(mailbox)

        if before_uid is not None and before_uid > 0:
            criteria = [*criteria, "UID", f"1:{before_uid}"]

        if not criteria:
            criteria = ["ALL"]

        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> tuple[list[int], int | None]:
            query = _build_uid_search_query(criteria)
            typ, data = client.uid("SEARCH", *query)
            if typ != "OK":
                raise ImapProtocolError("IMAP SEARCH fehlgeschlagen")
            uids = _extract_uids(data or [])
            uids.sort(reverse=True)
            if not uids:
                return [], None

            selected = uids[:limit]
            next_before_uid = selected[-1] - 1 if selected else None
            return selected, next_before_uid

        return self._run(action, mailbox=mailbox)

    def _fetch(
        self,
        mailbox: str,
        uid: int,
        query: str,
        *,
        expect_literal: bool = True,
    ) -> tuple[bytes | None, str | None]:
        if uid <= 0:
            raise InvalidSearchParameterError("Ungültige UID")
        self.ensure_mailbox(mailbox)

        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> tuple[bytes | None, str | None]:
            typ, data = client.uid("FETCH", str(uid), query)
            if typ != "OK":
                raise MessageNotFoundError(f"Nachricht {uid} nicht gefunden")
            metadata = extract_fetch_metadata(data or [])
            payload: bytes | None = extract_fetch_literal(data or []) if expect_literal else None
            if expect_literal and payload is None:
                raise MessageNotFoundError(f"Nachricht {uid} ist leer")
            return payload, extract_internal_date(metadata)

        return self._run(action, mailbox=mailbox)

    def fetch_headers(self, mailbox: str, uid: int, *, include_all_headers: bool = False) -> tuple[bytes, str | None]:
        fields = "HEADER" if include_all_headers else "HEADER.FIELDS (DATE FROM TO CC SUBJECT MESSAGE-ID)"
        payload, internal_date = self._fetch(mailbox, uid, f"(BODY.PEEK[{fields}] INTERNALDATE)")
        if payload is None:
            raise MessageNotFoundError(f"Nachricht {uid} hat keinen Header")
        return payload, internal_date

    def fetch_full_message(self, mailbox: str, uid: int) -> tuple[bytes, str | None]:
        payload, internal_date = self._fetch(mailbox, uid, "(RFC822 INTERNALDATE)")
        if payload is None:
            raise MessageNotFoundError(f"Nachricht {uid} hat keinen Inhalt")
        return payload, internal_date

    def fetch_message_part_mime(self, mailbox: str, uid: int, part_id: str) -> bytes:
        if not part_id:
            raise InvalidSearchParameterError("Ungültige part_id")
        payload, _ = self._fetch(mailbox, uid, f"(BODY.PEEK[{part_id}.MIME])")
        if payload is None:
            raise MessageNotFoundError(f"Teil {part_id} nicht gefunden")
        return payload

    def fetch_message_part_body(self, mailbox: str, uid: int, part_id: str) -> bytes:
        if not part_id:
            raise InvalidSearchParameterError("Ungültige part_id")
        payload, _ = self._fetch(mailbox, uid, f"(BODY.PEEK[{part_id}])")
        if payload is None:
            raise MessageNotFoundError(f"Teil {part_id} nicht gefunden")
        return payload

    def fetch_bodystructure(self, mailbox: str, uid: int) -> tuple[str, str | None]:
        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> tuple[str, str | None]:
            typ, data = client.uid("FETCH", str(uid), "(BODYSTRUCTURE INTERNALDATE)")
            if typ != "OK":
                raise MessageNotFoundError(f"Nachricht {uid} hat keine BODYSTRUCTURE")
            metadata = extract_bodystructure_from_fetch(data or [])
            if metadata is None:
                raise MessageNotFoundError(f"Nachricht {uid} hat keine BODYSTRUCTURE")
            internal_date = extract_internal_date(data or [])
            return metadata, internal_date

        return self._run(action, mailbox=mailbox)

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


__all__ = [
    "ImapClient",
    "_build_uid_search_query",
    "_format_imap_date",
    "_next_day",
    "_quote_imap_string",
    "build_search_cursor",
    "decode_mailbox_name",
    "encode_mailbox_name",
    "extract_bodystructure_from_fetch",
    "extract_fetch_literal",
    "extract_fetch_literals",
    "extract_fetch_metadata",
    "extract_internal_date",
    "parse_search_criteria",
    "parse_search_cursor",
]
