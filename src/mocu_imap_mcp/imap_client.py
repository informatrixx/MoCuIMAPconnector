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
    MessageTooLargeError,
)

logger = logging.getLogger("mocu_imap_mcp.imap")

_IMAP_ERROR = imaplib.IMAP4.error
_IMAP_ABORT = imaplib.IMAP4.abort


_LITERAL_RE = re.compile(rb"\{(\d+)\}")
_INTERNAL_DATE_RE = re.compile(r"INTERNALDATE\s+\"([^\"]+)\"", flags=re.IGNORECASE)
_INVALID_SEARCH_CHARS = re.compile(r"[\x00\r\n]")
_R = TypeVar("_R")


class RetryCause(StrEnum):
    RETRYABLE = "retryable"
    FATAL = "fatal"


@dataclass(frozen=True)
class MailboxInfo:
    name: str
    selectable: bool


@dataclass(frozen=True)
class SearchCursorState:
    version: int
    mailbox_index: int
    mailbox: str
    before_uid: int | None
    query_hash: str


@dataclass(frozen=True)
class FetchLiteral:
    marker: bytes
    data: bytes


@dataclass(frozen=True)
class FetchResponse:
    metadata_parts: list[bytes]
    literals: list[FetchLiteral]


def _as_text(data: bytes | str) -> str:
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data


def _safe_text_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _to_bytes(data: bytes | str) -> bytes:
    return data if isinstance(data, bytes) else data.encode("utf-8", errors="replace")


def _to_imap_arg(value: str | bytes) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _find_unquoted_literal_marker(data: bytes, start: int) -> re.Match[bytes] | None:
    """Find an IMAP literal marker while respecting quoted IMAP strings."""
    in_quote = False
    escaped = False
    cursor = start
    while cursor < len(data):
        char = data[cursor]
        if in_quote:
            if escaped:
                escaped = False
            elif char == 0x5C:  # backslash
                escaped = True
            elif char == 0x22:  # quote
                in_quote = False
            cursor += 1
            continue

        if char == 0x22:  # quote
            in_quote = True
            cursor += 1
            continue
        if char == 0x7B:  # {
            match = _LITERAL_RE.match(data, cursor)
            if match is not None:
                return match
        cursor += 1
    return None


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


def parse_fetch_response(data: list[Any]) -> FetchResponse:
    """Split a low-level IMAP FETCH response in metadata and literal payloads."""
    metadata: list[bytes] = []
    literals: list[FetchLiteral] = []

    if not data:
        return FetchResponse(metadata_parts=metadata, literals=literals)

    parts: list[bytes] = []
    for item in data:
        if isinstance(item, tuple):
            parts.extend([_to_bytes(part) for part in item if isinstance(part, (bytes, str))])
        elif isinstance(item, (bytes, str)):
            parts.append(_to_bytes(item))

    index = 0
    total_parts = len(parts)
    while index < len(parts):
        current = parts[index]
        cursor = 0
        if not current:
            index += 1
            continue

        while cursor < len(current):
            match = _find_unquoted_literal_marker(current, cursor)
            if match is None:
                metadata.append(current[cursor:])
                cursor = len(current)
                break

            match_start = match.start()
            match_end = match.end()
            metadata.append(current[cursor:match_start])
            metadata.append(match.group(0))

            size = int(match.group(1))
            literal_start = match_end
            if current[literal_start : literal_start + 2] == b"\r\n":
                literal_start += 2

            if literal_start + size <= len(current):
                literals.append(FetchLiteral(match.group(0), current[literal_start : literal_start + size]))
                cursor = literal_start + size
                continue

            if index + 1 >= total_parts:
                metadata.append(current[match_end:])
                cursor = len(current)
                break

            index += 1
            literals.append(FetchLiteral(match.group(0), parts[index]))
            cursor = len(current)

        if cursor < len(current):
            metadata.append(current[cursor:])
        index += 1

    metadata = [item for item in metadata if item not in {b"", b" ", b")", b" \r", b"\r", b"\n", b"\r\n"}]
    return FetchResponse(metadata_parts=metadata, literals=literals)


def extract_fetch_metadata(data: list[Any]) -> list[bytes]:
    """Extract plain FETCH metadata blocks (without literal payloads)."""
    return parse_fetch_response(data).metadata_parts


def extract_fetch_literals(data: list[Any]) -> list[bytes]:
    """Return all detected literal payload blocks from FETCH data."""
    return [entry.data for entry in parse_fetch_response(data).literals]


def extract_fetch_literal(data: list[Any]) -> bytes | None:
    literals = parse_fetch_response(data).literals
    if not literals:
        return None
    return literals[0].data


def _consume_fetch_structure_literal(
    data: bytes,
    start: int,
    literals: list[FetchLiteral],
) -> tuple[bytes, int]:
    if start >= len(data) or data[start : start + 1] != b"{":
        return b"{", start
    match = _LITERAL_RE.match(data[start:])
    if match is None:
        return b"{", start + 1
    expected = int(match.group(1))
    end = start + match.end()
    if data[end : end + 2] == b"\r\n":
        end += 2

    payload = b""
    if literals:
        literal_entry = literals.pop(0)
        payload = literal_entry.data
    else:
        payload = b""
    if expected != len(payload):
        logger.debug(
            "fetch bodystructure literal size mismatch expected=%s actual=%s marker=%s",
            expected,
            len(payload),
            match.group(0),
        )
    return payload, end


def _read_bodystructure_bytes(
    source: bytes,
    start: int,
    literals: list[FetchLiteral],
) -> bytes | None:
    if start >= len(source):
        return None
    if source[start] != ord("("):
        return None

    depth = 0
    in_quote = False
    escaped = False
    cursor = start
    out = bytearray()

    while cursor < len(source):
        char = source[cursor]
        if in_quote:
            out.append(char)
            if escaped:
                escaped = False
            elif char == 0x5C:  # backslash
                escaped = True
            elif char == 0x22:
                in_quote = False
            cursor += 1
            continue

        if char == 0x22:  # quote
            in_quote = True
            out.append(char)
            cursor += 1
            continue

        if char == 0x28:  # (
            depth += 1
            out.append(char)
            cursor += 1
            continue

        if char == 0x29:  # )
            out.append(char)
            depth -= 1
            if depth == 0:
                return bytes(out)
            cursor += 1
            continue

        if char == 0x7B:  # {
            value, next_cursor = _consume_fetch_structure_literal(source, cursor, literals)
            if next_cursor <= cursor:
                return None
            if next_cursor == cursor + 1 and value == b"{":
                out.append(char)
                cursor += 1
                continue
            # Keep literals syntactically intact. Inserting their bytes verbatim
            # would make parentheses and quotes in a filename look like IMAP
            # BODYSTRUCTURE syntax to the downstream tokenizer.
            out.extend(b"{" + str(len(value)).encode("ascii") + b"}\r\n" + value)
            cursor = next_cursor
            continue

        out.append(char)
        cursor += 1

    return None


def extract_bodystructure_bytes_from_fetch(data: list[Any]) -> bytes | None:
    response = parse_fetch_response(data)
    if not response.metadata_parts:
        return None

    joined = b" ".join(response.metadata_parts)
    marker_match = re.search(rb"\bBODYSTRUCTURE\b", joined, flags=re.IGNORECASE)
    if marker_match is None:
        return None

    cursor = marker_match.end()
    while cursor < len(joined) and chr(joined[cursor]).isspace():
        cursor += 1
    if cursor >= len(joined):
        return None

    if joined[cursor] == ord("{"):
        literals = response.literals.copy()
        body, next_cursor = _consume_fetch_structure_literal(joined, cursor, literals)
        if not body and not next_cursor:
            return None
        return body

    if joined[cursor] != ord("("):
        return None

    literals = response.literals.copy()
    return _read_bodystructure_bytes(joined, cursor, literals)


def extract_bodystructure_from_fetch(data: list[Any]) -> str | None:
    body_bytes = extract_bodystructure_bytes_from_fetch(data)
    if body_bytes is None:
        return None
    return body_bytes.decode("utf-8", errors="replace")


def extract_internal_date(data: list[Any]) -> str | None:
    metadata = parse_fetch_response(data).metadata_parts
    if not metadata:
        return None
    joined = b" ".join(metadata)
    match = _INTERNAL_DATE_RE.search(_safe_text_decode(joined))
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
    state: SearchCursorState,
    *,
    signing_key: bytes,
) -> str:
    if not isinstance(signing_key, (bytes, bytearray)):
        raise ValueError("signing_key muss Bytes sein.")
    if len(bytes(signing_key)) < 32:
        raise ValueError("signing_key muss mindestens 32 Bytes haben.")
    payload = {
        "v": state.version,
        "mailbox_index": state.mailbox_index,
        "mailbox": state.mailbox,
        "before_uid": state.before_uid,
        "q": state.query_hash,
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(bytes(signing_key), payload_bytes, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    sig = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{token}.{sig}"


def _b64url_decode(payload: str) -> bytes:
    return base64.urlsafe_b64decode(payload + "=" * ((4 - len(payload) % 4) % 4))


def parse_search_cursor(
    cursor: str | None,
    *,
    expected_query_hash: str,
    signing_key: bytes,
    expected_mailbox_count: int | None = None,
    expected_mailbox: str | None = None,
) -> SearchCursorState:

    if not cursor:
        raise InvalidSearchParameterError("Cursor fehlt")

    parts = cursor.split(".")
    if len(parts) != 2:
        raise InvalidSearchParameterError("Ungültiger Cursor")

    key = bytes(signing_key) if isinstance(signing_key, (bytes, bytearray)) else None
    if key is None:
        raise InvalidSearchParameterError("Ungültiger Cursor-Signaturschlüssel")
    if len(key) < 32:
        raise InvalidSearchParameterError("Ungültiger Cursor-Signaturschlüssel")

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

    if payload.get("v") != 3:
        raise InvalidSearchParameterError("Ungültiger Cursor")

    mailbox_index = payload.get("mailbox_index")
    if not isinstance(mailbox_index, int) or mailbox_index < 0:
        raise InvalidSearchParameterError("Ungültiger Cursor")

    mailbox = payload.get("mailbox")
    if not isinstance(mailbox, str) or not mailbox:
        raise InvalidSearchParameterError("Ungültiger Cursor")
    if expected_mailbox is not None and mailbox != expected_mailbox:
        raise InvalidSearchParameterError("Ungültiger Cursor")

    if expected_mailbox_count is not None and mailbox_index >= expected_mailbox_count:
        raise InvalidSearchParameterError("Ungültiger Cursor")

    if payload.get("q") != expected_query_hash:
        raise InvalidSearchParameterError("Cursor passt nicht zur aktuellen Suche")

    if payload.get("q") is None:
        raise InvalidSearchParameterError("Cursor enthält keinen Such-Hash")

    signature = _b64url_decode(signature_raw)
    expected = hmac.new(
        key,
        payload_data,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(signature, expected):
        raise InvalidSearchParameterError("Ungültiger Cursor")

    before_uid = payload.get("before_uid")
    if before_uid is None:
        before_uid_value: int | None = None
    elif not isinstance(before_uid, int) or before_uid < 1:
        raise InvalidSearchParameterError("Ungültiger Cursor")

    else:
        before_uid_value = before_uid

    return SearchCursorState(
        version=3,
        mailbox_index=mailbox_index,
        mailbox=mailbox,
        before_uid=before_uid_value,
        query_hash=expected_query_hash,
    )


def _needs_utf8_criteria(criteria: list[str | bytes]) -> bool:
    for token in criteria:
        if isinstance(token, str):
            if any(ord(ch) > 127 for ch in token):
                return True
            continue
        if isinstance(token, bytes) and any(byte > 127 for byte in token):
            return True
    return False


def _build_uid_search_query(criteria: list[str]) -> tuple[str | bytes, ...]:
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

                port = self.settings.imap_port
                if self.settings.imap_tls_mode == "starttls" and port == 993:
                    port = 143

                context = ssl.create_default_context()
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED

                if self.settings.imap_tls_mode == "ssl":
                    self._imap = imaplib.IMAP4_SSL(
                        self.settings.imap_host,
                        port,
                        timeout=self.settings.imap_connection_timeout,
                        ssl_context=context,
                    )
                elif self.settings.imap_tls_mode == "starttls":
                    self._imap = imaplib.IMAP4(
                        self.settings.imap_host,
                        port,
                        timeout=self.settings.imap_connection_timeout,
                    )
                    typ, capabilities = self._imap.capability()
                    if typ != "OK":
                        raise ImapProtocolError("IMAP CAPABILITY fehlgeschlagen")
                    combined = b" ".join(capabilities or [])
                    if b"STARTTLS" not in combined.upper():
                        raise ImapProtocolError("STARTTLS wird vom Server nicht unterstützt")
                    if not hasattr(self._imap, "starttls"):
                        raise ImapProtocolError("STARTTLS wird vom Server nicht unterstützt")
                    typ, _ = self._imap.starttls(context)
                    if typ != "OK":
                        raise ImapProtocolError("STARTTLS konnte nicht durchgeführt werden")
                    typ, _ = self._imap.capability()
                    if typ != "OK":
                        raise ImapProtocolError("IMAP CAPABILITY nach STARTTLS fehlgeschlagen")

                password = self.settings.imap_password.get_secret_value()
                try:
                    typ, _ = self._imap.login(self.settings.imap_username, password)
                except _IMAP_ABORT:
                    raise
                except _IMAP_ERROR as exc:
                    raise AuthenticationError("IMAP-Authentifizierung fehlgeschlagen") from exc
                if typ != "OK":
                    raise AuthenticationError("IMAP-Authentifizierung fehlgeschlagen")
                logger.info(
                    "IMAP login succeeded host=%s tls=%s",
                    self.settings.imap_host,
                    self.settings.imap_tls_mode,
                )
                return
            except _IMAP_ERROR as exc:
                if "AUTHENTICATION" in str(exc).upper() or "LOGIN" in str(exc).upper():
                    raise AuthenticationError("IMAP-Authentifizierung fehlgeschlagen") from exc
                last_error = exc
                self._close()
                if attempt < self.settings.imap_connection_retries and self._is_retryable_connect_error(exc):
                    time.sleep(self.settings.imap_retry_delay)
                    continue
                raise ImapProtocolError("IMAP-Protokollfehler") from last_error
            except Exception as exc:
                last_error = exc
                self._close()
                if attempt < self.settings.imap_connection_retries and self._is_retryable_connect_error(exc):
                    time.sleep(self.settings.imap_retry_delay)
                    continue

                if isinstance(exc, AuthenticationError):
                    raise
                if self._is_protocol_error(exc):
                    raise ImapProtocolError("IMAP-Protokollfehler") from last_error
                raise ImapConnectionError("IMAP-Verbindung fehlgeschlagen") from last_error

    def _is_retryable_connect_error(self, error: Exception) -> bool:
        if isinstance(error, (_IMAP_ABORT, TimeoutError, OSError)):
            return True
        message = str(error).upper()
        return any(token in message for token in ("CONNECTION", "TIMEOUT", "EOF", "BYE"))

    def _is_protocol_error(self, error: Exception) -> bool:
        if isinstance(error, _IMAP_ERROR):
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
        if isinstance(error, (TimeoutError, OSError, _IMAP_ABORT)):
            return RetryCause.RETRYABLE
        if isinstance(error, _IMAP_ERROR) and "BYE" in message:
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
            except (
                AuthenticationError,
                ImapProtocolError,
                MailboxNotFoundError,
                MessageNotFoundError,
                AttachmentNotFoundError,
                AttachmentTooLargeError,
                MessageTooLargeError,
                InvalidSearchParameterError,
            ):
                raise
            except (TimeoutError, OSError, _IMAP_ABORT) as exc:
                last_error = exc
                cause = self._classify_error(exc)
                if cause is RetryCause.RETRYABLE and attempt < self.settings.imap_connection_retries:
                    self._close()
                    time.sleep(self.settings.imap_retry_delay)
                    continue
                raise ImapConnectionError("IMAP-Befehl fehlgeschlagen") from last_error
            except _IMAP_ERROR as exc:
                last_error = exc
                should_retry = (
                    self._classify_error(exc) is RetryCause.RETRYABLE
                    and attempt < self.settings.imap_connection_retries
                )
                if should_retry:
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
        self._run(lambda _client: None, mailbox=mailbox)

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

        if before_uid is not None:
            if before_uid < 1:
                raise InvalidSearchParameterError("before_uid muss >= 1 sein")
            criteria = [*criteria, "UID", f"1:{before_uid}"]

        if not criteria:
            criteria = ["ALL"]

        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> tuple[list[int], int | None]:
            query = _build_uid_search_query(criteria)
            encoded_query = tuple(_to_imap_arg(part) for part in query)
            typ, data = client.uid("SEARCH", *encoded_query)  # type: ignore[arg-type]
            if typ != "OK":
                raise ImapProtocolError("IMAP SEARCH fehlgeschlagen")
            uids = _extract_uids(data or [])
            uids.sort(reverse=True)
            if not uids:
                return [], None

            selected = uids[:limit]
            next_before_uid = selected[-1] - 1 if selected and len(uids) > limit and selected[-1] > 1 else None
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
            if typ == "NO":
                raise MessageNotFoundError(f"Nachricht {uid} nicht gefunden")
            if typ != "OK":
                raise ImapProtocolError(f"IMAP FETCH fehlgeschlagen: {query}")
            payload: bytes | None = extract_fetch_literal(data or []) if expect_literal else None
            if expect_literal and payload is None:
                raise MessageNotFoundError(f"Nachricht {uid} ist leer")
            return payload, extract_internal_date(data or [])

        return self._run(action, mailbox=mailbox)

    def fetch_message_size(self, mailbox: str, uid: int) -> int:
        if uid <= 0:
            raise InvalidSearchParameterError("Ungültige UID")

        def action(client: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> int:
            typ, data = client.uid("FETCH", str(uid), "(RFC822.SIZE)")
            if typ == "NO":
                raise MessageNotFoundError(f"Nachricht {uid} nicht gefunden")
            if typ != "OK":
                raise ImapProtocolError("IMAP RFC822.SIZE fehlgeschlagen")
            joined = b" ".join(extract_fetch_metadata(data or []))
            match = re.search(rb"RFC822\.SIZE\s+(\d+)", joined, flags=re.IGNORECASE)
            if match is None:
                raise ImapProtocolError("IMAP Rückgabe enthält keine RFC822.SIZE")
            return int(match.group(1))

        return self._run(action, mailbox=mailbox)

    def assert_message_size_limit(self, mailbox: str, uid: int) -> int:
        max_bytes = self.settings.max_message_size_mb * 1024 * 1024
        size = self.fetch_message_size(mailbox, uid)
        if size > max_bytes:
            raise MessageTooLargeError(
                f"Nachricht {uid} überschreitet die Konfigurationsgrenze von {self.settings.max_message_size_mb} MB"
            )
        return size

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
            if typ == "NO":
                raise MessageNotFoundError(f"Nachricht {uid} hat keine BODYSTRUCTURE")
            if typ != "OK":
                raise ImapProtocolError("IMAP BODYSTRUCTURE fehlgeschlagen")
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
    "SearchCursorState",
    "_build_uid_search_query",
    "_format_imap_date",
    "_next_day",
    "_quote_imap_string",
    "build_search_cursor",
    "decode_mailbox_name",
    "encode_mailbox_name",
    "extract_bodystructure_bytes_from_fetch",
    "extract_bodystructure_from_fetch",
    "extract_fetch_literal",
    "extract_fetch_literals",
    "extract_fetch_metadata",
    "extract_internal_date",
    "parse_fetch_response",
    "parse_search_criteria",
    "parse_search_cursor",
]
