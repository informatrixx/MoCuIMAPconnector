from __future__ import annotations

# mypy: ignore-errors
#
import base64
import re
from datetime import datetime
from email import policy
from email.header import decode_header
from email.message import Message
from email.parser import BytesParser
from email.utils import collapse_rfc2231_value, decode_rfc2231, getaddresses, parsedate_to_datetime
from html.entities import name2codepoint
from html.parser import HTMLParser
from urllib.parse import unquote

from .models import AttachmentInfo, AttachmentMeta, MailAddress, MailDetail, MailSummary


def decode_header_value(raw_value: str | None) -> str:
    if not raw_value:
        return ""

    parts = decode_header(raw_value)
    decoded: list[str] = []
    for part, encoding in parts:
        if isinstance(part, bytes):
            charset = encoding or "utf-8"
            try:
                decoded.append(part.decode(charset, errors="replace"))
            except LookupError:
                decoded.append(part.decode("utf-8", errors="replace"))
            except UnicodeDecodeError:
                decoded.append(part.decode("latin1", errors="replace"))
        else:
            decoded.append(part)
    return "".join(decoded).strip()


def decode_filename(raw_filename: str | None) -> str:
    if not raw_filename:
        return ""

    if "encoded-word" in raw_filename.lower():
        # defensive fallback; decode_header handles this already but keeps intent explicit
        decoded = decode_header_value(raw_filename)
        if decoded:
            return decoded

    decoded = decode_header_value(raw_filename)
    if decoded and "%" in decoded:
        try:
            return unquote(decoded)
        except Exception:
            return decoded
    if decoded:
        return decoded

    # RFC 2231-style encoded filename*=
    if "''" in raw_filename:
        try:
            _, _, value = decode_rfc2231(raw_filename)
            if value:
                return value
        except Exception:
            pass
        try:
            return collapse_rfc2231_value(raw_filename)
        except Exception:
            pass

    if "%" in raw_filename:
        try:
            return unquote(raw_filename)
        except Exception:
            pass

    return raw_filename.strip()


def parse_addresses(raw: str | None) -> list[MailAddress]:
    if not raw:
        return []
    addresses = getaddresses([raw])
    parsed: list[MailAddress] = []
    for name, address in addresses:
        parsed.append(MailAddress(name=decode_header_value(name) or None, address=address or None))
    return parsed


def _strip_comment(text: str) -> str:
    return re.sub(r"\s*\(.*?\)\s*$", "", text, flags=re.DOTALL).strip()


def parse_imap_date(raw_date: str | None) -> str | None:
    if not raw_date:
        return None
    try:
        parsed = parsedate_to_datetime(raw_date)
    except Exception:
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=None).isoformat()
    return parsed.isoformat()


def parse_internal_imap_date(raw: str | None) -> str | None:
    if not raw:
        return None
    for fmt in ("%d-%b-%Y %H:%M:%S %z", "%d-%b-%Y %H:%M:%S %Z"):
        try:
            return datetime.strptime(raw, fmt).isoformat()
        except ValueError:
            continue
    return parse_imap_date(raw)


def message_from_bytes(raw_message: bytes) -> Message:
    return BytesParser(policy=policy.default).parsebytes(raw_message)


def _iter_parts_with_id(message: Message, prefix: str = "") -> list[tuple[str, Message]]:
    if not message.is_multipart():
        return [("1", message)]

    items: list[tuple[str, Message]] = []
    for index, part in enumerate(message.iter_parts(), 1):
        part_id = str(index) if not prefix else f"{prefix}.{index}"
        items.append((part_id, part))
        if part.is_multipart():
            items.extend(_iter_parts_with_id(part, part_id))
    return items


def _safe_part_content(part: Message) -> bytes:
    """
    Return decoded payload bytes for a part when possible.
    """
    payload = part.get_payload(decode=True)
    if payload is not None:
        if isinstance(payload, str):
            return payload.encode("utf-8", errors="replace")
        return payload

    raw = part.get_payload()
    if raw is None:
        return b""
    if isinstance(raw, bytes):
        return raw
    try:
        import quopri
        return quopri.decodestring(raw)
    except Exception:
        return raw.encode("utf-8", errors="replace")


def find_attachments(message: Message) -> list[AttachmentMeta]:
    attachments: list[AttachmentMeta] = []
    for part_id, part in _iter_parts_with_id(message):
        if part.is_multipart():
            continue

        filename = decode_filename(part.get_filename())
        if not filename:
            filename = decode_filename(part.get_param("name"))

        if not filename:
            cdisp = part.get_content_disposition() or ""
            if cdisp.lower() not in {"inline", "attachment"}:
                continue

        content_disposition = part.get_content_disposition() or "inline"
        inline = content_disposition.lower() == "inline"
        size_hint = part.get("Content-Length")
        size = int(size_hint) if size_hint and size_hint.isdigit() else None

        if size is None:
            try:
                decoded = _safe_part_content(part)
                size = len(decoded)
            except Exception:
                size = None

        attachments.append(
            AttachmentMeta(
                part_id=part_id,
                filename=filename or None,
                content_type=(part.get_content_type() or "application/octet-stream").lower(),
                size=size,
                inline=inline,
            )
        )
    return attachments


def _part_text_content(part: Message) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            return payload.decode(charset, errors="replace")
        if isinstance(payload, str):
            return payload
    except Exception:
        pass

    raw_payload = part.get_payload()
    if raw_payload is None:
        return ""
    if isinstance(raw_payload, str):
        return raw_payload
    return raw_payload.decode(charset, errors="replace")


def extract_body_text_and_html(message: Message) -> tuple[str, bool]:
    if not message.is_multipart():
        text = _part_text_content(message)
        return text.strip(), False

    plain_text: str | None = None
    html_body: str | None = None

    for part in message.walk():
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        disposition = part.get_content_disposition() or ""
        if disposition == "attachment":
            continue

        content = _part_text_content(part)
        if ctype == "text/plain" and plain_text is None:
            plain_text = content.strip()
            continue
        if ctype == "text/html" and html_body is None:
            html_body = content

    if plain_text is not None:
        return plain_text, False

    if html_body is None:
        return "", False
    return html_to_text(html_body), True


def html_to_text(html_content: str) -> str:
    parser = _SafeHtmlToText()
    parser.feed(html_content)
    parser.close()
    return parser.output().strip()


class _SafeHtmlToText(HTMLParser):
    """Very small HTML sanitizing parser used for body export."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._parts: list[str] = []
        self._skip_stack: list[str] = []

    def output(self) -> str:
        return "".join(self._parts)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str]]) -> None:
        tag = tag.lower()
        if tag in {"script", "style"}:
            self._skip_stack.append(tag)
            return
        if self._skip_stack:
            return
        if tag in {"p", "div", "section", "header", "footer", "li", "br", "tr"}:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._skip_stack and self._skip_stack[-1] == tag:
            self._skip_stack.pop()
            return
        if self._skip_stack:
            return
        if tag in {"p", "div", "section", "header", "footer", "li", "tr"}:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_stack:
            return
        chunk = re.sub(r"\s+", " ", data)
        if chunk:
            self._parts.append(chunk)

    def handle_entityref(self, name: str) -> None:
        if self._skip_stack:
            return
        self._parts.append(chr(name2codepoint.get(name, ord("?"))))

    def handle_charref(self, name: str) -> None:
        if self._skip_stack:
            return
        try:
            if name.startswith(("x", "X")):
                self._parts.append(chr(int(name[1:], 16)))
            else:
                self._parts.append(chr(int(name)))
        except ValueError:
            self._parts.append("?")

    def handle_comment(self, data: str) -> None:
        # ignore comments for safety
        return


def extract_summary(
    message: Message,
    mailbox: str,
    uid: int,
    internal_date: str | None = None,
) -> MailSummary:
    subject = decode_header_value(message.get("Subject"))
    from_header = parse_addresses(message.get("From"))
    date = parse_imap_date(message.get("Date"))
    to_header = parse_addresses(message.get("To"))
    attachments = find_attachments(message)

    return MailSummary(
        mailbox=mailbox,
        uid=uid,
        message_id=message.get("Message-ID"),
        date=date,
        internal_date=internal_date,
        from_=from_header[0] if from_header else None,
        to=to_header,
        subject=subject,
        has_attachments=bool(attachments),
        attachment_count=len(attachments),
        attachment_names=[item.filename for item in attachments if item.filename],
    )


def extract_mail_detail(
    message: Message,
    mailbox: str,
    uid: int,
    internal_date: str | None = None,
) -> MailDetail:
    subject = decode_header_value(message.get("Subject"))
    from_header = parse_addresses(message.get("From"))
    to_header = parse_addresses(message.get("To"))
    cc_header = parse_addresses(message.get("Cc"))
    date = parse_imap_date(message.get("Date"))

    text_body, html_available = extract_body_text_and_html(message)
    attachments = [item.model_dump(mode="json") for item in find_attachments(message)]

    return MailDetail(
        mailbox=mailbox,
        uid=uid,
        message_id=message.get("Message-ID"),
        date=date,
        internal_date=internal_date,
        from_=from_header[0] if from_header else None,
        to=to_header,
        cc=cc_header,
        subject=subject,
        text_body=text_body,
        html_available=html_available,
        attachments=[AttachmentInfo(**item) for item in attachments],
    )


def decode_b64_or_payload(data: bytes, encoding: str | None) -> bytes:
    encoding = (encoding or "").strip().upper()
    if encoding == "BASE64":
        return base64.b64decode(data, validate=False)
    if encoding == "QUOTED-PRINTABLE":
        import quopri

        return quopri.decodestring(data)
    return data


def select_attachment_part(
    message: Message,
    part_id: str,
) -> tuple[Message, str] | None:
    for current_id, part in _iter_parts_with_id(message):
        if current_id == part_id:
            return part, part.get_content_type().lower()
    return None
