"""Read displayable MIME text without downloading attachment payloads."""
from __future__ import annotations

from typing import Any

from .bodystructure import parse_bodystructure
from .imap_client import ImapClient
from .mail_parser import extract_mail_detail, message_from_bytes
from .models import AttachmentInfo
from .security import MessageTooLargeError


def text_parts(node: Any, prefix: str = "") -> list[tuple[str, str, int]]:
    if not isinstance(node, list) or not node:
        return []
    if isinstance(node[0], list):
        result: list[tuple[str, str, int]] = []
        for index, child in enumerate(node, 1):
            if not isinstance(child, list):
                break
            result.extend(text_parts(child, f"{prefix}.{index}" if prefix else str(index)))
        return result
    if len(node) < 7 or str(node[0]).upper() != "TEXT" or str(node[1]).upper() not in {"PLAIN", "HTML"}:
        return []
    # Named and explicitly attached text parts must never become display bodies.
    if isinstance(node[2], list) and any(str(k).upper() in {"NAME", "FILENAME"} for k in node[2][::2]):
        return []
    for extension in node[8:]:
        if isinstance(extension, list) and extension and str(extension[0]).upper() == "ATTACHMENT":
            return []
    return [(prefix or "1", str(node[1]).upper(), int(node[6]))]


def read_email(client: ImapClient, mailbox: str, uid: int, include_body: bool) -> dict[str, Any]:
    headers, internal_date = client.fetch_headers(mailbox, uid)
    structure, _ = client.fetch_bodystructure(mailbox, uid)
    from .bodystructure import iter_attachments_from_bodystructure

    attachments = iter_attachments_from_bodystructure(structure)
    detail = extract_mail_detail(message_from_bytes(headers), mailbox=mailbox, uid=uid, internal_date=internal_date)
    detail.text_body = ""
    detail.attachments = [AttachmentInfo.model_validate(a.model_dump()) for a in attachments]
    parsed = parse_bodystructure(structure)
    parts = text_parts(parsed[0] if len(parsed) == 1 else parsed)
    detail.html_available = any(kind == "HTML" for _, kind, _ in parts)
    if include_body:
        plain = [p for p in parts if p[1] == "PLAIN"]
        chosen = plain or [p for p in parts if p[1] == "HTML"]
        maximum = client.settings.max_message_size_mb * 1024 * 1024
        if sum(size for _, _, size in chosen) > maximum:
            raise MessageTooLargeError("Mail-Text ueberschreitet das Groessenlimit")
        chunks: list[str] = []
        downloaded = 0
        for part_id, _, _ in chosen:
            mime = client.fetch_message_part_mime(mailbox, uid, part_id)
            body = client.fetch_message_part_body(mailbox, uid, part_id)
            downloaded += len(mime) + len(body)
            if downloaded > maximum:
                raise MessageTooLargeError("Mail-Text ueberschreitet das Groessenlimit")
            part = message_from_bytes(mime.rstrip(b"\r\n") + b"\r\n\r\n" + body)
            chunks.append(extract_mail_detail(part, mailbox=mailbox, uid=uid).text_body)
        text = "\n".join(chunks)
        detail.text_body = text[:client.settings.max_body_chars]
        detail.text_body_truncated = len(text) > client.settings.max_body_chars
    return detail.model_dump(mode="json", by_alias=True)
