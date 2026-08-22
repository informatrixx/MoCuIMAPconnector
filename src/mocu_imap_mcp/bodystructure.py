from __future__ import annotations

from typing import Any

from .mail_parser import decode_filename
from .models import AttachmentMeta

BodyStructureAttachment = AttachmentMeta


def _tokenize_bodystructure(raw: str) -> list[Any]:
    raw = raw.strip()
    index = 0

    def skip_ws() -> None:
        nonlocal index
        while index < len(raw) and raw[index].isspace():
            index += 1

    def parse_token() -> Any:
        nonlocal index
        skip_ws()
        if index >= len(raw):
            return None

        ch = raw[index]
        if ch == "(":
            index += 1
            children: list[Any] = []
            while True:
                skip_ws()
                if index >= len(raw):
                    break
                if raw[index] == ")":
                    index += 1
                    break
                children.append(parse_token())
                skip_ws()
            return children

        if ch == '"':
            index += 1
            value_chars: list[str] = []
            while index < len(raw):
                current = raw[index]
                if current == "\\" and index + 1 < len(raw):
                    index += 1
                    value_chars.append(raw[index])
                    index += 1
                    continue
                if current == '"':
                    index += 1
                    break
                value_chars.append(current)
                index += 1
            return "".join(value_chars)

        start = index
        while index < len(raw) and not raw[index].isspace() and raw[index] not in {"(", ")"}:
            index += 1
        token = raw[start:index]
        if token.upper() == "NIL":
            return None
        return token

    values: list[Any] = []
    while index < len(raw):
        value = parse_token()
        if value is None and values and values[-1] is None:
            # avoid duplicate trailing None from malformed end markers
            continue
        if value is not None:
            values.append(value)
        skip_ws()
    return values


def parse_bodystructure(raw: str) -> list[Any]:
    values = _tokenize_bodystructure(raw)
    return values


def _params_to_dict(values: Any) -> dict[str, str]:
    if not isinstance(values, list):
        return {}
    result: dict[str, str] = {}
    for index in range(0, len(values), 2):
        if index + 1 >= len(values):
            break
        key = str(values[index]).upper()
        result[key] = decode_filename(str(values[index + 1]))
    return result


def _extract_attachment(node: list[Any], part_id: str) -> AttachmentMeta | None:
    if len(node) < 2:
        return None
    if not (isinstance(node[0], str) and isinstance(node[1], str)):
        return None

    content_type = (node[0] or "").upper()
    subtype = (node[1] or "").upper()
    if content_type == "MULTIPART":
        return None

    params = _params_to_dict(node[2]) if len(node) > 2 else {}
    size = None
    if len(node) > 6 and isinstance(node[6], str) and node[6].isdigit():
        size = int(node[6])
    elif len(node) > 6 and isinstance(node[6], int):
        size = node[6]

    transfer_encoding: str | None = None
    if len(node) > 5 and isinstance(node[5], str):
        transfer_encoding = node[5]

    disposition: str | None = None
    disposition_params: list[Any] | None = None
    if (
        len(node) > 8
        and isinstance(node[8], list)
        and node[8]
    ):
        if isinstance(node[8][0], str):
            disposition = (node[8][0] or "").upper()
        if len(node[8]) > 1 and isinstance(node[8][1], list):
            disposition_params = node[8][1]

    filename: str | None = None
    if params:
        filename = params.get("FILENAME") or params.get("NAME")
    if not filename and disposition_params:
        disposition_dict = _params_to_dict(disposition_params)
        filename = disposition_dict.get("FILENAME") or disposition_dict.get("NAME")

    has_attachment = bool(filename) or (disposition == "ATTACHMENT")
    if not has_attachment:
        return None

    return BodyStructureAttachment(
        part_id=part_id,
        filename=filename,
        content_type=f"{content_type}/{subtype}".lower(),
        size=size,
        inline=disposition == "INLINE",
        transfer_encoding=transfer_encoding,
    )


def iter_attachments_from_bodystructure(raw: str) -> list[AttachmentMeta]:
    if not raw:
        return []
    parsed = parse_bodystructure(raw)
    if not parsed:
        return []

    root = parsed[0] if len(parsed) == 1 and isinstance(parsed[0], list) else parsed
    attachments: list[AttachmentMeta] = []

    def walk(node: Any, part_id: str) -> None:
        if not isinstance(node, list):
            return

        if _extract_attachment(node, part_id if part_id else "1") is not None and part_id:
            attachment = _extract_attachment(node, part_id)
            if attachment is not None:
                attachments.append(attachment)
            return

        if len(node) >= 2 and isinstance(node[0], str) and isinstance(node[1], str):
            attachment = _extract_attachment(node, part_id if part_id else "1")
            if attachment is not None:
                attachments.append(attachment)
            return

        child_index = 1
        for child in node:
            if not isinstance(child, list):
                continue
            walk(child, f"{part_id}.{child_index}" if part_id else str(child_index))
            child_index += 1

    walk(root, "")
    return attachments
