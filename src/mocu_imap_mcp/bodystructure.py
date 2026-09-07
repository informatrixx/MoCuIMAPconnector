from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from .mail_parser import decode_filename
from .models import AttachmentMeta

BodyStructureAttachment = AttachmentMeta
BodyStructureToken = str | bytes | int | list["BodyStructureToken"]


_NO_TOKEN = object()


def _decode_token(value: str | bytes | int) -> str | int:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _to_bytes(raw: str | bytes) -> bytes:
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _tokenize_bodystructure(raw: str | bytes) -> list[BodyStructureToken]:
    raw_bytes = _to_bytes(raw)
    index = 0
    length = len(raw_bytes)
    tokens: list[BodyStructureToken] = []

    def skip_ws() -> None:
        nonlocal index
        while index < length and raw_bytes[index] in b" \t\r\n":
            index += 1

    def parse_atom() -> object:
        nonlocal index
        start = index
        while index < length and raw_bytes[index] not in b" ()\"{}":
            index += 1
        if index == start:
            return _NO_TOKEN
        value = raw_bytes[start:index]
        if value.upper() == b"NIL":
            return None
        return value.decode("utf-8", errors="replace")

    def parse_quoted() -> object:
        nonlocal index
        index += 1
        chars: list[bytes] = []
        while index < length:
            current = raw_bytes[index]
            if current == 0x5C:
                index += 1
                if index >= length:
                    break
                chars.append(bytes([raw_bytes[index]]))
                index += 1
                continue
            if current == 0x22:
                index += 1
                break
            chars.append(bytes([current]))
            index += 1
        return b"".join(chars).decode("utf-8", errors="replace")

    def parse_literal() -> object:
        nonlocal index
        start = index + 1
        end = raw_bytes.find(b"}", start)
        if end == -1:
            return _NO_TOKEN
        size_text = raw_bytes[start:end].strip()
        if not size_text.isdigit():
            return _NO_TOKEN
        size = int(size_text)
        index = end + 1
        if raw_bytes[index : index + 2] == b"\r\n":
            index += 2
        value = raw_bytes[index : index + size]
        index += size
        return value

    def parse_list() -> object:
        nonlocal index
        index += 1
        children: list[BodyStructureToken] = []
        while index < length:
            skip_ws()
            if index >= length:
                return children
            if raw_bytes[index] == 0x29:
                index += 1
                break
            child = parse_token()
            if child is not _NO_TOKEN:
                children.append(cast(BodyStructureToken, child))
            skip_ws()
        return children

    def parse_token() -> object:
        nonlocal index
        skip_ws()
        if index >= length:
            return _NO_TOKEN
        char = raw_bytes[index]
        if char == 0x28:
            return parse_list()
        if char == 0x29:
            index += 1
            return _NO_TOKEN
        if char == 0x22:
            return parse_quoted()
        if char == 0x7B:
            return parse_literal()
        atom = parse_atom()
        if atom is _NO_TOKEN:
            return _NO_TOKEN
        return atom

    while index < length:
        token = parse_token()
        if token is _NO_TOKEN:
            break
        tokens.append(cast(BodyStructureToken, token))
        skip_ws()

    return tokens


def parse_bodystructure(raw: str | bytes) -> list[BodyStructureToken]:
    return _tokenize_bodystructure(raw)


def _normalize_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _params_to_dict(values: list[BodyStructureToken]) -> dict[str, str]:
    result: dict[str, str] = {}
    index = 0
    while index < len(values):
        key = values[index]
        if isinstance(key, str) and index + 1 < len(values) and isinstance(values[index + 1], (str, bytes, int)):
            raw_value = values[index + 1]
            value = raw_value.decode("utf-8", errors="replace") if isinstance(raw_value, bytes) else str(raw_value)
            result[str(key).upper()] = value
        index += 2
    return result


def _parse_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value)
    if text.isdigit():
        return int(text)
    return None


def _iter_extension_fields(node: list[BodyStructureToken], start: int) -> Iterable[BodyStructureToken]:
    if start >= len(node):
        return []
    return node[start:]


def _find_disposition(node: list[BodyStructureToken], start: int) -> tuple[str | None, list[BodyStructureToken] | None]:
    for value in _iter_extension_fields(node, start):
        if not isinstance(value, list) or len(value) == 0:
            continue
        first = value[0]
        if not isinstance(first, str) or str(first).upper() not in {"INLINE", "ATTACHMENT", "RENDER"}:
            continue
        params = value[1] if len(value) > 1 and isinstance(value[1], list) else None
        return str(first).upper(), params if isinstance(params, list) else None
    return None, None


def _extension_scan_start(content_type: str) -> int:
    if content_type == "TEXT":
        return 8
    if content_type == "MESSAGE":
        return 11
    return 7


def _disposition_from_node(
    node: list[BodyStructureToken],
    content_type: str,
) -> tuple[str | None, list[BodyStructureToken] | None]:
    start = _extension_scan_start(content_type)
    disposition, disposition_params = _find_disposition(node, start)
    if disposition is not None:
        return disposition, disposition_params
    return _find_disposition(node, 0)


def _extract_attachment(node: list[BodyStructureToken], part_id: str) -> BodyStructureAttachment | None:
    if len(node) < 2:
        return None
    first = _normalize_text(node[0])
    second = _normalize_text(node[1])
    if not (isinstance(first, str) and isinstance(second, str)):
        return None

    content_type = first.upper()
    subtype = second.upper()
    if content_type == "MULTIPART":
        return None

    params = node[2] if len(node) > 2 and isinstance(node[2], list) else []
    fixed_params = _params_to_dict(params) if isinstance(params, list) else {}
    size = _parse_int(node[6]) if len(node) > 6 else None
    transfer_encoding = _normalize_text(node[5]) if len(node) > 5 else None

    disposition, disposition_params = _disposition_from_node(node, content_type)
    filename = fixed_params.get("NAME") or fixed_params.get("FILENAME")

    if not filename and disposition_params is not None:
        disposition_params_dict = _params_to_dict(disposition_params)
        filename = disposition_params_dict.get("NAME") or disposition_params_dict.get("FILENAME")

    is_inline = disposition == "INLINE"
    has_attachment = bool(filename) or (disposition == "ATTACHMENT")
    if not has_attachment:
        return None

    return BodyStructureAttachment(
        part_id=part_id,
        filename=decode_filename(_normalize_text(filename)),
        content_type=f"{content_type}/{subtype}".lower(),
        size=size,
        inline=is_inline,
        transfer_encoding=transfer_encoding,
    )


def _is_multipart(node: list[BodyStructureToken]) -> bool:
    return bool(node) and isinstance(node[0], list)


def _walk_multipart(node: list[BodyStructureToken], part_id: str, attachments: list[BodyStructureAttachment]) -> None:
    for index, child in enumerate(node, start=1):
        if not isinstance(child, list):
            break
        child_id = str(index) if not part_id else f"{part_id}.{index}"
        walk_bodystructure_part(child, child_id, attachments)


def walk_bodystructure_part(node: BodyStructureToken, part_id: str, attachments: list[BodyStructureAttachment]) -> None:
    if not isinstance(node, list):
        return
    if _is_multipart(node):
        _walk_multipart(node, part_id, attachments)
        return

    attachment = _extract_attachment(node, part_id)
    if attachment is not None:
        attachments.append(attachment)


def iter_attachments_from_bodystructure(raw: str | bytes) -> list[BodyStructureAttachment]:
    if not raw:
        return []

    parsed = parse_bodystructure(raw)
    if not parsed:
        return []

    root: list[BodyStructureToken] = parsed
    while len(root) == 1 and isinstance(root[0], list):
        root = root[0]

    attachments: list[BodyStructureAttachment] = []
    start_part_id = "1" if not _is_multipart(root) else ""
    walk_bodystructure_part(root, start_part_id, attachments)
    return attachments
