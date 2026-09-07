from __future__ import annotations

from collections.abc import Iterable

from .mail_parser import decode_filename
from .models import AttachmentMeta

BodyStructureAttachment = AttachmentMeta

_NO_TOKEN = object()


def _tokenize_bodystructure(raw: str) -> list[object]:
    raw = raw.strip()
    index = 0
    length = len(raw)
    tokens: list[object] = []

    def skip_ws() -> None:
        nonlocal index
        while index < length and raw[index].isspace():
            index += 1

    def parse_atom() -> object:
        nonlocal index
        start = index
        while index < length and not raw[index].isspace() and raw[index] not in {"(", ")", "\"", "{"}:
            index += 1
        if index == start:
            return _NO_TOKEN
        value = raw[start:index]
        if value.upper() == "NIL":
            return None
        return value

    def parse_quoted() -> object:
        nonlocal index
        index += 1
        chars: list[str] = []
        while index < length:
            current = raw[index]
            if current == "\\":
                index += 1
                if index >= length:
                    break
                chars.append(raw[index])
                index += 1
                continue
            if current == '"':
                index += 1
                break
            chars.append(current)
            index += 1
        return "".join(chars)

    def parse_literal() -> object:
        nonlocal index
        # we are at '{'
        start = index + 1
        end = raw.find("}", start)
        if end == -1:
            raise ValueError("Ungültige Literal-Kennung")
        size_raw = raw[start:end]
        size_text = size_raw.strip()
        if not size_text.isdigit():
            raise ValueError("Ungültige Literal-Größe")
        size = int(size_text)
        index = end + 1
        while index < length and raw[index].isspace():
            index += 1
        value = raw[index : index + size]
        index += size
        return value

    def parse_list() -> object:
        nonlocal index
        index += 1
        children: list[object] = []
        while index < length:
            skip_ws()
            if index >= length:
                break
            if raw[index] == ")":
                index += 1
                break
            child = parse_token()
            if child is not _NO_TOKEN:
                children.append(child)
            skip_ws()
        return children

    def parse_token() -> object:
        nonlocal index
        skip_ws()
        if index >= length:
            return _NO_TOKEN
        char = raw[index]
        if char == "(":
            return parse_list()
        if char == ")":
            index += 1
            return _NO_TOKEN
        if char == '"':
            return parse_quoted()
        if char == "{":
            return parse_literal()
        atom = parse_atom()
        if atom is _NO_TOKEN:
            return _NO_TOKEN
        return atom

    while index < length:
        token = parse_token()
        if token is _NO_TOKEN:
            break
        tokens.append(token)
        skip_ws()

    return tokens


def parse_bodystructure(raw: str) -> list[object]:
    return _tokenize_bodystructure(raw)


def _params_to_dict(values: list[object]) -> dict[str, str]:
    result: dict[str, str] = {}
    index = 0
    while index < len(values):
        key = values[index]
        if isinstance(key, str) and index + 1 < len(values) and isinstance(values[index + 1], (str, int)):
            result[str(key).upper()] = str(values[index + 1])
        index += 2
    return result


def _parse_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def _iter_extension_fields(node: list[object], start: int) -> Iterable[object]:
    if start >= len(node):
        return []
    return node[start:]


def _find_disposition(node: list[object], start: int) -> tuple[str | None, list[object] | None]:
    for value in _iter_extension_fields(node, start):
        if not isinstance(value, list) or len(value) == 0:
            continue
        first = value[0]
        if not isinstance(first, str) or first.upper() not in {"INLINE", "ATTACHMENT", "RENDER"}:
            continue
        params = value[1] if len(value) > 1 and isinstance(value[1], list) else None
        return first.upper(), params if isinstance(params, list) else None
    return None, None


def _extension_scan_start(content_type: str) -> int:
    if content_type == "TEXT":
        return 8
    if content_type == "MESSAGE":
        return 11
    return 7


def _disposition_from_node(node: list[object], content_type: str) -> tuple[str | None, list[object] | None]:
    start = _extension_scan_start(content_type)
    disposition, disposition_params = _find_disposition(node, start)
    if disposition is not None:
        return disposition, disposition_params
    return _find_disposition(node, 0)


def _extract_attachment(node: list[object], part_id: str) -> BodyStructureAttachment | None:
    if len(node) < 2:
        return None
    first = node[0]
    second = node[1]
    if not (isinstance(first, str) and isinstance(second, str)):
        return None

    content_type = first.upper()
    subtype = second.upper()
    if content_type == "MULTIPART":
        return None

    params = node[2] if len(node) > 2 and isinstance(node[2], list) else []
    fixed_params = _params_to_dict(params) if isinstance(params, list) else {}
    size = _parse_int(node[6]) if len(node) > 6 else None
    transfer_encoding = str(node[5]) if len(node) > 5 and isinstance(node[5], (str, int)) else None

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
        filename=decode_filename(filename),
        content_type=f"{content_type}/{subtype}".lower(),
        size=size,
        inline=is_inline,
        transfer_encoding=transfer_encoding,
    )


def _is_multipart(node: list[object]) -> bool:
    return bool(node) and isinstance(node[0], list)


def _walk_multipart(node: list[object], part_id: str, attachments: list[BodyStructureAttachment]) -> None:
    for index, child in enumerate(node, start=1):
        if not isinstance(child, list):
            break
        child_id = str(index) if not part_id else f"{part_id}.{index}"
        walk_bodystructure_part(child, child_id, attachments)


def walk_bodystructure_part(node: object, part_id: str, attachments: list[BodyStructureAttachment]) -> None:
    if not isinstance(node, list):
        return
    if _is_multipart(node):
        _walk_multipart(node, part_id, attachments)
        return

    attachment = _extract_attachment(node, part_id)
    if attachment is not None:
        attachments.append(attachment)


def iter_attachments_from_bodystructure(raw: str) -> list[BodyStructureAttachment]:
    if not raw:
        return []

    parsed = parse_bodystructure(raw)
    if not parsed:
        return []

    root: list[object] = parsed
    while len(root) == 1 and isinstance(root[0], list):
        root = root[0]

    attachments: list[BodyStructureAttachment] = []
    walk_bodystructure_part(root, "", attachments)
    return attachments
