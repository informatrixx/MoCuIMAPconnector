from __future__ import annotations

import logging
import time
import urllib.parse
from collections.abc import Callable
from typing import Any

from mcp.server.mcpserver import MCPServer

from ..config import Settings
from ..imap_client import ImapClient
from ..security import PROMPT_INJECTION_WARNING

_RESOURCE_MIME_MAP: tuple[tuple[str, str], ...] = (
    ("application/pdf", "application/pdf"),
    ("text/plain", "text/plain"),
    ("text/csv", "text/csv"),
    ("text/html", "text/html"),
    ("application/json", "application/json"),
    ("application/xml", "application/xml"),
    ("image/jpeg", "image/jpeg"),
    ("image/jpg", "image/jpeg"),
    ("image/png", "image/png"),
    ("image/gif", "image/gif"),
    ("image/webp", "image/webp"),
    ("application/zip", "application/zip"),
)


def _resource_mime_from_content_type(content_type: str) -> str:
    normalized = (content_type or "").lower().strip()
    if normalized in dict(_RESOURCE_MIME_MAP):
        return dict(_RESOURCE_MIME_MAP)[normalized]
    if normalized.startswith("text/"):
        if normalized == "text/plain":
            return "text/plain"
        if normalized == "text/csv":
            return "text/csv"
        return "text/plain"
    if normalized.startswith("application/") and normalized == "application/pdf":
        return "application/pdf"
    return "application/octet-stream"


def _resource_prefix(content_type: str) -> str:
    mime = _resource_mime_from_content_type(content_type)
    if mime == "application/pdf":
        return "pdf"
    if mime == "text/plain":
        return "txt"
    if mime == "text/csv":
        return "csv"
    if mime == "text/html":
        return "html"
    if mime.startswith("text/"):
        return "text"
    if mime == "application/json":
        return "json"
    if mime == "application/xml":
        return "xml"
    if mime == "image/jpeg":
        return "jpeg"
    if mime == "image/png":
        return "png"
    if mime == "image/gif":
        return "gif"
    if mime == "image/webp":
        return "webp"
    if mime == "application/zip":
        return "zip"
    return "octet"


def _read_attachment(mailbox_token: str, uid: int, part_id: str, settings: Settings) -> bytes:
    mailbox = urllib.parse.unquote(mailbox_token)
    with ImapClient(settings) as client:
        return client.read_attachment(mailbox, uid, part_id)


def register_attachment_tools(server: MCPServer, settings: Settings) -> None:
    logger = logging.getLogger("mocu_imap_mcp.tools")

    @server.tool(
        name="list_attachments",
        description=(
            "Listet alle Anhänge zu einer Nachricht auf.\n"
            f"{PROMPT_INJECTION_WARNING}"
        ),
    )
    def list_attachments(mailbox: str, uid: int) -> dict[str, Any]:
        start = time.perf_counter()
        if not mailbox:
            logger.warning("tool=list_attachments failed: mailbox fehlt")
            return {"error": "mailbox fehlt"}
        if uid <= 0:
            logger.warning("tool=list_attachments failed: uid ungültig")
            return {"error": "uid ungültig"}

        with ImapClient(settings) as client:
            attachments = client.list_attachments(mailbox, uid)
            detail_list: list[dict[str, Any]] = []
            for attachment in attachments:
                detail_list.append(
                    {
                        "part_id": attachment.part_id,
                        "filename": attachment.filename,
                        "content_type": attachment.content_type,
                        "size": attachment.size,
                        "sha256": None,
                        "inline": bool(attachment.inline),
                    },
                )

        logger.info(
            "tool=list_attachments duration=%.3fs mailbox=%s uid=%s count=%s",
            time.perf_counter() - start,
            mailbox,
            uid,
            len(detail_list),
        )
        return {"attachments": detail_list}

    @server.tool(
        name="get_attachment",
        description=(
            "Liefert einen einzelnen Anhang über eine MCP-Ressource.\n"
            "Die eigentliche Binärantwort erfolgt über den Resource-Zugriff.\n\n"
            f"{PROMPT_INJECTION_WARNING}"
        ),
    )
    def get_attachment(mailbox: str, uid: int, part_id: str) -> dict[str, Any]:
        start = time.perf_counter()
        if not mailbox:
            logger.warning("tool=get_attachment failed: mailbox fehlt")
            return {"error": "mailbox fehlt"}
        if uid <= 0:
            logger.warning("tool=get_attachment failed: uid ungültig")
            return {"error": "uid ungültig"}
        if not part_id:
            logger.warning("tool=get_attachment failed: part_id fehlt")
            return {"error": "part_id fehlt"}

        with ImapClient(settings) as client:
            attachments = client.list_attachments(mailbox, uid)
            attachment = next((a for a in attachments if a.part_id == part_id), None)
            if attachment is None:
                logger.warning("tool=get_attachment failed: part_id nicht gefunden")
                return {"error": "part_id nicht gefunden"}

        logger.info(
            "tool=get_attachment duration=%.3fs mailbox=%s uid=%s part_id=%s",
            time.perf_counter() - start,
            mailbox,
            uid,
            part_id,
        )
        mailbox_token = urllib.parse.quote(mailbox, safe="")
        resource = _resource_prefix(attachment.content_type)
        uri = f"mocu://attachment-{resource}/{mailbox_token}/{uid}/{part_id}"
        return {
            "uri": uri,
            "filename": attachment.filename,
            "content_type": attachment.content_type,
            "size": attachment.size,
            "inline": bool(attachment.inline),
        }

    _mime_resources = (
        ("pdf", "application/pdf"),
        ("txt", "text/plain"),
        ("html", "text/html"),
        ("text", "text/plain"),
        ("csv", "text/csv"),
        ("json", "application/json"),
        ("xml", "application/xml"),
        ("jpeg", "image/jpeg"),
        ("png", "image/png"),
        ("gif", "image/gif"),
        ("webp", "image/webp"),
        ("zip", "application/zip"),
        ("octet", "application/octet-stream"),
    )

    for resource_prefix, mime_type in _mime_resources:
        def _make_reader(prefix: str, _mime_type: str) -> Callable[[str, int, str], bytes]:
            @server.resource(
                f"mocu://attachment-{prefix}/{{mailbox_token}}/{{uid}}/{{part_id}}",
                name=f"imap-attachment-{prefix}",
                description=f"Binärer Zugriff auf Anhänge ({_mime_type}).",
                mime_type=_mime_type,
            )
            def _reader(mailbox_token: str, uid: int, part_id: str) -> bytes:
                return _read_attachment(mailbox_token, uid, part_id, settings)

            _reader.__name__ = f"read_attachment_resource_{prefix}"
            return _reader

        locals()[f"_resource_reader_{resource_prefix}"] = _make_reader(resource_prefix, mime_type)
