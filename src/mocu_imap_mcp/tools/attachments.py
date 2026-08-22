from __future__ import annotations

import logging
import time
import urllib.parse
from typing import Any

from mcp.server.mcpserver import MCPServer

from ..config import Settings
from ..imap_client import ImapClient
from ..security import PROMPT_INJECTION_WARNING


def _resource_mime_from_content_type(content_type: str) -> str:
    normalized = (content_type or "").lower().strip()
    if normalized == "application/pdf":
        return "application/pdf"
    if normalized in {"image/jpeg", "image/jpg"}:
        return "image/jpeg"
    if normalized == "image/png":
        return "image/png"
    if normalized == "image/gif":
        return "image/gif"
    if normalized == "image/webp":
        return "image/webp"
    return "application/octet-stream"


def _resource_prefix(content_type: str) -> str:
    mime = _resource_mime_from_content_type(content_type)
    if mime == "application/pdf":
        return "pdf"
    if mime == "image/jpeg":
        return "jpeg"
    if mime == "image/png":
        return "png"
    if mime == "image/gif":
        return "gif"
    if mime == "image/webp":
        return "webp"
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
                entry = {
                    "part_id": attachment.part_id,
                    "filename": attachment.filename,
                    "content_type": attachment.content_type,
                    "size": attachment.size,
                    "sha256": None,
                }
                detail_list.append(entry)

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
        }

    @server.resource(
        "mocu://attachment-pdf/{mailbox_token}/{uid}/{part_id}",
        name="imap-attachment",
        description="Binärer Zugriff auf einen PDF-Anhang.",
        mime_type="application/pdf",
    )
    def read_attachment_resource(mailbox_token: str, uid: int, part_id: str) -> bytes:
        return _read_attachment(mailbox_token, uid, part_id, settings)

    @server.resource(
        "mocu://attachment-jpeg/{mailbox_token}/{uid}/{part_id}",
        name="imap-attachment",
        description="Binärer Zugriff auf einen JPEG-Anhang.",
        mime_type="image/jpeg",
    )
    def read_attachment_resource_jpeg(mailbox_token: str, uid: int, part_id: str) -> bytes:
        return _read_attachment(mailbox_token, uid, part_id, settings)

    @server.resource(
        "mocu://attachment-png/{mailbox_token}/{uid}/{part_id}",
        name="imap-attachment",
        description="Binärer Zugriff auf einen PNG-Anhang.",
        mime_type="image/png",
    )
    def read_attachment_resource_png(mailbox_token: str, uid: int, part_id: str) -> bytes:
        return _read_attachment(mailbox_token, uid, part_id, settings)

    @server.resource(
        "mocu://attachment-gif/{mailbox_token}/{uid}/{part_id}",
        name="imap-attachment",
        description="Binärer Zugriff auf einen GIF-Anhang.",
        mime_type="image/gif",
    )
    def read_attachment_resource_gif(mailbox_token: str, uid: int, part_id: str) -> bytes:
        return _read_attachment(mailbox_token, uid, part_id, settings)

    @server.resource(
        "mocu://attachment-webp/{mailbox_token}/{uid}/{part_id}",
        name="imap-attachment",
        description="Binärer Zugriff auf einen WebP-Anhang.",
        mime_type="image/webp",
    )
    def read_attachment_resource_webp(mailbox_token: str, uid: int, part_id: str) -> bytes:
        return _read_attachment(mailbox_token, uid, part_id, settings)

    @server.resource(
        "mocu://attachment-octet/{mailbox_token}/{uid}/{part_id}",
        name="imap-attachment",
        description="Binärer Zugriff auf einen Anhang.",
        mime_type="application/octet-stream",
    )
    def read_attachment_resource_octet(mailbox_token: str, uid: int, part_id: str) -> bytes:
        return _read_attachment(mailbox_token, uid, part_id, settings)
