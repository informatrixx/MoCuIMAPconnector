from __future__ import annotations

import logging
import time
import urllib.parse
from typing import Any

from mcp.server.mcpserver import MCPServer

from ..config import Settings
from ..imap_client import ImapClient
from ..security import PROMPT_INJECTION_WARNING, AttachmentTooLargeError, sha256_hex


def register_attachment_tools(server: MCPServer, settings: Settings) -> None:
    logger = logging.getLogger("mocu_imap_mcp.tools")
    max_bytes = settings.max_attachment_size_mb * 1024 * 1024

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
                if attachment.size is None or attachment.size <= max_bytes:
                    try:
                        data = client.read_attachment(mailbox, uid, attachment.part_id)
                        entry["sha256"] = sha256_hex(data)
                    except AttachmentTooLargeError:
                        entry["sha256"] = None
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
        uri = f"mocu://attachment/{mailbox_token}/{uid}/{part_id}"
        return {
            "uri": uri,
            "filename": attachment.filename,
            "content_type": attachment.content_type,
            "size": attachment.size,
        }

    @server.resource(
        "mocu://attachment/{mailbox_token}/{uid}/{part_id}",
        name="imap-attachment",
        description="Binärer Zugriff auf einen IMAP-Anhang",
        mime_type="application/octet-stream",
    )
    def read_attachment_resource(mailbox_token: str, uid: int, part_id: str) -> bytes:
        mailbox = urllib.parse.unquote(mailbox_token)
        with ImapClient(settings) as client:
            return client.read_attachment(mailbox, uid, part_id)
