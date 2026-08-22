from __future__ import annotations

import logging
import time
from typing import Any

from mcp.server.mcpserver import MCPServer

from ..config import Settings
from ..imap_client import ImapClient
from ..mail_parser import extract_mail_detail, message_from_bytes
from ..security import PROMPT_INJECTION_WARNING


def register_message_tools(server: MCPServer, settings: Settings) -> None:
    logger = logging.getLogger("mocu_imap_mcp.tools")

    @server.tool(
        name="get_email",
        description=(
            "Lädt eine einzelne Mail anhand von mailbox + UID. "
            "Körper kann per include_body geholt werden.\n\n"
            f"{PROMPT_INJECTION_WARNING}"
        ),
    )
    def get_email(mailbox: str, uid: int, include_body: bool = True) -> dict[str, Any]:
        started = time.perf_counter()
        if not mailbox:
            logger.warning("tool=get_email failed: mailbox fehlt")
            return {"error": "mailbox fehlt"}
        if uid <= 0:
            logger.warning("tool=get_email failed: uid ungültig")
            return {"error": "uid ungültig"}
        with ImapClient(settings) as client:
            headers_raw, internal_date = client.fetch_headers(mailbox, uid)
            if include_body:
                full_raw, _ = client.fetch_full_message(mailbox, uid)
                message = message_from_bytes(full_raw)
            else:
                message = message_from_bytes(headers_raw)
            detail = extract_mail_detail(message, mailbox=mailbox, uid=uid, internal_date=internal_date)
            logger.info(
                "tool=get_email duration=%.3fs uid=%s include_body=%s",
                time.perf_counter() - started,
                uid,
                include_body,
            )
            return detail.model_dump(mode="json", by_alias=True)
