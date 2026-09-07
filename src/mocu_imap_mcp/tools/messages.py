from __future__ import annotations

import logging
import time
from typing import Any

from mcp.server.mcpserver import MCPServer

from ..config import Settings
from ..imap_client import ImapClient
from ..mail_parser import extract_mail_detail, message_from_bytes
from ..security import PROMPT_INJECTION_WARNING, MessageTooLargeError


def get_email_impl(
    settings: Settings,
    mailbox: str,
    uid: int,
    include_body: bool = True,
) -> dict[str, Any]:
    if not mailbox:
        return {"error": "mailbox fehlt"}
    if uid <= 0:
        return {"error": "uid ungültig"}

    with ImapClient(settings) as client:
        if include_body:
            try:
                client.assert_message_size_limit(mailbox, uid)
            except MessageTooLargeError as exc:
                return {
                    "error": str(exc),
                }
        headers_raw, internal_date = client.fetch_headers(mailbox, uid)
        if include_body:
            full_raw, _ = client.fetch_full_message(mailbox, uid)
            message = message_from_bytes(full_raw)
        else:
            message = message_from_bytes(headers_raw)
        detail = extract_mail_detail(message, mailbox=mailbox, uid=uid, internal_date=internal_date)
    if include_body and len(detail.text_body) > settings.max_body_chars:
        detail.text_body = detail.text_body[: settings.max_body_chars]
        detail.text_body_truncated = True

    return detail.model_dump(mode="json", by_alias=True)


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
        result = get_email_impl(settings, mailbox, uid, include_body=include_body)
        if "error" in result:
            logger.warning("tool=get_email failed: %s", result["error"])
            return result
        logger.info(
            "tool=get_email duration=%.3fs uid=%s include_body=%s",
            time.perf_counter() - started,
            uid,
            include_body,
        )
        return result
