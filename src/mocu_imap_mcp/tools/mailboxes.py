from __future__ import annotations

import logging
import time
from typing import Any

from mcp.server.mcpserver import MCPServer

from ..config import Settings
from ..imap_client import ImapClient
from ..security import PROMPT_INJECTION_WARNING


def register_mailbox_tools(server: MCPServer, settings: Settings) -> None:
    logger = logging.getLogger("mocu_imap_mcp.tools")

    @server.tool(description=f"List IMAP mailboxes.\n\n{PROMPT_INJECTION_WARNING}")
    def list_mailboxes() -> dict[str, Any]:
        started = time.perf_counter()
        with ImapClient(settings) as client:
            boxes = client.list_mailboxes()
        duration = time.perf_counter() - started
        logger.info("tool=list_mailboxes duration=%.3fs count=%s", duration, len(boxes))
        result = {
            "mailboxes": [
                {"name": box.name, "selectable": box.selectable}
                for box in boxes
            ]
        }
        return result
