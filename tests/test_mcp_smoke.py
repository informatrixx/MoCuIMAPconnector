from __future__ import annotations

import asyncio

from mocu_imap_mcp.config import Settings
from mocu_imap_mcp.server import create_server


async def _build_server_toolset() -> tuple[list[str], list[str]]:
    settings = Settings(
        imap_username="user",
        imap_password="password",
        cursor_signing_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    server = create_server(settings)
    tools = [tool.name for tool in await server.list_tools()]
    templates = [template.uri_template for template in await server.list_resource_templates()]
    return tools, templates


def test_mcp_smoke_tool_and_resource_registration() -> None:
    tools, templates = asyncio.run(_build_server_toolset())
    assert "list_mailboxes" in tools
    assert "search_emails" in tools
    assert "find_invoice_candidates" in tools
    assert "get_email" in tools
    assert "list_attachments" in tools
    assert "get_attachment" in tools
    assert len(tools) == 6
    assert len(templates) >= 6
    assert any(template.startswith("mocu://attachment-") for template in templates)
