from __future__ import annotations

import logging

from mcp.server.mcpserver import MCPServer

from .config import Settings, get_settings
from .tools.attachments import register_attachment_tools
from .tools.mailboxes import register_mailbox_tools
from .tools.messages import register_message_tools
from .tools.search import register_search_tools

logger = logging.getLogger("mocu_imap_mcp.server")


def _as_list(value: list[str] | str) -> list[str]:
    if isinstance(value, str):
        return [value]
    return value

def _configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def create_server(settings: Settings | None = None) -> MCPServer:
    cfg = settings or get_settings()
    server = MCPServer(name="MoCu IMAP Connector")
    register_mailbox_tools(server, cfg)
    register_search_tools(server, cfg)
    register_message_tools(server, cfg)
    register_attachment_tools(server, cfg)
    return server


def run() -> None:
    import os

    import uvicorn

    from .runtime import Runtime, load_runtime_settings
    from .web_app import create_app

    os.umask(0o077)
    _configure_logging()
    try:
        settings = load_runtime_settings()
        runtime = Runtime(settings)
    except Exception as exc:
        logger.error("Start fehlgeschlagen error_class=%s", type(exc).__name__)
        raise SystemExit(1) from None
    logger.info("MCP server start")
    try:
        uvicorn.run(create_app(runtime), host=settings.mcp_bind, port=settings.mcp_port,
                    access_log=False, proxy_headers=False)
    finally:
        logger.info("MCP server stopped")


def main() -> None:
    run()


if __name__ == "__main__":
    main()
