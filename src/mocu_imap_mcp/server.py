from __future__ import annotations

import logging

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import ValidationError

from .config import Settings, get_settings
from .security import sanitize_validation_error
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
    try:
        settings = get_settings()
    except ValidationError as exc:
        logger.error("Ungültige Konfiguration: %s", sanitize_validation_error(exc))
        raise
    _configure_logging(settings.log_level)
    transport_security = TransportSecuritySettings(
        allowed_hosts=_as_list(settings.mcp_allowed_hosts),
        allowed_origins=_as_list(settings.mcp_allowed_origins),
        enable_dns_rebinding_protection=True,
    )
    logger.info("MCP server start host=%s port=%s", settings.mcp_bind, settings.mcp_port)
    server = create_server(settings)
    try:
        server.run(
            transport="streamable-http",
            host=settings.mcp_bind,
            port=settings.mcp_port,
            streamable_http_path=settings.mcp_http_path,
            max_request_body_size=settings.mcp_max_request_body_size,
            transport_security=transport_security,
        )
    except KeyboardInterrupt:
        logger.info("MCP server stopped by KeyboardInterrupt")
        raise
    finally:
        logger.info("MCP server stopped")


def main() -> None:
    run()


if __name__ == "__main__":
    main()
