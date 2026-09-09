from __future__ import annotations

import asyncio
import base64
import tempfile
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from mocu_imap_mcp.multi_tools import register
from mocu_imap_mcp.runtime import Runtime, RuntimeSettings


async def main() -> None:
    # This script verifies registration only and must not require real IMAP
    # credentials or a production cursor key.
    with tempfile.TemporaryDirectory(prefix="mocu-smoke-") as directory:
        root = Path(directory)
        key = root / "synthetic.key"
        key.write_bytes(base64.urlsafe_b64encode(bytes(range(32))))
        runtime = Runtime(RuntimeSettings(database_path=root / "test.sqlite3", mocu_master_key_file=key))
        server = MCPServer("MoCu IMAP Connector")
        register(server, runtime)
        await check(server)


async def check(server: MCPServer) -> None:
    tools = [tool.name for tool in await server.list_tools()]
    resources = [resource.uri for resource in await server.list_resources()]
    templates = [template.uri_template for template in await server.list_resource_templates()]
    print(f"Tools: {len(tools)}")
    for item in tools:
        print(item)
    print(f"Resources: {len(resources)}")
    for item in resources:
        print(item)
    print(f"Resource templates: {len(templates)}")
    for item in templates:
        print(item)


if __name__ == "__main__":
    asyncio.run(main())
