from __future__ import annotations

import asyncio

from mocu_imap_mcp.server import create_server


async def main() -> None:
    server = create_server()
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
