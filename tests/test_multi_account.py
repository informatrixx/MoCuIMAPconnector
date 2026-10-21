from __future__ import annotations

import asyncio
from contextlib import contextmanager
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer
from starlette.testclient import TestClient

from mocu_imap_mcp.accounts import AccountError
from mocu_imap_mcp.auth_context import require_access
from mocu_imap_mcp.imap_client import MailboxInfo
from mocu_imap_mcp.models import AttachmentMeta
from mocu_imap_mcp.multi_search import search
from mocu_imap_mcp.multi_tools import register
from mocu_imap_mcp.runtime import Runtime
from mocu_imap_mcp.web_app import create_app
from test_accounts_runtime import add_account


def test_sparse_accounts_no_duplicates_and_changed_selection(runtime: Runtime, monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = add_account(runtime), add_account(runtime)

    class Client:
        def list_mailboxes(self) -> list[MailboxInfo]:
            return [MailboxInfo("INBOX", True)]

        def pin_mailbox(self, mailbox: str, uidvalidity: int | None) -> int:
            assert uidvalidity in (None, 123)
            return 123

        def search_uids(self, mailbox: str, criteria: object, *, before_uid: int | None,
                        limit: int) -> tuple[list[int], int | None]:
            uids = list(range(before_uid if before_uid is not None else 500, 0, -1))
            batch = uids[:limit]
            return batch, batch[-1] - 1 if len(uids) > limit else None

        def fetch_headers(self, mailbox: str, uid: int) -> tuple[bytes, None]:
            return b"Subject: invoice\r\n\r\n" if uid % 20 == 0 or uid == 1 else b"Subject: hello\r\n\r\n", None

        def list_attachments(self, mailbox: str, uid: int) -> list[AttachmentMeta]:
            return []

    @contextmanager
    def client(account_id: str) -> Any:
        yield Client()

    monkeypatch.setattr(runtime, "client", client)
    runtime.settings.search_scan_budget = 37
    found = []
    cursor = None
    for _ in range(100):
        page = search(runtime, invoices=True, limit=10, cursor=cursor)
        found.extend((r["account_id"], r["uid"]) for r in page["candidates"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert len(found) == len(set(found)) == 52
    assert set(found) == {(a, uid) for a in (first, second) for uid in [1, *range(20, 501, 20)]}
    page = search(runtime, invoices=True, limit=1)
    runtime.store.set_enabled(second, False)
    with pytest.raises(AccountError):
        search(runtime, invoices=True, cursor=page["next_cursor"])


def test_mcp_registration_requires_reference_and_sanitizes(runtime: Runtime) -> None:
    async def check() -> None:
        server = MCPServer("fixture")
        register(server, runtime)
        tools = {t.name: t for t in await server.list_tools()}
        assert len(tools) == 11
        for name in ("get_email", "get_attachment", "list_attachments"):
            schema = tools[name].input_schema
            assert {"account_id", "uidvalidity", "uid", "mailbox"}.issubset(schema["required"])
        assert "password" not in tools["begin_account_setup"].input_schema["properties"]
        templates = await server.list_resource_templates()
        assert all("{account_id}" in str(t.uri_template) and "{uidvalidity}" in str(t.uri_template) for t in templates)

    asyncio.run(check())


def test_web_admin_and_csrf_boundaries(runtime: Runtime, monkeypatch: pytest.MonkeyPatch) -> None:
    token, _ = runtime.store.begin_setup(owner=require_access())
    with TestClient(create_app(runtime), base_url="https://imap-mcp.example.at") as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/setup/" + token).status_code == 403
    runtime.settings.access_mode = "trusted_proxy"
    runtime.settings.trusted_proxy_ips = ["testclient"]
    runtime.settings.oidc_issuer = "https://issuer.example/realm"
    with TestClient(create_app(runtime), base_url="https://imap-mcp.example.at") as client:
        assert client.get("/setup/" + token).status_code == 401
        headers = {"x-mocu-subject": "fixture-admin", "x-mocu-role": "admin",
                   "x-mocu-issuer": runtime.settings.oidc_issuer, "x-mocu-scopes": "mocu:read mocu:admin",
                   "x-mocu-auth-type": "session"}
        response = client.get("/setup/" + token, headers=headers)
        assert response.status_code == 200
        assert "no-store" in response.headers["cache-control"]
        assert response.headers["referrer-policy"] == "strict-origin"
        assert "Secure" in response.headers["set-cookie"]
        assert client.post("/setup/" + token, headers=headers, data={}).status_code == 403
        headers["origin"] = "https://imap-mcp.example.at"
        form = {"display_name": "Fixture", "imap_host": "imap.example.org", "imap_port": "993",
                "tls_mode": "ssl", "username": "fixture", "password": "synthetic-password-only",
                "csrf": client.cookies.get("__Host-mocu-csrf")}
        monkeypatch.setattr(runtime, "setup", lambda *args: "fixture-id")
        response = client.post("/setup/" + token, headers=headers, data=form)
        assert response.status_code == 200
        assert "synthetic-password-only" not in response.text


def test_http_mcp_admin_identity_reaches_tool(runtime: Runtime) -> None:
    runtime.settings.access_mode = "trusted_proxy"
    runtime.settings.trusted_proxy_ips = ["testclient"]
    runtime.settings.oidc_issuer = "https://issuer.example/realm"
    runtime.settings.mcp_allowed_hosts = ["imap-mcp.example.at"]
    with TestClient(create_app(runtime), base_url="https://imap-mcp.example.at") as client:
        headers = {"x-mocu-subject": "fixture", "x-mocu-role": "reader",
                   "x-mocu-issuer": runtime.settings.oidc_issuer, "x-mocu-scopes": "mocu:read mocu:admin",
                   "x-mocu-auth-type": "bearer",
                   "Accept": "application/json, text/event-stream"}
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "begin_account_setup", "arguments": {}}}
        response = client.post("/mcp", headers=headers, json=body)
        assert response.status_code == 200, response.text
        assert response.json()["result"]["isError"] is True
        headers["x-mocu-role"] = "admin"
        response = client.post("/mcp", headers=headers, json=body)
        assert response.status_code == 200, response.text
        assert response.json()["result"].get("isError") is not True, response.text
        assert "setup_url" in response.text
