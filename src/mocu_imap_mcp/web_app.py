"""ASGI boundary for a locally bound MCP service behind an authenticated proxy."""
from __future__ import annotations

import hmac
import secrets
from typing import Any
from urllib.parse import parse_qs

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .accounts import AccountInput
from .multi_tools import register, role
from .runtime import Runtime

_HEADERS = {
    "Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
}


class AccessBoundary:
    def __init__(self, app: ASGIApp, runtime: Runtime) -> None:
        self.app = app
        self.runtime = runtime

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        settings = self.runtime.settings
        peer = request.client.host if request.client else ""
        current_role = ""
        if settings.access_mode == "trusted_proxy" and peer in settings.trusted_proxy_ips:
            if request.headers.get("x-mocu-subject"):
                current_role = request.headers.get("x-mocu-role", "")
        elif settings.access_mode == "local" and peer in {"127.0.0.1", "::1", "testclient"}:
            current_role = "reader"
        if scope["path"] not in {"/healthz", "/readyz"}:
            if current_role not in {"reader", "admin"}:
                await JSONResponse({"error": "Authentifizierung erforderlich"}, status_code=401)(scope, receive, send)
                return
            if scope["path"].startswith("/setup/") and current_role != "admin":
                await JSONResponse({"error": "Administrative Authentifizierung erforderlich"},
                                   status_code=403)(scope, receive, send)
                return
        context = role.set(current_role)
        try:
            await self.app(scope, receive, send)
        finally:
            role.reset(context)


def create_app(runtime: Runtime) -> ASGIApp:
    server = MCPServer(name="MoCu IMAP Connector")
    register(server, runtime)
    mcp_app = server.streamable_http_app(
        stateless_http=True, json_response=True, transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=runtime.settings.mcp_allowed_hosts,
            allowed_origins=[runtime.settings.public_base_url.rstrip("/")],
        ),
    )

    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def ready(request: Request) -> Response:
        try:
            with runtime.store.connection() as db:
                db.execute("SELECT 1").fetchone()
            return JSONResponse({"status": "ok"})
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)

    async def setup(request: Request) -> Response:
        token = request.path_params["token"]
        if len(token) > 128:
            return HTMLResponse("Einrichtung ungueltig", status_code=400, headers=_HEADERS)
        if request.method == "GET":
            csrf = secrets.token_urlsafe(32)
            response = HTMLResponse(
                '<!doctype html><html lang="de"><meta charset="utf-8"><title>MoCu Konto einrichten</title>'
                '<h1>IMAP-Konto einrichten</h1><form method="post">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                '<label>Anzeigename <input name="display_name" required maxlength="120"></label><br>'
                '<label>IMAP-Host <input name="imap_host" required maxlength="253"></label><br>'
                '<label>Port <input name="imap_port" type="number" value="993" required></label><br>'
                '<label>TLS <select name="tls_mode"><option value="ssl">SSL</option>'
                '<option value="starttls">STARTTLS (Port 143)</option></select></label><br>'
                '<label>Benutzername <input name="username" required maxlength="320"></label><br>'
                '<label>Passwort <input name="password" type="password" required autocomplete="new-password">'
                '</label><br><button>Verbindung pruefen und speichern</button></form></html>', headers=_HEADERS,
            )
            response.set_cookie("__Host-mocu-csrf", csrf, secure=True, httponly=True, samesite="strict", max_age=600)
            return response
        if request.headers.get("origin") != runtime.settings.public_base_url.rstrip("/"):
            return HTMLResponse("Origin ungueltig", status_code=403, headers=_HEADERS)
        if request.headers.get("content-type", "").split(";")[0] != "application/x-www-form-urlencoded":
            return HTMLResponse("Formular ungueltig", status_code=415, headers=_HEADERS)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16384:
                return HTMLResponse("Formular zu gross", status_code=413, headers=_HEADERS)
        try:
            parsed = parse_qs(body.decode(), strict_parsing=True, max_num_fields=8)
            if any(len(v) != 1 for v in parsed.values()):
                raise ValueError
            form: dict[str, Any] = {k: v[0] for k, v in parsed.items()}
            csrf = form.pop("csrf", "")
            cookie = request.cookies.get("__Host-mocu-csrf", "")
            if not cookie or not hmac.compare_digest(cookie, csrf):
                return HTMLResponse("CSRF-Pruefung fehlgeschlagen", status_code=403, headers=_HEADERS)
            account = AccountInput.model_validate(form)
            from starlette.concurrency import run_in_threadpool

            await run_in_threadpool(runtime.setup, token, account)
        except Exception:
            return HTMLResponse("Einrichtung fehlgeschlagen. Eingaben oder Verbindungsdaten pruefen.",
                                status_code=400, headers=_HEADERS)
        response = HTMLResponse("Postfach erfolgreich verbunden. Du kannst zu ChatGPT zurueckkehren.", headers=_HEADERS)
        response.delete_cookie("__Host-mocu-csrf", secure=True, httponly=True, samesite="strict")
        return response

    app = Starlette(routes=[Route("/healthz", health), Route("/readyz", ready),
                            Route("/setup/{token}", setup, methods=["GET", "POST"]), Mount("/", app=mcp_app)],
                    lifespan=mcp_app.router.lifespan_context)
    return AccessBoundary(app, runtime)
