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
from .auth_context import Principal, challenge, principal, require_access
from .multi_tools import register
from .runtime import Runtime

_HEADERS = {
    # no-referrer makes Chromium form navigations send Origin:null. Origin-only
    # referrers preserve the strict POST check without exposing secret URL paths.
    "Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "strict-origin",
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
        identity = None
        if settings.access_mode == "trusted_proxy" and peer in settings.trusted_proxy_ips:
            names = ["issuer", "subject", "role", "scopes", "auth-type"]
            values = [request.headers.getlist("x-mocu-" + name) for name in names]
            ambiguous = any(b"_" in name for name, _ in scope["headers"] if name.startswith(b"x"))
            if not ambiguous and all(len(v) == 1 and v[0] for v in values):
                issuer, subject, role, scopes, auth_type = [v[0] for v in values]
                if issuer == settings.oidc_issuer and role in {"reader", "admin"}:
                    identity = Principal(issuer, subject, frozenset(scopes.split()), role, auth_type)
        elif settings.access_mode == "local" and peer in {"127.0.0.1", "::1", "testclient"}:
            identity = Principal("local", "local-reader", frozenset({"mocu:read"}), "reader", "local")
        if scope["path"] not in {"/healthz", "/readyz"}:
            is_setup = scope["path"].startswith("/setup/")
            resource = settings.public_base_url.rstrip("/") + "/mcp"
            if identity is None or (settings.access_mode == "trusted_proxy" and
                                    identity.auth_type != ("session" if is_setup else "bearer")):
                await JSONResponse({"error": "Authentifizierung erforderlich"}, status_code=401,
                    headers={} if is_setup else {"WWW-Authenticate": challenge(resource)})(
                        scope, receive, send)
                return
            if "mocu:read" not in identity.scopes or (is_setup and (
                    identity.role != "admin" or "mocu:admin" not in identity.scopes)):
                await JSONResponse({"error": "Administrative Authentifizierung erforderlich"},
                    status_code=403, headers={} if is_setup else {"WWW-Authenticate": challenge(
                        resource, error="insufficient_scope", scope="mocu:read")})(scope, receive, send)
                return
        context = principal.set(identity)
        try:
            await self.app(scope, receive, send)
        finally:
            principal.reset(context)


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
        owner = require_access(admin=True)
        try:
            runtime.store.check_owner(token, owner)
        except ValueError:
            return HTMLResponse("Einrichtung ungueltig", status_code=403, headers=_HEADERS)
        if request.method == "GET":
            csrf = secrets.token_urlsafe(32)
            response = HTMLResponse(
                '<!doctype html><html lang="de"><meta charset="utf-8"><title>MoCu Konto einrichten</title>'
                '<h1>IMAP-Konto einrichten</h1><p>Alle freigeschalteten Reader dieser Installation '
                'koennen alle aktivierten Konten lesen. Keine Mandantentrennung.</p><form method="post">'
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

            await run_in_threadpool(runtime.setup, token, account, owner)
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
