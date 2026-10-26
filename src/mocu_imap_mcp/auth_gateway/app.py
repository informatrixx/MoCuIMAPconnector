from __future__ import annotations

from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from ..auth_context import AccessDenied, Principal, challenge
from .config import GatewaySettings
from .provider import Provider
from .state import BrowserState, safe_return

HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "strict-origin", "X-Content-Type-Options": "nosniff",
           "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'"}
COOKIE = "__Host-mocu-session"
TRANSACTION = "__Host-mocu-transaction"


def identity_headers(identity: Principal) -> dict[str, str]:
    return {"X-Mocu-Issuer": identity.issuer, "X-Mocu-Subject": identity.subject,
            "X-Mocu-Role": identity.role, "X-Mocu-Scopes": " ".join(sorted(identity.scopes)),
            "X-Mocu-Auth-Type": identity.auth_type}


def create_gateway(settings: GatewaySettings, provider: Provider | None = None,
                   state: BrowserState | None = None) -> Starlette:
    service = provider or Provider(settings)
    sessions = state or BrowserState(settings.base_path)

    def denied(code: int = 401, *, authenticate: str | None = None) -> Response:
        headers = dict(HEADERS)
        if authenticate is not None:
            headers["WWW-Authenticate"] = authenticate
        return JSONResponse({"error": "Access denied"}, status_code=code,
                            headers=headers)

    def peer_allowed(request: Request) -> bool:
        return bool(request.client and request.client.host in settings.gateway_proxy_ips)

    def browser_session(request: Request) -> Principal:
        if len(request.headers.getlist("cookie")) > 1:
            raise ValueError("Mehrdeutiges Cookie")
        item = sessions.get(request.cookies.get(COOKIE, ""), settings.session_idle_seconds,
                            settings.session_absolute_seconds)
        if item.identity.subject not in settings.admin_subjects:
            raise ValueError("Berechtigung entzogen")
        return item.identity

    async def bearer(request: Request) -> Response:
        if not peer_allowed(request):
            return denied(403)
        headers = request.headers.getlist("authorization")
        if not headers or (len(headers) == 1 and headers[0].split(" ", 1)[0].lower() != "bearer"):
            return denied(authenticate=challenge(settings.mcp_resource))
        if (len(headers) != 1 or headers[0][:7].lower() != "bearer " or not headers[0][7:] or
                any(c.isspace() for c in headers[0][7:])):
            return denied(authenticate=challenge(settings.mcp_resource, error="invalid_token"))
        try:
            identity = await run_in_threadpool(service.access, headers[0][7:])
            if "mocu:read" not in identity.scopes:
                return denied(403, authenticate=challenge(settings.mcp_resource,
                                                         error="insufficient_scope", scope="mocu:read"))
            return Response(status_code=204, headers=identity_headers(identity))
        except AccessDenied:
            return denied(403)
        except Exception:
            # Includes unavailable verification infrastructure: no access, never a scope upgrade.
            return denied(authenticate=challenge(settings.mcp_resource, error="invalid_token"))

    async def session_check(request: Request) -> Response:
        if not peer_allowed(request):
            return denied(403)
        try:
            return Response(status_code=204, headers=identity_headers(browser_session(request)))
        except ValueError:
            return denied()

    async def discovery(request: Request) -> Response:
        return JSONResponse({"resource": settings.mcp_resource, "authorization_servers": [settings.oidc_issuer],
            "scopes_supported": ["mocu:read", "mocu:admin"], "bearer_methods_supported": ["header"]}, headers=HEADERS)

    async def login(request: Request) -> Response:
        try:
            # nginx's internal GET fallback supplies the original path; never a query parameter.
            default = settings.base_path + "/auth/session"
            target = request.headers.get("x-mocu-return", default) if peer_allowed(request) else default
            item = sessions.begin(safe_return(target, settings.base_path))
            response = RedirectResponse(await run_in_threadpool(service.authorize, item), status_code=303,
                                        headers=HEADERS)
            response.set_cookie(TRANSACTION, item.browser, secure=True, httponly=True, samesite="lax", max_age=180)
            return response
        except Exception:
            return denied(400)

    async def callback(request: Request) -> Response:
        try:
            if any(len(request.query_params.getlist(k)) != 1 for k in request.query_params):
                raise ValueError
            item = sessions.consume(request.query_params.get("state", ""), request.cookies.get(TRANSACTION, ""))
            issuer = request.query_params.get("iss")
            if (service.metadata.get("authorization_response_iss_parameter_supported") and
                    issuer != settings.oidc_issuer) or (issuer is not None and issuer != settings.oidc_issuer):
                raise ValueError
            if "error" in request.query_params or not request.query_params.get("code"):
                raise ValueError
            identity = await run_in_threadpool(service.callback, item, request.query_params["code"])
            sid = sessions.create(identity, request.cookies.get(COOKIE, ""))
            response = RedirectResponse(item.return_to, status_code=303, headers=HEADERS)
            response.set_cookie(COOKIE, sid, secure=True, httponly=True, samesite="lax",
                                max_age=settings.session_absolute_seconds)
            response.delete_cookie(TRANSACTION, secure=True, httponly=True, samesite="lax")
            return response
        except Exception:
            return denied(400)

    async def session_page(request: Request) -> Response:
        try:
            browser_session(request)
            item = sessions.get(request.cookies[COOKIE], settings.session_idle_seconds,
                                settings.session_absolute_seconds)
            return HTMLResponse('<h1>MoCu Admin</h1><p>Gemeinsame Vertrauensgruppe: '
                'Reader sehen alle aktiven Konten.</p>'
                f'<form method="post" action="{settings.base_path}/auth/logout"><input type="hidden" name="csrf" '
                f'value="{item.csrf}"><button>Abmelden</button></form>', headers=HEADERS)
        except ValueError:
            return denied()

    async def logout(request: Request) -> Response:
        try:
            if request.headers.get("origin") != settings.origin:
                raise ValueError
            if request.headers.get("content-type", "").split(";")[0] != "application/x-www-form-urlencoded":
                raise ValueError
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 1024:
                    raise ValueError
            form = parse_qs(body.decode(), strict_parsing=True, max_num_fields=1)
            if len(form.get("csrf", [])) != 1:
                raise ValueError
            sessions.logout(request.cookies.get(COOKIE, ""), form["csrf"][0])
            response = Response(status_code=204, headers=HEADERS)
            response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="lax")
            return response
        except ValueError:
            return denied(403)

    app = Starlette(routes=[Route("/verify/bearer", bearer), Route("/verify/session", session_check),
        Route("/.well-known/oauth-protected-resource/mcp", discovery), Route("/auth/login", login),
        Route("/auth/callback", callback), Route("/auth/session", session_page),
        Route("/auth/logout", logout, methods=["POST"])])
    return app
