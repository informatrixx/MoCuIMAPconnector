"""Render secret-free provider/nginx configuration outside the checkout."""
from __future__ import annotations

import argparse
import json
import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from mocu_imap_mcp.public_urls import validate_base_url


def realm(resource: str, redirect: str, origin: str) -> dict[str, object]:
    scopes = [{"name": name, "protocol": "openid-connect", "attributes": {"include.in.token.scope": "true"}}
              for name in ("mocu:read", "mocu:admin")]
    clients = []
    for client_id, callback, secret in [("mocu-chatgpt", redirect, "${MOCU_CHATGPT_SECRET}"),
                                       ("mocu-admin-web", origin + "/auth/callback", "${MOCU_ADMIN_SECRET}")]:
        mappers = [{"name": "subject", "protocol": "openid-connect", "protocolMapper": "oidc-sub-mapper",
                    "config": {"access.token.claim": "true"}}]
        if client_id == "mocu-chatgpt":
            mappers.append({"name": "mocu-resource", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper", "config": {"included.client.audience": "mocu-resource",
                "access.token.claim": "true", "id.token.claim": "false"}})
        clients.append({"clientId": client_id, "enabled": True, "protocol": "openid-connect",
            "publicClient": False, "clientAuthenticatorType": "client-secret", "secret": secret,
            "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
            "serviceAccountsEnabled": False, "redirectUris": [callback], "fullScopeAllowed": False,
            "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": ""},
            "optionalClientScopes": ["mocu:read", "mocu:admin"],
            "protocolMappers": mappers})
    clients.append({"clientId": "mocu-resource", "enabled": True, "bearerOnly": True,
                    "protocol": "openid-connect", "attributes": {"resource_url": resource}})
    return {"realm": "mocu", "enabled": True, "sslRequired": "all", "registrationAllowed": False,
            "resetPasswordAllowed": False, "rememberMe": False, "accessTokenLifespan": 300,
            "revokeRefreshToken": True, "refreshTokenMaxReuse": 0, "ssoSessionIdleTimeout": 900,
            "ssoSessionMaxLifespan": 3600, "eventsEnabled": False, "adminEventsEnabled": False,
            "clients": clients, "clientScopes": scopes}


def render(output: Path, origin: str, issuer: str, redirect: str,
           initial_user: str | None = None, initial_subject: str | None = None) -> None:
    root = Path(__file__).resolve().parents[1]
    output = output.resolve()
    if output.is_relative_to(root):
        raise ValueError("Generated deployment files must remain outside the checkout")
    for value in (origin, issuer, redirect):
        url = urlsplit(value)
        if (url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment or
                not re.fullmatch(r"[a-zA-Z0-9.-]+", url.netloc) or '*' in value):
            raise ValueError("Exact HTTPS URLs without wildcards required")
    origin = validate_base_url(origin)
    validate_base_url(issuer)
    if not issuer.endswith("/realms/mocu"):
        raise ValueError("Reference profile requires a /realms/mocu issuer")
    base_path = urlsplit(origin).path
    oidc_path = urlsplit(issuer).path.removesuffix("/realms/mocu")
    shared_host = urlsplit(origin).netloc == urlsplit(issuer).netloc
    if shared_host and (not base_path or oidc_path != base_path + "/oidc"):
        raise ValueError("Shared host requires a separate <base-path>/oidc provider path")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    nginx = (root / "deploy/auth/nginx.conf.template").read_text()
    provider = (root / "deploy/auth/provider.locations.template").read_text()
    provider = provider.replace("@OIDC_PATH@", oidc_path).replace("@AUTH_HOST@", urlsplit(issuer).netloc)
    provider_server = ("server { listen 443 ssl; server_name " + urlsplit(issuer).netloc + ";\n" +
                       'add_header Strict-Transport-Security "max-age=31536000" always;\n' + provider + "\n}")
    nginx = (nginx.replace("@MCP_HOST@", urlsplit(origin).netloc).replace("@BASE_PATH@", base_path)
             .replace("@SHARED_PROVIDER_LOCATIONS@", provider if shared_host else "")
             .replace("@PROVIDER_SERVER@", "" if shared_host else provider_server))
    with (output / "nginx.conf").open("x") as file:
        file.write(nginx)
    profile = realm(origin + "/mcp", redirect, origin)
    if initial_user is not None:
        if not initial_subject or str(uuid.UUID(initial_subject)) != initial_subject:
            raise ValueError("Explicit immutable initial UUID subject required")
        profile["users"] = [{"id": initial_subject, "username": initial_user, "enabled": True,
            "credentials": [{"type": "password", "temporary": False, "value": "${MOCU_INITIAL_USER_PASSWORD}"}]}]
    with (output / "realm.json").open("x") as file:
        json.dump(profile, file, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--chatgpt-redirect", required=True)
    parser.add_argument("--initial-user")
    parser.add_argument("--initial-subject")
    args = parser.parse_args()
    render(args.output, args.origin, args.issuer, args.chatgpt_redirect, args.initial_user, args.initial_subject)
