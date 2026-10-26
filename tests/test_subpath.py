"""Public subpaths never alter Origin checks or the trusted proxy boundary."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from scripts.prepare_auth import render
from starlette.testclient import TestClient

from mocu_imap_mcp.auth_context import Principal, challenge
from mocu_imap_mcp.auth_gateway.app import COOKIE, create_gateway
from mocu_imap_mcp.auth_gateway.config import GatewaySettings
from mocu_imap_mcp.auth_gateway.provider import Provider
from mocu_imap_mcp.auth_gateway.state import BrowserState
from mocu_imap_mcp.public_urls import metadata_url, validate_base_url
from mocu_imap_mcp.runtime import Runtime, RuntimeSettings
from mocu_imap_mcp.web_app import create_app


@pytest.mark.parametrize("prefix", ["", "/imap", "/services/imap"])
def test_canonical_metadata_and_base_urls(prefix: str) -> None:
    base = "https://admin.example.at" + prefix
    resource = base + "/mcp"
    assert RuntimeSettings(public_base_url=base + "/").public_base_url == base
    expected = "https://admin.example.at/.well-known/oauth-protected-resource" + prefix + "/mcp"
    assert metadata_url(resource) == expected
    assert challenge(resource) == f'Bearer resource_metadata="{expected}"'
    settings = GatewaySettings(oidc_issuer="https://issuer.example/realms/mocu", mcp_resource=resource,
        admin_oidc_client_secret_file="/unused", allowed_subjects=["admin"])
    assert settings.origin == "https://admin.example.at"
    assert settings.public_base_url == base and settings.base_path == prefix


@pytest.mark.parametrize("suffix", ["/../imap", "/imap//other", "/%69map", "/imap?x=1", "/imap#x",
                                    '/imap"', "/imap\\other", "/imap\r\nInjected:yes"])
def test_ambiguous_prefixes_fail_closed(suffix: str) -> None:
    with pytest.raises(ValueError):
        validate_base_url("https://admin.example.at" + suffix)


def test_subpath_browser_return_and_logout(tmp_path: Path) -> None:
    state = BrowserState("/imap")
    target = "/imap/setup/" + "a" * 43
    assert state.begin(target).return_to == target
    for other in ("/setup/" + "a" * 43, "/imapp/setup/" + "a" * 43, "//evil.example", target + "?next=bad"):
        with pytest.raises(ValueError):
            state.begin(other)
    secret = tmp_path / "synthetic-secret"
    secret.write_text("synthetic-client-secret-only")
    settings = GatewaySettings(oidc_issuer="https://admin.example.at/imap/oidc/realms/mocu",
        mcp_resource="https://admin.example.at/imap/mcp", allowed_subjects=["admin"], admin_subjects=["admin"],
        admin_oidc_client_secret_file=secret)
    provider = Provider(settings)
    with provider.client() as client:
        assert client.redirect_uri == "https://admin.example.at/imap/auth/callback"
    owner = Principal(settings.oidc_issuer, "admin", frozenset({"mocu:read", "mocu:admin"}), "admin", "session")
    sid = state.create(owner)
    with TestClient(create_gateway(settings, provider, state), base_url=settings.origin) as client:
        client.cookies.set(COOKIE, sid)
        page = client.get("/auth/session")  # trusted proxy strips the configured public prefix
        assert page.status_code == 200 and 'action="/imap/auth/logout"' in page.text
        csrf = state.sessions[sid].csrf
        assert client.post("/auth/logout", data={"csrf": csrf},
                           headers={"Origin": settings.public_base_url}).status_code == 403
        assert client.post("/auth/logout", data={"csrf": csrf},
                           headers={"Origin": settings.origin}).status_code == 204


def test_subpath_setup_origin_is_host_only(runtime: Runtime) -> None:
    runtime.settings.public_base_url = "https://imap-mcp.example.at/imap"
    runtime.settings.access_mode = "trusted_proxy"
    runtime.settings.trusted_proxy_ips = ["testclient"]
    runtime.settings.oidc_issuer = "https://issuer.example/realms/mocu"
    owner = Principal(runtime.settings.oidc_issuer, "admin", frozenset({"mocu:read", "mocu:admin"}),
                      "admin", "session")
    token, _ = runtime.store.begin_setup(owner=owner)
    headers = {"x-mocu-issuer": owner.issuer, "x-mocu-subject": owner.subject, "x-mocu-role": owner.role,
               "x-mocu-scopes": "mocu:read mocu:admin", "x-mocu-auth-type": "session"}
    with TestClient(create_app(runtime), base_url="https://imap-mcp.example.at") as client:
        page = client.get("/setup/" + token, headers=headers)
        assert page.status_code == 200
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', page.text)[1]
        form = {"csrf": csrf, "display_name": "Synthetic", "imap_host": "localhost", "imap_port": "25",
                "tls_mode": "ssl", "username": "synthetic-user", "password": "synthetic-password-only"}
        rejected = client.post("/setup/" + token, headers=headers | {"Origin": runtime.settings.public_base_url},
                               data=form)
        assert rejected.status_code == 403
        accepted = client.post("/setup/" + token,
            headers=headers | {"Origin": "https://imap-mcp.example.at"}, data=form)
        # Correct Origin/CSRF, still rejected by the existing forbidden IMAP port policy.
        assert accepted.status_code == 400 and "Einrichtung fehlgeschlagen" in accepted.text


def test_shared_host_renderer_has_one_vhost_and_separate_provider_prefix(tmp_path: Path) -> None:
    render(tmp_path, "https://admin.example.at/imap", "https://admin.example.at/imap/oidc/realms/mocu",
           "https://callback.example/registered")
    nginx = (tmp_path / "nginx.conf").read_text()
    assert nginx.count("server_name admin.example.at;") == 1
    assert "location = /imap/mcp" in nginx
    assert "location /imap/oidc/" in nginx
    assert "location = /.well-known/oauth-protected-resource/imap/mcp" in nginx
    assert "@BASE_PATH@" not in nginx and "@PROVIDER_SERVER@" not in nginx


def test_overlapping_shared_host_provider_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="separate"):
        render(tmp_path, "https://admin.example.at/imap", "https://admin.example.at/realms/mocu",
               "https://callback.example/registered")
