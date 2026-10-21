"""Auth boundary regressions; all keys and identities are synthetic."""
from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from mocu_imap_mcp.accounts import AccountError
from mocu_imap_mcp.auth_context import Principal, principal, require_access
from mocu_imap_mcp.auth_gateway.app import COOKIE, TRANSACTION, create_gateway
from mocu_imap_mcp.auth_gateway.config import GatewaySettings
from mocu_imap_mcp.auth_gateway.provider import Provider
from mocu_imap_mcp.auth_gateway.state import BrowserState, safe_return
from mocu_imap_mcp.runtime import Runtime
from mocu_imap_mcp.web_app import create_app


def identity(subject: str = "admin", role: str = "admin") -> Principal:
    return Principal("https://issuer.example/realm", subject, frozenset({"mocu:read", "mocu:admin"}), role, "bearer")


def test_setup_creator_cannot_be_consumed_by_other_admin(runtime: Runtime) -> None:
    owner = identity()
    token, _ = runtime.store.begin_setup(owner=owner)
    with pytest.raises(AccountError):
        runtime.store.claim(token, owner=identity("other"))
    runtime.store.claim(token, owner=owner)


def test_schema_migration_invalidates_only_unbound_tokens(runtime: Runtime) -> None:
    from mocu_imap_mcp.accounts import AccountStore
    from test_accounts_runtime import add_account
    account = add_account(runtime)
    token, _ = runtime.store.begin_setup(owner=identity())
    with runtime.store.connection() as db:
        db.execute("ALTER TABLE setup_tokens DROP COLUMN owner_issuer")
        db.execute("ALTER TABLE setup_tokens DROP COLUMN owner_subject")
        db.execute("PRAGMA user_version=1")
    migrated = AccountStore(runtime.store.path, runtime.store.vault)
    assert migrated.get(account).id == account
    assert migrated.password(account).get_secret_value() == "synthetic-password-only"
    with pytest.raises(AccountError):
        migrated.claim(token, owner=identity())


def test_concurrent_identities_are_isolated() -> None:
    async def run(subject: str) -> None:
        marker = principal.set(identity(subject))
        try:
            await asyncio.sleep(0)
            assert require_access(admin=True).subject == subject
        finally:
            principal.reset(marker)

    async def check() -> None:
        await asyncio.gather(run("one"), run("two"))
        assert principal.get() is None
    asyncio.run(check())


@pytest.mark.parametrize("path", ["https://evil.example", "//evil", "/\\evil", "/setup/a?secret=b", "/other"])
def test_return_targets_are_restricted(path: str) -> None:
    with pytest.raises(ValueError):
        safe_return(path)


def test_browser_transaction_one_use_bound_to_browser() -> None:
    state = BrowserState()
    transaction = state.begin("/setup/" + "a" * 43)
    with pytest.raises(ValueError):
        state.consume(transaction.state, "different-browser")
    assert state.consume(transaction.state, transaction.browser).return_to.startswith("/setup/")
    with pytest.raises(ValueError):
        state.consume(transaction.state, transaction.browser)


@pytest.fixture
def provider() -> tuple[Provider, object]:
    settings = GatewaySettings(oidc_issuer="https://issuer.example/realm",
                               mcp_resource="https://imap.example/mcp",
                               admin_oidc_client_secret_file="/unused",
                               allowed_subjects=["admin"], admin_subjects=["admin"])
    service = Provider(settings)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.PyJWK.from_json(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    service.keys = {"fixture": jwk}
    service.keys_until = time.monotonic() + 300
    return service, key


@pytest.mark.parametrize("change", [{"exp": 1}, {"iss": "https://wrong.example"}, {"aud": "other"},
                                   {"typ": "ID"}, {"nbf": 9999999999}, {"sub": ""}, {"sub": "unknown"}])
def test_invalid_access_claims(provider: tuple[Provider, object], change: dict[str, object]) -> None:
    service, key = provider
    claims = {"iss": service.settings.oidc_issuer, "aud": service.settings.mcp_resource,
              "exp": int(time.time()) + 300, "sub": "admin", "typ": "Bearer", "scope": "mocu:read"}
    claims.update(change)
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture"})
    with pytest.raises(ValueError):
        service.access(token)


def test_valid_token_and_scope_does_not_create_admin(provider: tuple[Provider, object]) -> None:
    service, key = provider
    service.settings.admin_subjects = []
    claims = {"iss": service.settings.oidc_issuer, "aud": service.settings.mcp_resource,
              "exp": int(time.time()) + 300, "sub": "admin", "typ": "Bearer", "scope": "mocu:read mocu:admin"}
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture"})
    assert service.access(token).role == "reader"


def test_bad_signature_missing_exp_unknown_kid_and_no_token_directed_fetch(
        provider: tuple[Provider, object], monkeypatch: pytest.MonkeyPatch) -> None:
    service, key = provider
    claims = {"iss": service.settings.oidc_issuer, "aud": service.settings.mcp_resource,
              "sub": "admin", "typ": "Bearer", "scope": "mocu:read"}
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for signer, extra in [(key, {}), (other, {"exp": int(time.time()) + 300})]:
        token = jwt.encode({**claims, **extra}, signer, algorithm="RS256", headers={"kid": "fixture"})
        with pytest.raises(ValueError):
            service.access(token)
    calls = []
    def unavailable(url: str) -> dict:
        calls.append(url)
        raise OSError("synthetic-secret-must-not-leak")
    monkeypatch.setattr(service, "_json", unavailable)
    token = jwt.encode({**claims, "exp": int(time.time()) + 300}, key, algorithm="RS256",
                       headers={"kid": "unknown", "jku": "https://attacker.invalid", "x5u": "https://evil.invalid"})
    for _ in range(5):
        with pytest.raises(ValueError, match="Token ungueltig"):
            service.access(token)
    assert calls == [service.settings.oidc_issuer + "/.well-known/openid-configuration"]


def test_jwks_rotation_and_expired_cache_fail_closed(provider: tuple[Provider, object],
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    service, _key = provider
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service.metadata = {"jwks_uri": "https://issuer.example/keys"}
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(other.public_key(), as_dict=True)
    jwk.update(kid="rotated", alg="RS256")
    monkeypatch.setattr(service, "_json", lambda url: {"keys": [jwk]})
    assert service._key("rotated").key_id == "rotated"
    service.keys_until = 0
    service.refresh_after = 0
    monkeypatch.setattr(service, "_json", lambda url: (_ for _ in ()).throw(OSError()))
    with pytest.raises(OSError):
        service._key("rotated")


def test_http_gateway_auth_failure_and_secret_redaction(provider: tuple[Provider, object],
                                                       caplog: pytest.LogCaptureFixture) -> None:
    service, _ = provider
    service.settings.gateway_proxy_ips = ["testclient"]
    with TestClient(create_gateway(service.settings, service)) as client:
        for headers in [{}, {"Authorization": "Bearer synthetic-secret-must-not-leak"},
                        [("Authorization", "Bearer a"), ("Authorization", "Bearer b")]]:
            response = client.get("/verify/bearer", headers=headers)
            assert response.status_code == 401
            assert "resource_metadata=" in response.headers["www-authenticate"]
            assert "synthetic-secret" not in response.text
        assert "synthetic-secret" not in caplog.text
        assert client.get("/verify/session").status_code == 401
        assert client.get("/.well-known/oauth-protected-resource/mcp").status_code == 200


@pytest.mark.parametrize(("case", "status", "error", "scope"), [
    ("missing", 401, None, None),
    ("malformed", 401, "invalid_token", None),
    ("expired", 401, "invalid_token", None),
    ("signature", 401, "invalid_token", None),
    ("issuer", 401, "invalid_token", None),
    ("audience", 401, "invalid_token", None),
    ("id-token", 401, "invalid_token", None),
    ("not-yet-valid", 401, "invalid_token", None),
    ("no-scope", 403, "insufficient_scope", "mocu:read"),
    ("unlisted", 403, None, None),
    ("valid", 204, None, None),
])
def test_gateway_bearer_challenge_contract(provider: tuple[Provider, object], case: str, status: int,
                                          error: str | None, scope: str | None,
                                          caplog: pytest.LogCaptureFixture) -> None:
    service, key = provider
    service.settings.gateway_proxy_ips = ["testclient"]
    marker = "synthetic-secret-must-not-leak"
    claims = {"iss": service.settings.oidc_issuer, "aud": service.settings.mcp_resource,
              "exp": int(time.time()) + 300, "sub": "admin", "typ": "Bearer", "scope": "mocu:read",
              "private_marker": marker}
    changes = {"expired": {"exp": 1}, "issuer": {"iss": "https://wrong.example"},
               "audience": {"aud": "other"}, "id-token": {"typ": "ID"},
               "not-yet-valid": {"nbf": 9999999999}, "no-scope": {"scope": "openid"},
               "unlisted": {"sub": "not-allowed"}}
    claims.update(changes.get(case, {}))
    if case == "signature":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = marker if case == "malformed" else jwt.encode(claims, key, algorithm="RS256",
                                                         headers={"kid": "fixture"})
    headers = {} if case == "missing" else {"Authorization": "Bearer " + token}
    with TestClient(create_gateway(service.settings, service)) as client:
        response = client.get("/verify/bearer", headers=headers)
    assert response.status_code == status
    expected = []
    if case not in {"unlisted", "valid"}:
        value = 'Bearer resource_metadata="https://imap.example/.well-known/oauth-protected-resource/mcp"'
        if error:
            value += f', error="{error}"'
        if scope:
            value += f', scope="{scope}"'
        expected = [value]
    assert response.headers.get_list("www-authenticate") == expected
    for secret in (token, marker):
        assert secret not in response.text
        assert secret not in str(response.headers)
        assert secret not in caplog.text


@pytest.mark.parametrize(("headers", "error"), [
    ({"Authorization": "Bearer "}, "invalid_token"),
    ({"Authorization": "Basic synthetic-marker"}, None),
    ({"Authorization": "Bearer one two"}, "invalid_token"),
    ([("Authorization", "Bearer a"), ("Authorization", "Bearer b")], "invalid_token"),
])
def test_ambiguous_or_invalid_authorization_stays_rejected(provider: tuple[Provider, object],
                                                          headers: dict | list, error: str | None) -> None:
    service, _ = provider
    service.settings.gateway_proxy_ips = ["testclient"]
    with TestClient(create_gateway(service.settings, service)) as client:
        response = client.get("/verify/bearer", headers=headers)
    assert response.status_code == 401
    value = 'Bearer resource_metadata="https://imap.example/.well-known/oauth-protected-resource/mcp"'
    if error:
        value += f', error="{error}"'
    assert response.headers.get_list("www-authenticate") == [value]


def test_provider_failure_does_not_invent_scope_or_leak_secret(provider: tuple[Provider, object],
        monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    service, _ = provider
    service.settings.gateway_proxy_ips = ["testclient"]
    def unavailable(token: str) -> Principal:
        raise OSError("synthetic-provider-secret")
    monkeypatch.setattr(service, "access", unavailable)
    with TestClient(create_gateway(service.settings, service)) as client:
        response = client.get("/verify/bearer", headers={"Authorization": "Bearer synthetic-token"})
    assert response.status_code == 401
    assert 'error="invalid_token"' in response.headers["www-authenticate"]
    assert "insufficient_scope" not in response.headers["www-authenticate"]
    assert "synthetic-provider-secret" not in response.text + str(response.headers) + caplog.text


def test_browser_and_untrusted_peer_denials_have_no_bearer_challenge(provider: tuple[Provider, object]) -> None:
    service, _ = provider
    with TestClient(create_gateway(service.settings, service)) as client:
        assert client.get("/verify/bearer").status_code == 403
        assert "www-authenticate" not in client.get("/verify/bearer").headers
        service.settings.gateway_proxy_ips = ["testclient"]
        for path in ("/verify/session", "/auth/session", "/auth/callback"):
            response = client.get(path)
            assert response.status_code in (400, 401)
            assert "www-authenticate" not in response.headers
        response = client.post("/auth/logout", data={"csrf": "wrong"})
        assert response.status_code == 403
        assert "www-authenticate" not in response.headers


def test_unlisted_signed_user_is_forbidden_without_login_loop(provider: tuple[Provider, object]) -> None:
    service, key = provider
    service.settings.gateway_proxy_ips = ["testclient"]
    claims = {"iss": service.settings.oidc_issuer, "aud": service.settings.mcp_resource,
              "exp": int(time.time()) + 300, "sub": "not-allowed", "typ": "Bearer", "scope": "mocu:read"}
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture"})
    with TestClient(create_gateway(service.settings, service)) as client:
        response = client.get("/verify/bearer", headers={"Authorization": "Bearer " + token})
        assert response.status_code == 403 and "www-authenticate" not in response.headers


def test_connector_untrusted_peer_duplicate_headers_wrong_auth_kind(runtime: Runtime) -> None:
    runtime.settings.access_mode = "trusted_proxy"
    runtime.settings.oidc_issuer = "https://issuer.example/realm"
    runtime.settings.trusted_proxy_ips = ["127.0.0.1"]
    headers = {"x-mocu-issuer": runtime.settings.oidc_issuer, "x-mocu-subject": "admin",
               "x-mocu-role": "admin", "x-mocu-scopes": "mocu:read mocu:admin", "x-mocu-auth-type": "bearer"}
    with TestClient(create_app(runtime)) as client:
        assert client.post("/mcp", headers=headers, json={}).status_code == 401
        runtime.settings.trusted_proxy_ips = ["testclient"]
        duplicate = [*headers.items(), ("x-mocu-role", "reader")]
        assert client.post("/mcp", headers=duplicate, json={}).status_code == 401
        headers["x-mocu-auth-type"] = "session"
        assert client.post("/mcp", headers=headers, json={}).status_code == 401


def test_connector_challenges_are_not_browser_or_role_errors(runtime: Runtime) -> None:
    runtime.settings.access_mode = "trusted_proxy"
    runtime.settings.oidc_issuer = "https://issuer.example/realm"
    runtime.settings.trusted_proxy_ips = ["testclient"]
    headers = {"x-mocu-issuer": runtime.settings.oidc_issuer, "x-mocu-subject": "admin",
               "x-mocu-role": "admin", "x-mocu-scopes": "openid", "x-mocu-auth-type": "bearer"}
    discovery = ('Bearer resource_metadata="https://imap-mcp.example.at/'
                 '.well-known/oauth-protected-resource/mcp"')
    with TestClient(create_app(runtime)) as client:
        response = client.post("/mcp", json={})
        assert response.status_code == 401
        assert response.headers.get_list("www-authenticate") == [discovery]
        response = client.post("/mcp", headers=headers, json={})
        assert response.status_code == 403
        assert response.headers.get_list("www-authenticate") == [
            discovery + ', error="insufficient_scope", scope="mocu:read"']
        response = client.post("/setup/" + "a" * 43, json={})
        assert response.status_code == 401
        assert "www-authenticate" not in response.headers and "location" not in response.headers
        headers.update({"x-mocu-auth-type": "session", "x-mocu-role": "reader",
                        "x-mocu-scopes": "mocu:read mocu:admin"})
        response = client.post("/setup/" + "a" * 43, headers=headers, json={})
        assert response.status_code == 403 and "www-authenticate" not in response.headers


def test_scope_error_retains_oauth_metadata_and_reader_denial_does_not_loop(runtime: Runtime) -> None:
    from mcp.server.mcpserver import MCPServer
    from mcp.server.mcpserver.exceptions import ToolError

    from mocu_imap_mcp.multi_tools import register
    async def check() -> None:
        server = MCPServer("fixture")
        register(server, runtime)
        for role, expect_challenge in [("admin", True), ("reader", False)]:
            marker = principal.set(Principal("https://issuer.example/realm", "admin",
                                             frozenset({"mocu:read"}), role, "bearer"))
            try:
                if not expect_challenge:
                    with pytest.raises(ToolError, match="Administrative Berechtigung"):
                        await server.call_tool("begin_account_setup", {})
                    continue
                result = await server.call_tool("begin_account_setup", {})
                assert result.is_error
                assert bool(result.meta and "mcp/www_authenticate" in result.meta) == expect_challenge
                assert result.meta["mcp/www_authenticate"] == [
                    'Bearer resource_metadata="https://imap-mcp.example.at/.well-known/oauth-protected-resource/mcp", '
                    'error="insufficient_scope", scope="mocu:admin"']
            finally:
                principal.reset(marker)
        tools = await server.list_tools()
        assert all(t.meta["securitySchemes"][0]["type"] == "oauth2" for t in tools)
    asyncio.run(check())


def test_session_fixation_idle_absolute_logout(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [0.0]
    monkeypatch.setattr("mocu_imap_mcp.auth_gateway.state.time.monotonic", lambda: clock[0])
    store = BrowserState()
    first = store.create(identity())
    second = store.create(identity(), first)
    with pytest.raises(ValueError):
        store.get(first, 30, 60)
    csrf = store.get(second, 30, 60).csrf
    with pytest.raises(ValueError):
        store.logout(second, "wrong")
    store.logout(second, csrf)
    with pytest.raises(ValueError):
        store.get(second, 30, 60)
    third = store.create(identity())
    clock[0] = 31
    with pytest.raises(ValueError):
        store.get(third, 30, 60)
    fourth = store.create(identity())
    clock[0] = 92
    with pytest.raises(ValueError):
        store.get(fourth, 300, 60)


def test_callback_state_error_replay_and_nonce(provider: tuple[Provider, object], tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    service, key = provider
    service.settings.gateway_proxy_ips = ["testclient"]
    state = BrowserState()
    item = state.begin("/auth/session")
    with TestClient(create_gateway(service.settings, service, state), base_url="https://imap.example") as client:
        client.cookies.set(TRANSACTION, item.browser)
        assert client.get("/auth/callback", params={"state": "wrong", "error": "access_denied"}).status_code == 400
        assert client.get("/auth/callback", params={"state": item.state, "error": "access_denied"}).status_code == 400
        assert item.state not in state.transactions
    from contextlib import contextmanager
    claims = {"iss": service.settings.oidc_issuer, "aud": service.settings.admin_oidc_client_id,
              "exp": int(time.time()) + 300, "iat": int(time.time()), "sub": "admin", "nonce": "wrong"}
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture"})
    class Client:
        def fetch_token(self, *args: object, **kwargs: object) -> dict:
            return {"id_token": token}
    @contextmanager
    def fake_client() -> Iterator[Client]:
        yield Client()
    service.metadata = {"token_endpoint": "https://issuer.example/token"}
    monkeypatch.setattr(service, "client", fake_client)
    from joserfc.errors import InvalidClaimError
    with pytest.raises(InvalidClaimError):
        service.callback(item, "synthetic-code")


def test_browser_logout_origin_and_csrf(provider: tuple[Provider, object]) -> None:
    service, _ = provider
    state = BrowserState()
    sid = state.create(identity())
    with TestClient(create_gateway(service.settings, service, state), base_url="https://imap.example") as client:
        client.cookies.set(COOKIE, sid)
        assert client.get("/auth/session").status_code == 200
        assert client.post("/auth/logout", data={"csrf": "wrong"}).status_code == 403
        csrf = state.sessions[sid].csrf
        assert client.post("/auth/logout", data={"csrf": csrf},
                           headers={"Origin": "https://evil.example"}).status_code == 403
        assert client.post("/auth/logout", data={"csrf": csrf},
                           headers={"Origin": service.settings.origin}).status_code == 204
        assert client.get("/auth/session").status_code == 401


def test_invalid_public_configuration_fails_closed() -> None:
    from pydantic import ValidationError

    from mocu_imap_mcp.runtime import RuntimeSettings
    for update in [{"oidc_issuer": "http://issuer.example"}, {"mcp_resource": "https://imap.example/mcp/"},
                   {"allowed_subjects": []}, {"admin_subjects": ["not-allowed"]},
                   {"gateway_proxy_ips": ["10.0.0.0/8"]}]:
        values = {"oidc_issuer": "https://issuer.example", "mcp_resource": "https://imap.example/mcp",
                  "admin_oidc_client_secret_file": "/not-a-secret-value", "allowed_subjects": ["admin"]}
        with pytest.raises(ValidationError):
            GatewaySettings(**(values | update))
    with pytest.raises(ValidationError):
        RuntimeSettings(access_mode="trusted_proxy", trusted_proxy_ips=["10.0.0.0/8"],
                         oidc_issuer="https://issuer.example")
