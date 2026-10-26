"""Runs only in the isolated E2E runner. No production secrets or targets."""
from __future__ import annotations

import os
import ssl
import sys
import time
import traceback
import uuid
from http.client import HTTPSConnection
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import jwt
import requests
from authlib.integrations.requests_client import OAuth2Session
from playwright.sync_api import Browser, sync_playwright

ORIGIN = "https://imap-mcp.example.at"
BASE_PATH = os.environ.get("MOCU_TEST_BASE_PATH", "")
PUBLIC_BASE = ORIGIN + BASE_PATH
ISSUER = PUBLIC_BASE + "/oidc/realms/mocu" if BASE_PATH else "https://auth.example.at/realms/mocu"
RESOURCE = PUBLIC_BASE + "/mcp"
CALLBACK = PUBLIC_BASE + "/test-callback"
METADATA = ORIGIN + "/.well-known/oauth-protected-resource" + BASE_PATH + "/mcp"


def assert_challenge(response: requests.Response, status: int, error: str | None = None,
                     scope: str | None = None) -> None:
    """Check raw header count too: requests' merged header can hide duplicates."""
    assert response.status_code == status
    expected = f'Bearer resource_metadata="{METADATA}"'
    if error:
        expected += f', error="{error}"'
    if scope:
        expected += f', scope="{scope}"'
    assert response.raw.headers.getlist("WWW-Authenticate") == [expected]
    assert "synthetic-secret-must-not-leak" not in response.text + str(response.headers)


def oauth() -> OAuth2Session:
    client = OAuth2Session("mocu-chatgpt", Path("/test/client").read_text().strip(),
        token_endpoint_auth_method="client_secret_basic", redirect_uri=CALLBACK,
        scope="openid mocu:read mocu:admin", code_challenge_method="S256")
    client.verify = "/test/ca.pem"
    client.trust_env = False
    return client


def code(browser: Browser, client: OAuth2Session, user: str, resource: str = RESOURCE,
         allow_target_error: bool = False) -> str:
    url, state = client.create_authorization_url(ISSUER + "/protocol/openid-connect/auth",
        state="synthetic-state", code_verifier="v" * 64, resource=resource)
    context = browser.new_context(ignore_https_errors=True)  # ephemeral self-signed browser fixture only
    page = context.new_page()
    page.on("response", lambda response: print("Auth E2E: browser HTTP failure " + str({
        "status": response.status, "provider": response.url.startswith(ISSUER)}), flush=True)
        if response.status >= 400 and urlsplit(response.url).path != urlsplit(CALLBACK).path else None)
    try:
        page.goto(url)
        print("Auth E2E: browser authorization form loaded", flush=True)
        page.locator("#username").fill(user)
        page.locator("#password").fill(Path("/test/password").read_text().strip())
        page.locator("#kc-login").click()
        print("Auth E2E: browser credentials submitted", flush=True)
        page.wait_for_url(CALLBACK + "**", timeout=15000)
        query = parse_qs(urlsplit(page.url).query)
        assert query["state"] == [state]
        assert query["iss"] == [ISSUER]
        if allow_target_error and "error" in query:
            assert query.get("error") == ["invalid_target"] and "code" not in query
            return ""
        return query["code"][0]
    finally:
        context.close()


def main() -> None:
    http = requests.Session()
    http.verify = "/test/ca.pem"
    http.trust_env = False
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            if (http.get(ISSUER + "/.well-known/openid-configuration", timeout=3).status_code == 200 and
                http.get(METADATA, timeout=3).status_code == 200):
                break
        except requests.RequestException:
            pass
        time.sleep(2)
    else:
        raise RuntimeError("Auth stack readiness deadline exceeded")
    print("Auth E2E: provider and gateway ready", flush=True)
    metadata = http.get(METADATA, timeout=5).json()
    assert metadata["resource"] == RESOURCE and metadata["authorization_servers"] == [ISSUER]
    if BASE_PATH:
        landing = http.get(PUBLIC_BASE + "/", allow_redirects=False, timeout=5)
        assert landing.status_code == 303
        assert urlsplit(landing.headers["Location"]).path == BASE_PATH + "/auth/login"
        assert http.post(ORIGIN + "/mcp", json={}, timeout=5).status_code == 404
        assert http.get(PUBLIC_BASE + "/oidc/admin/", timeout=5).status_code == 403
        assert http.get(PUBLIC_BASE + "/oidc/realms/master/", timeout=5).status_code == 403
    unauth = http.post(RESOURCE, json={}, timeout=5)
    assert_challenge(unauth, 401)
    invalid = http.post(RESOURCE, headers={"Authorization": "Bearer synthetic-secret-must-not-leak"},
                        json={}, timeout=5)
    assert_challenge(invalid, 401, "invalid_token")
    assert http.get(ORIGIN + "/_verify_bearer", timeout=5).status_code == 404
    assert http.post(RESOURCE, headers={"X-Mocu-Role": "admin", "X-Mocu-Subject": "synthetic-admin"},
                     json={}, timeout=5).status_code == 401
    duplicate = HTTPSConnection("imap-mcp.example.at", context=ssl.create_default_context(
        cafile="/test/ca.pem"), timeout=5)
    duplicate.putrequest("POST", BASE_PATH + "/mcp")
    duplicate.putheader("Authorization", "Bearer synthetic-one")
    duplicate.putheader("Authorization", "Bearer synthetic-two")
    duplicate.putheader("Content-Length", "0")
    duplicate.endheaders()
    assert duplicate.getresponse().status in (400, 401)
    duplicate.close()
    for method in ("initialize", "tools/list", "resources/read"):
        assert http.post(RESOURCE, json={"jsonrpc": "2.0", "id": 1, "method": method}, timeout=5).status_code == 401
    print("Auth E2E: discovery, challenge, header spoofing PASS", flush=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        with oauth() as client:
            token = client.fetch_token(ISSUER + "/protocol/openid-connect/token",
                code=code(browser, client, "synthetic-admin"), code_verifier="v" * 64, resource=RESOURCE)
            refreshed = client.refresh_token(ISSUER + "/protocol/openid-connect/token",
                refresh_token=token["refresh_token"], resource=RESOURCE)
        print("Auth E2E: code + PKCE + refresh PASS", flush=True)
        # Contract diagnostics are booleans only, never tokens, subjects or credentials.
        claims = jwt.decode(refreshed["access_token"], options={"verify_signature": False})
        print("Auth E2E: token contract " + str({"issuer": claims.get("iss") == ISSUER,
            "audience": claims.get("aud") == RESOURCE or RESOURCE in claims.get("aud", []),
            "subject": claims.get("sub") == str(uuid.uuid5(uuid.NAMESPACE_DNS, "synthetic-admin")),
            "type": claims.get("typ") == "Bearer"}), flush=True)

        def tool(access: str, name: str) -> dict:
            response = http.post(RESOURCE, headers={"Authorization": "Bearer " + access,
                "Accept": "application/json, text/event-stream"}, json={"jsonrpc": "2.0", "id": 1,
                "method": "tools/call", "params": {"name": name, "arguments": {}}}, timeout=10)
            assert response.status_code == 200, f"MCP status {response.status_code}"
            assert "WWW-Authenticate" not in response.headers
            return response.json()["result"]

        assert "accounts" in tool(refreshed["access_token"], "list_accounts")["structuredContent"]
        setup = tool(refreshed["access_token"], "begin_account_setup")["structuredContent"]["setup_url"]
        assert_challenge(http.post(RESOURCE, headers={"Authorization": "Bearer " + token["id_token"]},
                                   json={}, timeout=5), 401, "invalid_token")
        with oauth() as client:
            reader = client.fetch_token(ISSUER + "/protocol/openid-connect/token",
                code=code(browser, client, "synthetic-reader"), code_verifier="v" * 64, resource=RESOURCE)
        reader_denied = tool(reader["access_token"], "begin_account_setup")
        assert reader_denied["isError"] and "mcp/www_authenticate" not in reader_denied.get("_meta", {})
        for scopes, expected_status in [("openid", 403), ("openid mocu:read", 200)]:
            with oauth() as client:
                client.scope = scopes
                restricted = client.fetch_token(ISSUER + "/protocol/openid-connect/token",
                    code=code(browser, client, "synthetic-admin"), code_verifier="v" * 64, resource=RESOURCE)
            if expected_status == 403:
                response = http.post(RESOURCE, headers={"Authorization": "Bearer " + restricted["access_token"]},
                                     json={}, timeout=5)
                assert_challenge(response, 403, "insufficient_scope", "mocu:read")
            else:
                result = tool(restricted["access_token"], "begin_account_setup")
                assert result["isError"] and result["_meta"]["mcp/www_authenticate"] == [
                    f'Bearer resource_metadata="{METADATA}", '
                    'error="insufficient_scope", scope="mocu:admin"']
        print("Auth E2E: exact 401/403 challenges, single proxy headers, scope/role distinction PASS", flush=True)
        for resource, verifier in [("https://wrong.example/mcp", "v" * 64), (RESOURCE, "wrong" * 16)]:
            with oauth() as client:
                fresh_code = code(browser, client, "synthetic-admin")
                response = http.post(ISSUER + "/protocol/openid-connect/token", auth=(client.client_id,
                    Path("/test/client").read_text().strip()), data={"grant_type": "authorization_code",
                    "code": fresh_code, "redirect_uri": CALLBACK, "code_verifier": verifier,
                    "resource": resource}, timeout=5)
                print("Auth E2E: negative token exchange " + str({"status": response.status_code,
                    "resource_mismatch": resource != RESOURCE}), flush=True)
                assert response.status_code == 400
        with oauth() as client:
            invalid_code = code(browser, client, "synthetic-admin", resource="https://wrong.example/mcp",
                                allow_target_error=True)
            if invalid_code:
                # Keycloak can defer target validation until token issuance. A code alone grants no MCP access.
                response = http.post(ISSUER + "/protocol/openid-connect/token", auth=(client.client_id,
                    Path("/test/client").read_text().strip()), data={"grant_type": "authorization_code",
                    "code": invalid_code, "redirect_uri": CALLBACK, "code_verifier": "v" * 64,
                    "resource": "https://wrong.example/mcp"}, timeout=5)
                assert response.status_code == 400 and response.json().get("error") == "invalid_target"
        print("Auth E2E: resource binding, PKCE negatives, ID-token rejection, Reader/Admin PASS", flush=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(setup)
        page.locator("#username").fill("synthetic-reader")
        page.locator("#password").fill(Path("/test/password").read_text().strip())
        with page.expect_response(
                lambda response: urlsplit(response.url).path == BASE_PATH + "/auth/callback") as rejected:
            page.locator("#kc-login").click(no_wait_after=True)
        assert rejected.value.status == 400
        assert not any(cookie["name"] == "__Host-mocu-session" for cookie in context.cookies())
        context.close()
        for user, expected in [("synthetic-other-admin", 403), ("synthetic-admin", 200)]:
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            seen = []
            page.on("request", lambda request, seen=seen: seen.append(request.url))
            page.goto(setup)
            page.locator("#username").fill(user)
            page.locator("#password").fill(Path("/test/password").read_text().strip())
            page.locator("#kc-login").click()
            page.wait_for_url(setup, timeout=15000)
            assert context.request.get(setup).status == expected
            assert all(setup.rsplit("/", 1)[1] not in url for url in seen if url.startswith(ISSUER))
            assert context.request.post(RESOURCE, data="{}").status == 401  # cookie never authenticates MCP
            if expected == 200:
                assert page.locator('input[name="password"]').count() == 1
                assert context.request.post(setup, data={}).status == 403
                page.reload()
                for name, value in {"display_name": "Synthetic", "imap_host": "localhost", "imap_port": "25",
                                    "username": "synthetic-user",
                                    "password": Path("/test/password").read_text().strip()}.items():
                    page.locator(f'input[name="{name}"]').fill(value)
                with page.expect_response(lambda response: response.url == setup and
                                          response.request.method == "POST") as submitted:
                    page.locator("button").click(no_wait_after=True)
                # CSRF/Origin accepted, but existing production port/SSRF policy rejects the IMAP target.
                assert submitted.value.status == 400
                print("Auth E2E: setup POST passes CSRF/Origin and rejects forbidden IMAP port PASS", flush=True)
                assert Path("/test/password").read_text().strip() not in submitted.value.text()
                page.goto(PUBLIC_BASE + "/auth/session")
                with page.expect_response(lambda response: response.url == PUBLIC_BASE + "/auth/logout") as logged_out:
                    page.locator("button").click(no_wait_after=True)
                print("Auth E2E: logout contract " + str({"status": logged_out.value.status,
                    "origin_matches": logged_out.value.request.headers.get("origin") == ORIGIN,
                    "origin_null": logged_out.value.request.headers.get("origin") == "null"}), flush=True)
                assert logged_out.value.status == 204
                assert context.request.get(PUBLIC_BASE + "/auth/session").status == 401
                expired = context.request.post(setup, data={})
                assert expired.status == 401 and "location" not in expired.headers
                assert "www-authenticate" not in expired.headers
            context.close()
        browser.close()
    print("Auth E2E: admin browser, creator binding, CSRF, logout, cookie isolation PASS", flush=True)


if __name__ == "__main__":
    try:
        if "--outage" in sys.argv:
            with requests.Session() as client:
                client.trust_env = False
                response = client.post(RESOURCE, json={}, verify="/test/ca.pem", timeout=10)
                assert response.status_code in (500, 502, 503)
                assert "Location" not in response.headers
                assert "WWW-Authenticate" not in response.headers
            print("Auth E2E: verifier outage fails closed PASS", flush=True)
        else:
            main()
    except Exception as exc:
        # Playwright/HTTP exceptions can echo OAuth URLs; never print them.
        frame = traceback.extract_tb(exc.__traceback__)[-1]
        print(f"Auth E2E: FAIL {type(exc).__name__} at line {frame.lineno}", flush=True)
        for frame in traceback.extract_tb(exc.__traceback__):
            if frame.filename.endswith("auth_browser_test.py"):
                print(f"Auth E2E: failure site {frame.name}:{frame.lineno}", flush=True)
        if exc.__context__ is not None:
            original = traceback.extract_tb(exc.__context__.__traceback__)[-1]
            print(f"Auth E2E: underlying {type(exc.__context__).__name__}:{original.lineno}", flush=True)
        if isinstance(exc, AssertionError) and str(exc).startswith("MCP status "):
            print("Auth E2E: " + str(exc), flush=True)
        raise SystemExit(1) from None
