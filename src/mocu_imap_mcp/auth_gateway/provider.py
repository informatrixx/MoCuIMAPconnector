"""Fixed-issuer OIDC client and bounded JWKS verifier. No token-directed fetches."""
from __future__ import annotations

import json
import threading
import time
from typing import Any
from urllib.parse import urlsplit

import jwt
import requests
from authlib.integrations.requests_client import OAuth2Session  # type: ignore[import-untyped]
from authlib.oidc.core import CodeIDToken  # type: ignore[import-untyped]

from ..auth_context import AccessDenied, Principal
from .config import GatewaySettings
from .state import Transaction


class BoundedOAuthSession(OAuth2Session):  # type: ignore[misc]
    def send(self, request: Any, **kwargs: Any) -> requests.Response:
        kwargs.update(timeout=(3, 5), stream=True, allow_redirects=False)
        response = super().send(request, **kwargs)
        try:
            data = bytearray()
            deadline = time.monotonic() + 10
            for chunk in response.iter_content(8192):
                data.extend(chunk)
                if len(data) > 262144 or time.monotonic() > deadline:
                    raise ValueError("Provider-Antwort zu gross oder zu langsam")
            response._content = bytes(data)
            response._content_consumed = True
            return response  # type: ignore[no-any-return]
        finally:
            response.close()


class Provider:
    def __init__(self, settings: GatewaySettings) -> None:
        self.settings = settings
        self.metadata: dict[str, Any] = {}
        self.keys: dict[str, jwt.PyJWK] = {}
        self.keys_until = 0.0
        self.refresh_after = 0.0
        self.lock = threading.Lock()

    def _json(self, url: str) -> dict[str, Any]:
        with BoundedOAuthSession() as client:
            client.trust_env = False
            client.verify = str(self.settings.oidc_ca_file) if self.settings.oidc_ca_file else True
            # A CA bundle can be configured explicitly; never disable TLS verification.
            response = client.get(url, withhold_token=True)
            response.raise_for_status()
            result = json.loads(response.content)
            if not isinstance(result, dict):
                raise ValueError("Ungueltige Provider-Antwort")
            return result

    def discover(self) -> None:
        metadata = self._json(self.settings.oidc_issuer + "/.well-known/openid-configuration")
        if metadata.get("issuer") != self.settings.oidc_issuer:
            raise ValueError("Issuer stimmt nicht ueberein")
        origin = urlsplit(self.settings.oidc_issuer)
        for name in ("jwks_uri", "authorization_endpoint", "token_endpoint"):
            url = urlsplit(metadata.get(name, ""))
            if (url.scheme, url.netloc) != (origin.scheme, origin.netloc) or url.username or url.fragment:
                raise ValueError("Provider-Endpoint ausserhalb des konfigurierten Issuers")
        if "S256" not in metadata.get("code_challenge_methods_supported", []):
            raise ValueError("Provider unterstuetzt kein PKCE S256")
        if "client_secret_basic" not in metadata.get("token_endpoint_auth_methods_supported", []):
            raise ValueError("Provider unterstuetzt die konfigurierte Client-Authentifizierung nicht")
        self.metadata = metadata

    def _key(self, kid: str) -> jwt.PyJWK:
        with self.lock:
            now = time.monotonic()
            if kid in self.keys and now < self.keys_until:
                return self.keys[kid]
            if now < self.refresh_after:
                raise ValueError("Signaturschluessel nicht verfuegbar")
            self.refresh_after = now + self.settings.jwks_refresh_seconds
            if not self.metadata:
                self.discover()
            data = self._json(self.metadata["jwks_uri"])
            keys = data.get("keys", [])
            if not isinstance(keys, list) or len(keys) > 32:
                raise ValueError("Ungueltiges JWKS")
            refreshed = {}
            for key in keys:
                if key.get("use", "sig") == "sig" and key.get("alg", "RS256") == "RS256":
                    key_id = key.get("kid")
                    if not isinstance(key_id, str) or key_id in refreshed:
                        raise ValueError("Mehrdeutiges JWKS")
                    refreshed[key_id] = jwt.PyJWK.from_dict(key, algorithm="RS256")
            self.keys = refreshed
            self.keys_until = time.monotonic() + self.settings.jwks_cache_seconds
            if kid not in self.keys:
                raise ValueError("Signaturschluessel unbekannt")
            return self.keys[kid]

    def decode(self, token: str, audience: str) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            if not token or len(token) > 16384:
                raise ValueError
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                raise ValueError
            claims = jwt.decode(token, self._key(header["kid"]), algorithms=["RS256"],
                                issuer=self.settings.oidc_issuer, audience=audience,
                                options={"require": ["iss", "aud", "exp", "sub"]})
            if not isinstance(claims["sub"], str) or not claims["sub"]:
                raise ValueError
        except Exception:
            raise ValueError("Token ungueltig oder Provider nicht verfuegbar") from None
        if claims["sub"] not in self.settings.allowed_subjects:
            raise AccessDenied("Benutzer nicht freigeschaltet")
        return claims, header

    def access(self, token: str) -> Principal:
        claims, _ = self.decode(token, self.settings.mcp_resource)
        if claims.get(self.settings.access_token_type_claim) != self.settings.access_token_type_value:
            raise ValueError("Kein Access-Token")
        scope = claims.get("scope", "")
        if not isinstance(scope, str) or len(scope) > 4096:
            raise ValueError("Ungueltige Scopes")
        return self._identity(claims["sub"], frozenset(scope.split()), "bearer")

    def _identity(self, subject: str, scopes: frozenset[str], auth_type: str) -> Principal:
        role = "admin" if subject in self.settings.admin_subjects else "reader"
        return Principal(self.settings.oidc_issuer, subject, scopes, role, auth_type)

    def client(self) -> BoundedOAuthSession:
        secret = self.settings.admin_oidc_client_secret_file.read_text().strip()
        if len(secret) < 16:
            raise ValueError("OIDC-Client-Secret fehlt")
        client = BoundedOAuthSession(self.settings.admin_oidc_client_id, secret,
            token_endpoint_auth_method="client_secret_basic", scope="openid",
            redirect_uri=self.settings.origin + "/auth/callback", code_challenge_method="S256")
        client.trust_env = False
        client.verify = str(self.settings.oidc_ca_file) if self.settings.oidc_ca_file else True
        return client

    def authorize(self, item: Transaction) -> str:
        if not self.metadata:
            self.discover()
        with self.client() as client:
            url, _ = client.create_authorization_url(self.metadata["authorization_endpoint"],
                state=item.state, code_verifier=item.verifier, nonce=item.nonce)
            return str(url)

    def callback(self, item: Transaction, code: str) -> Principal:
        with self.client() as client:
            token = client.fetch_token(self.metadata["token_endpoint"], code=code,
                                       code_verifier=item.verifier, grant_type="authorization_code")
        claims, header = self.decode(token["id_token"], self.settings.admin_oidc_client_id)
        CodeIDToken(claims, header, params={"nonce": item.nonce,
            "client_id": self.settings.admin_oidc_client_id, "access_token": token.get("access_token")}).validate()
        if claims["sub"] not in self.settings.admin_subjects:
            raise ValueError("Administrative Berechtigung erforderlich")
        return self._identity(claims["sub"], frozenset({"mocu:read", "mocu:admin"}), "session")
