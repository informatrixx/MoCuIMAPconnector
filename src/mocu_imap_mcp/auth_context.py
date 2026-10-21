"""Verified request identity; never populated from mail or OAuth request scopes."""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Principal:
    issuer: str
    subject: str
    scopes: frozenset[str]
    role: str
    auth_type: str


principal: ContextVar[Principal | None] = ContextVar("mocu_identity", default=None)


class AccessDenied(ValueError):
    """Authorization denied without a re-login loop."""


class MissingScope(AccessDenied):
    def __init__(self, scope: str) -> None:
        self.scope = scope
        super().__init__("Zusaetzlicher OAuth-Scope erforderlich")


def require_access(*, admin: bool = False) -> Principal:
    current = principal.get()
    if current is None:
        raise AccessDenied("Authentifizierung erforderlich")
    if admin and current.role != "admin":
        raise AccessDenied("Administrative Berechtigung erforderlich")
    for scope in (("mocu:read", "mocu:admin") if admin else ("mocu:read",)):
        if scope not in current.scopes:
            raise MissingScope(scope)
    return current


def challenge(resource: str, *, error: Literal["invalid_token", "insufficient_scope"] | None = None,
              scope: str | None = None) -> str:
    """Build discovery/error headers from configuration and fixed values, never claims."""
    if (any(ord(c) < 33 or ord(c) > 126 or c in {'"', '\\'} for c in resource) or
            error not in {None, "invalid_token", "insufficient_scope"} or
            scope not in {None, "mocu:read", "mocu:admin"} or
            (scope is not None and error != "insufficient_scope")):
        raise ValueError("Ungueltige OAuth-Challenge-Konfiguration")
    origin = resource.removesuffix("/mcp")
    value = f'Bearer resource_metadata="{origin}/.well-known/oauth-protected-resource/mcp"'
    if error:
        value += f', error="{error}"'
    if scope:
        value += f', scope="{scope}"'
    return value
