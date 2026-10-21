"""Verified request identity; never populated from mail or OAuth request scopes."""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass


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


def challenge(resource: str, scope: str = "mocu:read") -> str:
    origin = resource.removesuffix("/mcp")
    return (f'Bearer resource_metadata="{origin}/.well-known/oauth-protected-resource/mcp", '
            f'error="insufficient_scope", error_description="Required OAuth scope missing", scope="{scope}"')
