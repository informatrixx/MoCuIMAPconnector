from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", hide_input_in_errors=True)
    oidc_issuer: str
    mcp_resource: str
    admin_oidc_client_id: str = "mocu-admin-web"
    admin_oidc_client_secret_file: Path
    oidc_ca_file: Path | None = None
    allowed_subjects: list[str] = Field(min_length=1)
    admin_subjects: list[str] = Field(default_factory=list)
    access_token_type_claim: str = "typ"
    access_token_type_value: str = "Bearer"
    gateway_bind: str = "127.0.0.1"
    gateway_port: int = Field(default=8766, ge=1, le=65535)
    gateway_proxy_ips: list[str] = Field(default_factory=lambda: ["127.0.0.1"])
    session_idle_seconds: int = Field(default=180, ge=30, le=300)
    session_absolute_seconds: int = Field(default=300, ge=30, le=300)
    jwks_cache_seconds: int = Field(default=300, ge=30, le=600)
    jwks_refresh_seconds: int = Field(default=30, ge=5, le=60)

    @property
    def origin(self) -> str:
        return self.mcp_resource.removesuffix("/mcp")

    @model_validator(mode="after")
    def validate_urls(self) -> GatewaySettings:
        from ipaddress import ip_address
        for value in (self.oidc_issuer, self.mcp_resource):
            url = urlsplit(value)
            if (url.scheme != "https" or not url.hostname or url.username or url.password or url.query or
                    url.fragment or any(ord(c) < 33 or ord(c) > 126 or c in {'"', '\\'} for c in value)):
                raise ValueError("Exakte HTTPS-URLs ohne Credentials erforderlich")
        if urlsplit(self.mcp_resource).path != "/mcp":
            raise ValueError("MCP_RESOURCE muss den exakten /mcp Endpoint bezeichnen")
        if not set(self.admin_subjects).issubset(self.allowed_subjects):
            raise ValueError("Admins muessen explizit freigeschaltet sein")
        for subject in self.allowed_subjects:
            if not subject or any(ord(c) < 33 or ord(c) > 126 or c in {',', ';'} for c in subject):
                raise ValueError("Ungueltige Subject-ID")
        for peer in self.gateway_proxy_ips:
            ip_address(peer)
        return self
