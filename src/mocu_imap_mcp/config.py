from __future__ import annotations

import json
from typing import Any

from pydantic import Field, SecretStr, field_serializer, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _split_csv(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        text = values.strip()
        if not text:
            return []
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = None
            else:
                if isinstance(parsed, list):
                    return [str(value).strip() for value in parsed if str(value).strip()]
        return [value.strip() for value in values.split(",") if value.strip()]
    if isinstance(values, list):
        return [str(value).strip() for value in values if str(value).strip()]
    return []


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    imap_host: str = "imap.gmx.net"
    imap_port: int = Field(default=993, ge=1, le=65535)
    imap_ssl: bool = True
    imap_username: str = ""
    imap_password: SecretStr = SecretStr("")
    imap_connection_timeout: int = Field(default=30, ge=1, le=120)
    imap_connection_retries: int = Field(default=3, ge=1, le=10)
    imap_retry_delay: float = Field(default=1.5, ge=0.1, le=30.0)
    cursor_signing_key: str = Field(default="")

    mcp_bind: str = "127.0.0.1"
    mcp_port: int = Field(default=8765, ge=1, le=65535)
    mcp_http_path: str = "/mcp"
    max_search_results: int = Field(default=100, ge=1, le=500)
    default_search_limit: int = Field(default=50, ge=1, le=100)
    search_scan_batch_size: int = Field(default=100, ge=1, le=1000)
    max_attachment_size_mb: int = Field(default=25, ge=1, le=500)
    mcp_max_request_body_size: int = Field(default=4 * 1024 * 1024, ge=1)
    log_level: str = "INFO"

    mcp_allowed_hosts: list[str] | str = Field(default_factory=list)
    mcp_allowed_origins: list[str] | str = Field(default_factory=list)

    @field_serializer("imap_password")
    def _redact_secret(self, _value: str, _info: Any) -> str:
        return "***redacted***"

    @field_validator("mcp_allowed_hosts", "mcp_allowed_origins", mode="before")
    @classmethod
    def _split_csv_fields(cls, value: Any) -> list[str]:
        return _split_csv(value)

    def __repr__(self) -> str:
        data = self.model_dump(by_alias=False)
        if "imap_password" in data:
            data["imap_password"] = "***REDACTED***"
        values = ", ".join(f"{key}={value!r}" for key, value in sorted(data.items()))
        return f"Settings({values})"


def get_settings() -> Settings:
    settings = Settings()
    if not settings.mcp_allowed_hosts:
        settings.mcp_allowed_hosts = ["127.0.0.1", "127.0.0.1:*"]
    if not settings.mcp_allowed_origins:
        settings.mcp_allowed_origins = [
            "https://127.0.0.1",
            "https://localhost",
            "http://127.0.0.1",
            "http://localhost",
        ]
    if not settings.cursor_signing_key:
        raise ValueError("CURSOR_SIGNING_KEY muss gesetzt und sicher geheim gehalten werden.")
    return settings
