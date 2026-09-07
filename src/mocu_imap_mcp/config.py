from __future__ import annotations

import base64
import json
import re
from typing import Any, Literal

from pydantic import AliasChoices, Field, SecretStr, field_serializer, field_validator, model_validator
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
        hide_input_in_errors=True,
    )

    imap_host: str = "imap.gmx.net"
    imap_port: int = Field(default=993, ge=1, le=65535)
    imap_tls_mode: Literal["ssl", "starttls"] = "ssl"
    imap_ssl: bool | None = None
    imap_connection_timeout: int = Field(default=30, ge=1, le=120)
    imap_connection_retries: int = Field(default=3, ge=1, le=10)
    imap_retry_delay: float = Field(default=1.5, ge=0.1, le=30.0)
    imap_username: str = ""
    imap_password: SecretStr = SecretStr("")
    cursor_signing_key: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices(
            "cursor_signing_key",
            "CURSOR_SIGNING_KEY_HEX",
            "CURSOR_SIGNING_KEY",
        ),
    )

    mcp_bind: str = "127.0.0.1"
    mcp_port: int = Field(default=8765, ge=1, le=65535)
    mcp_http_path: str = "/mcp"
    max_search_results: int = Field(default=100, ge=1, le=500)
    default_search_limit: int = Field(default=50, ge=1, le=100)
    search_scan_batch_size: int = Field(default=100, ge=1, le=1000)
    max_attachment_size_mb: int = Field(default=25, ge=1, le=500)
    max_message_size_mb: int = Field(default=50, ge=1, le=1024)
    max_body_chars: int = Field(default=200_000, ge=1, le=1_000_000)
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

    @field_validator("imap_tls_mode", mode="before")
    @classmethod
    def _normalize_tls_mode(cls, value: Any) -> str:
        if isinstance(value, str):
            normalized = value.strip().lower()
            if not normalized:
                return "ssl"
            if normalized not in {"ssl", "starttls"}:
                raise ValueError("IMAP_TLS_MODE muss ssl oder starttls sein.")
            return normalized
        return str(value).strip().lower() if value is not None else "ssl"

    @field_validator("cursor_signing_key", mode="after")
    @classmethod
    def _validate_cursor_signing_key(cls, value: SecretStr) -> SecretStr:
        if not value:
            raise ValueError(
                "CURSOR_SIGNING_KEY_HEX muss gesetzt und sicher geheim gehalten werden."
            )

        raw = value.get_secret_value()
        raw = raw.strip()
        if not raw:
            raise ValueError(
                "CURSOR_SIGNING_KEY_HEX muss gesetzt und sicher geheim gehalten werden."
            )

        if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
            return value

        b64_chars = raw.rstrip("=")
        padding = "=" * ((4 - len(b64_chars) % 4) % 4)
        try:
            decoded = base64.urlsafe_b64decode(b64_chars + padding)
        except Exception as e:
            raise ValueError("CURSOR_SIGNING_KEY_HEX muss 64 Hex-Zeichen oder Base64url mit >= 32 Bytes sein.") from e
        if len(decoded) < 32:
            raise ValueError("CURSOR_SIGNING_KEY_HEX muss mindestens 32 zufällige Bytes enthalten.")
        return value

    @model_validator(mode="after")
    def _migrate_legacy_ssl_toggle(self) -> Settings:
        if self.imap_ssl is not None:
            if self.imap_ssl is False:
                raise ValueError(
                    "IMAP_SSL=false ist nicht zulässig. "
                    "Für den Wechsel auf STARTTLS bitte IMAP_TLS_MODE=starttls setzen."
                )
            if self.imap_tls_mode != "ssl":
                raise ValueError(
                    "IMAP_TLS_MODE ist bereits gesetzt. Bitte IMAP_SSL nicht zusätzlich verwenden."
                )
            object.__setattr__(self, "imap_tls_mode", "ssl")
        return self

    def __repr__(self) -> str:
        data = self.model_dump(by_alias=False)
        if "imap_password" in data:
            data["imap_password"] = "***REDACTED***"
        if "cursor_signing_key" in data:
            data["cursor_signing_key"] = "***REDACTED***"
        values = ", ".join(f"{key}={value!r}" for key, value in sorted(data.items()))
        return f"Settings({values})"

    def cursor_signing_key_bytes(self) -> bytes:
        return decode_cursor_signing_key(self.cursor_signing_key.get_secret_value())


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
    return settings


class CursorSigningKeyError(ValueError):
    """Raised if the cursor signing key cannot be decoded."""


def decode_cursor_signing_key(raw: str) -> bytes:
    trimmed = raw.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", trimmed):
        return bytes.fromhex(trimmed)

    b64_chars = trimmed.rstrip("=")
    padding = "=" * ((4 - len(b64_chars) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(b64_chars + padding)
    except Exception as exc:
        raise CursorSigningKeyError(
            "CURSOR_SIGNING_KEY_HEX oder CURSOR_SIGNING_KEY enthält kein gültiges Base64url."
        ) from exc
    if len(decoded) < 32:
        raise CursorSigningKeyError(
            "CURSOR_SIGNING_KEY_HEX oder CURSOR_SIGNING_KEY muss mindestens 32 dekodierte Bytes haben."
        )
    return decoded
