"""Multi-account process configuration and per-request IMAP lifecycle."""
from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .accounts import AccountError, AccountInput, AccountStore
from .config import Settings
from .credentials import CredentialVault
from .imap_client import ImapClient
from .network import connection_factory


class RuntimeSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", hide_input_in_errors=True)
    database_path: Path = Path("/data/mocu-imap.sqlite3")
    mocu_master_key_file: Path = Path("/run/secrets/mocu_master_key")
    mcp_bind: str = "127.0.0.1"
    mcp_port: int = Field(default=8765, ge=1, le=65535)
    public_base_url: str = "https://imap-mcp.example.at"
    access_mode: Literal["local", "trusted_proxy"] = "local"
    trusted_proxy_ips: list[str] = Field(default_factory=list)
    mcp_allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "127.0.0.1:*", "localhost:*"])
    max_attachment_size_mb: int = Field(default=25, ge=1, le=100)
    max_message_size_mb: int = Field(default=50, ge=1, le=100)
    max_body_chars: int = Field(default=200000, ge=1, le=1000000)
    search_scan_budget: int = Field(default=500, ge=1, le=5000)
    search_time_budget: int = Field(default=45, ge=1, le=120)

    @model_validator(mode="after")
    def validate_runtime(self) -> RuntimeSettings:
        from urllib.parse import urlsplit

        url = urlsplit(self.public_base_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("PUBLIC_BASE_URL muss eine HTTPS-Origin sein")
        if url.path not in ("", "/"):
            raise ValueError("PUBLIC_BASE_URL darf keinen Pfad enthalten")
        if self.access_mode == "trusted_proxy" and not self.trusted_proxy_ips:
            raise ValueError("TRUSTED_PROXY_IPS muss explizit gesetzt werden")
        return self


def load_runtime_settings() -> RuntimeSettings:
    if any(os.environ.get(k) for k in ("IMAP_USERNAME", "IMAP_PASSWORD", "IMAP_HOST", "IMAP_PORT",
                                       "CURSOR_SIGNING_KEY", "CURSOR_SIGNING_KEY_HEX")):
        raise AccountError("Legacy-Kontokonfiguration entfernen; Konto ueber geschuetztes Setup neu einrichten")
    return RuntimeSettings()


class Runtime:
    def __init__(self, settings: RuntimeSettings) -> None:
        self.settings = settings
        self.store = AccountStore(settings.database_path, CredentialVault.from_file(settings.mocu_master_key_file))

    def client_settings(self, value: AccountInput) -> Settings:
        # AccountInput and RuntimeSettings already validated these fields. Avoid
        # reading legacy .env/process values when constructing a per-account client.
        return Settings.model_construct(
            imap_host=value.imap_host, imap_port=value.imap_port,
            imap_tls_mode=value.tls_mode, imap_username=value.username, imap_password=SecretStr(""),
            cursor_signing_key=SecretStr(self.store.vault.cursor_key.hex()), imap_connection_retries=2,
            max_attachment_size_mb=self.settings.max_attachment_size_mb,
            max_message_size_mb=self.settings.max_message_size_mb, max_body_chars=self.settings.max_body_chars,
        )

    @contextmanager
    def client(self, account_id: str) -> Iterator[ImapClient]:
        account = self.store.get(account_id)
        value = AccountInput(display_name=account.display_name, imap_host=account.imap_host,
                             imap_port=account.imap_port, tls_mode=account.tls_mode,
                             username=account.username, password=SecretStr(""))
        def password() -> str:
            if self.store.get(account_id).revision != account.revision:
                raise AccountError("Kontokonfiguration wurde geaendert; Aufruf neu starten")
            return self.store.password(account_id, account.revision).get_secret_value()

        with ImapClient(self.client_settings(value), connector=connection_factory,
                        credential_provider=password) as client:
            yield client
            if self.store.get(account_id).revision != account.revision:
                raise AccountError("Kontokonfiguration wurde geaendert; Aufruf neu starten")

    def setup(self, token: str, value: AccountInput) -> str:
        self.store.claim(token)
        try:
            with ImapClient(self.client_settings(value), connector=connection_factory,
                            credential_provider=value.password.get_secret_value) as client:
                client.list_mailboxes()
            return self.store.finish(token, value)
        finally:
            self.store.release(token)
