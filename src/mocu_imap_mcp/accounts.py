"""Transactional local account storage. Never stores mail content."""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
import uuid
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from .auth_context import Principal
from .credentials import CredentialVault, SealedPassword


class AccountError(ValueError):
    """Sanitized local account/setup failure."""


class AccountInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    display_name: str = Field(min_length=1, max_length=120)
    imap_host: str = Field(min_length=1, max_length=253)
    imap_port: int = Field(default=993, ge=1, le=65535)
    tls_mode: Literal["ssl", "starttls"] = "ssl"
    username: str = Field(min_length=1, max_length=320)
    password: SecretStr = Field(exclude=True, repr=False)

    @field_validator("display_name", "imap_host", "username")
    @classmethod
    def no_controls(cls, value: str) -> str:
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Steuerzeichen sind nicht erlaubt")
        return value


class Account(BaseModel):
    id: str
    display_name: str
    imap_host: str
    imap_port: int
    tls_mode: Literal["ssl", "starttls"]
    username: str = Field(exclude=True, repr=False)
    enabled: bool
    revision: int
    created_at: float
    updated_at: float


class AccountStore:
    def __init__(self, path: Path, vault: CredentialVault) -> None:
        self.path = path
        self.vault = vault
        with self.connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2):
                raise AccountError("Unbekannte Datenbankversion")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                  id TEXT PRIMARY KEY, display_name TEXT NOT NULL, imap_host TEXT NOT NULL,
                  imap_port INTEGER NOT NULL, tls_mode TEXT NOT NULL, username TEXT NOT NULL,
                  ciphertext BLOB NOT NULL, nonce BLOB NOT NULL, key_id TEXT NOT NULL,
                  format_version INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                  revision INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL, updated_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS setup_tokens (
                  token_hash TEXT PRIMARY KEY, expires_at REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                  claimed INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0,
                  account_id TEXT REFERENCES accounts(id) ON DELETE CASCADE);
            """)
            if version < 2:
                db.execute("BEGIN IMMEDIATE")
                db.execute("ALTER TABLE setup_tokens ADD COLUMN owner_issuer TEXT")
                db.execute("ALTER TABLE setup_tokens ADD COLUMN owner_subject TEXT")
                db.execute("DELETE FROM setup_tokens")
                db.execute("PRAGMA user_version=2")
            for row in db.execute("SELECT id,ciphertext,nonce,key_id,format_version FROM accounts"):
                vault.decrypt(row["id"], self._sealed(row))

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        if not self.path.exists():
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _sealed(row: sqlite3.Row) -> SealedPassword:
        return SealedPassword(row["ciphertext"], row["nonce"], row["key_id"], row["format_version"])

    @staticmethod
    def _account(row: sqlite3.Row) -> Account:
        return Account.model_validate({k: row[k] for k in Account.model_fields})

    def list(self) -> list[Account]:
        with self.connection() as db:
            return [self._account(r) for r in db.execute("SELECT * FROM accounts ORDER BY id")]

    def get(self, account_id: str) -> Account:
        with self.connection() as db:
            row = db.execute("SELECT * FROM accounts WHERE id=? AND enabled=1", (account_id,)).fetchone()
            if row is None:
                raise AccountError("Konto unbekannt oder deaktiviert")
            return self._account(row)

    def password(self, account_id: str, expected_revision: int | None = None) -> SecretStr:
        with self.connection() as db:
            row = db.execute("SELECT * FROM accounts WHERE id=? AND enabled=1", (account_id,)).fetchone()
            if row is None:
                raise AccountError("Konto unbekannt oder deaktiviert")
            if expected_revision is not None and row["revision"] != expected_revision:
                raise AccountError("Kontokonfiguration geaendert; Aufruf neu starten")
            return SecretStr(self.vault.decrypt(account_id, self._sealed(row)))

    def begin_setup(self, account_id: str | None = None, *, owner: Principal) -> tuple[str, float]:
        if account_id is not None:
            self.get(account_id)
        token = secrets.token_urlsafe(32)
        expires = time.time() + 600
        with self.connection() as db:
            db.execute("DELETE FROM setup_tokens WHERE expires_at < ?", (time.time(),))
            if db.execute("SELECT count(*) FROM setup_tokens").fetchone()[0] >= 100:
                raise AccountError("Zu viele offene Einrichtungen")
            db.execute("""INSERT INTO setup_tokens(token_hash,expires_at,account_id,owner_issuer,owner_subject)
                       VALUES(?,?,?,?,?)""",
                       (hashlib.sha256(token.encode()).hexdigest(), expires, account_id, owner.issuer, owner.subject))
        return token, expires

    def check_owner(self, token: str, owner: Principal) -> None:
        with self.connection() as db:
            row = db.execute("""SELECT 1 FROM setup_tokens WHERE token_hash=? AND owner_issuer=?
                AND owner_subject=? AND used=0 AND attempts<3 AND expires_at>?""",
                (hashlib.sha256(token.encode()).hexdigest(), owner.issuer, owner.subject, time.time())).fetchone()
            if row is None:
                raise AccountError("Einrichtung ungueltig oder nicht fuer diesen Benutzer")

    def claim(self, token: str, *, owner: Principal) -> str | None:
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.connection() as db:
            cursor = db.execute("""UPDATE setup_tokens SET claimed=1,attempts=attempts+1
                WHERE token_hash=? AND used=0 AND claimed=0 AND attempts<3 AND expires_at>?
                AND owner_issuer=? AND owner_subject=?""",
                                (digest, time.time(), owner.issuer, owner.subject))
            if cursor.rowcount != 1:
                raise AccountError("Einrichtung abgelaufen, verwendet oder gesperrt")
            row = db.execute("SELECT account_id FROM setup_tokens WHERE token_hash=?", (digest,)).fetchone()
            return str(row[0]) if row[0] is not None else None

    def release(self, token: str) -> None:
        with self.connection() as db:
            db.execute("UPDATE setup_tokens SET claimed=0 WHERE token_hash=? AND used=0",
                       (hashlib.sha256(token.encode()).hexdigest(),))

    def finish(self, token: str, value: AccountInput) -> str:
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT account_id FROM setup_tokens
                WHERE token_hash=? AND claimed=1 AND used=0 AND expires_at>?""", (digest, time.time())).fetchone()
            if row is None:
                raise AccountError("Einrichtung nicht mehr gueltig")
            account_id = row[0] or str(uuid.uuid4())
            sealed = self.vault.encrypt(account_id, value.password.get_secret_value())
            now = time.time()
            if row[0] is None:
                db.execute("""INSERT INTO accounts
                    (id,display_name,imap_host,imap_port,tls_mode,username,ciphertext,nonce,key_id,
                    format_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (account_id, value.display_name, value.imap_host, value.imap_port, value.tls_mode,
                     value.username, sealed.ciphertext, sealed.nonce, sealed.key_id, sealed.version, now, now))
            else:
                cursor = db.execute("""UPDATE accounts SET display_name=?,imap_host=?,imap_port=?,tls_mode=?,
                    username=?,ciphertext=?,nonce=?,key_id=?,format_version=?,updated_at=?,revision=revision+1
                    WHERE id=? AND enabled=1""",
                    (value.display_name, value.imap_host, value.imap_port, value.tls_mode, value.username,
                     sealed.ciphertext, sealed.nonce, sealed.key_id, sealed.version, now, account_id))
                if cursor.rowcount != 1:
                    raise AccountError("Konto nicht mehr verfuegbar")
            db.execute("UPDATE setup_tokens SET used=1 WHERE token_hash=?", (digest,))
            return str(account_id)

    def delete(self, account_id: str) -> None:
        with self.connection() as db:
            db.execute("DELETE FROM accounts WHERE id=?", (account_id,))

    def set_enabled(self, account_id: str, enabled: bool) -> None:
        with self.connection() as db:
            db.execute("UPDATE accounts SET enabled=?,revision=revision+1,updated_at=? WHERE id=?",
                       (int(enabled), time.time(), account_id))

    def rotate(self, new_vault: CredentialVault) -> None:
        """Offline only: caller stops all services and backs up before rotation."""
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            for row in db.execute("SELECT * FROM accounts").fetchall():
                sealed = new_vault.encrypt(row["id"], self.vault.decrypt(row["id"], self._sealed(row)))
                db.execute("UPDATE accounts SET ciphertext=?,nonce=?,key_id=?,format_version=? WHERE id=?",
                           (sealed.ciphertext, sealed.nonce, sealed.key_id, sealed.version, row["id"]))
        self.vault = new_vault

    def backup(self, destination: Path) -> None:
        try:
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise AccountError("Backup-Ziel existiert bereits") from None
        os.close(fd)
        with self.connection() as db, closing(sqlite3.connect(destination)) as backup:
            db.backup(backup)
