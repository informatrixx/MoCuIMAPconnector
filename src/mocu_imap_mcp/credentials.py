"""Versioned authenticated credential encryption; no plaintext serialization."""
from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CredentialError(ValueError):
    """Credential storage cannot be unlocked or authenticated."""


@dataclass(frozen=True)
class SealedPassword:
    ciphertext: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    key_id: str
    version: int = 1


class CredentialVault:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise CredentialError("Master-Key muss genau 32 Bytes enthalten")
        self._cipher = AESGCM(key)
        self.key_id = hashlib.sha256(key).hexdigest()[:32]
        self.cursor_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"mocu/cursor/v4",
        ).derive(key)

    @classmethod
    def from_file(cls, path: Path) -> CredentialVault:
        try:
            with path.open("rb") as stream:
                raw = stream.read(128).strip()
            key = base64.b64decode(raw, altchars=b"-_", validate=True)
            return cls(key)
        except (OSError, ValueError):
            raise CredentialError("Master-Key-Datei fehlt oder ist ungueltig") from None

    def encrypt(self, account_id: str, password: str) -> SealedPassword:
        nonce = os.urandom(12)
        aad = ("mocu/credential/v1/" + account_id).encode()
        return SealedPassword(self._cipher.encrypt(nonce, password.encode(), aad), nonce, self.key_id)

    def decrypt(self, account_id: str, sealed: SealedPassword) -> str:
        if sealed.version != 1 or sealed.key_id != self.key_id:
            raise CredentialError("Credential-Schluessel oder Format passt nicht")
        try:
            return self._cipher.decrypt(
                sealed.nonce, sealed.ciphertext, ("mocu/credential/v1/" + account_id).encode(),
            ).decode()
        except (InvalidTag, ValueError, UnicodeError):
            raise CredentialError("Credential-Authentifizierung fehlgeschlagen") from None
