from __future__ import annotations

import base64
from collections.abc import Iterator
from pathlib import Path

import pytest

from mocu_imap_mcp.auth_context import Principal, principal
from mocu_imap_mcp.runtime import Runtime, RuntimeSettings


@pytest.fixture
def runtime(tmp_path: Path) -> Iterator[Runtime]:
    key = tmp_path / "test.key"
    key.write_bytes(base64.urlsafe_b64encode(bytes(range(32))))
    marker = principal.set(Principal("https://issuer.example/realm", "fixture-admin",
                           frozenset({"mocu:read", "mocu:admin"}), "admin", "bearer"))
    try:
        yield Runtime(RuntimeSettings(database_path=tmp_path / "accounts.sqlite3", mocu_master_key_file=key))
    finally:
        principal.reset(marker)
