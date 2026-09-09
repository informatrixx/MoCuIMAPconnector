from __future__ import annotations

import base64
from pathlib import Path

import pytest

from mocu_imap_mcp.runtime import Runtime, RuntimeSettings


@pytest.fixture
def runtime(tmp_path: Path) -> Runtime:
    key = tmp_path / "test.key"
    key.write_bytes(base64.urlsafe_b64encode(bytes(range(32))))
    return Runtime(RuntimeSettings(database_path=tmp_path / "accounts.sqlite3", mocu_master_key_file=key))
