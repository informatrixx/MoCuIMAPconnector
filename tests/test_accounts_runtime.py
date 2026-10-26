from __future__ import annotations

import dataclasses
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import SecretStr

from mocu_imap_mcp.accounts import AccountError, AccountInput, AccountStore
from mocu_imap_mcp.auth_context import require_access
from mocu_imap_mcp.credentials import CredentialError, CredentialVault
from mocu_imap_mcp.runtime import Runtime


def account_input() -> AccountInput:
    return AccountInput(display_name="Fixture", imap_host="imap.example.org", username="fixture@example.org",
                        password=SecretStr("synthetic-password-only"))


def add_account(runtime: Runtime) -> str:
    token, _ = runtime.store.begin_setup(owner=require_access())
    runtime.store.claim(token, owner=require_access())
    return runtime.store.finish(token, account_input())


@pytest.mark.parametrize("nonce", [None, bytes.fromhex("0000000000000000000000f9")],
                         ids=["random", "ciphertext-starts-with-x"])
def test_crypto_aad_nonce_key_tampering(nonce: bytes | None, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = CredentialVault(bytes(range(32)))
    if nonce is None:
        sealed = vault.encrypt("account-a", "synthetic-password-only")
    else:
        # Synthetic fixture reproduces the old no-op replacement with certainty.
        with monkeypatch.context() as patch:
            patch.setattr("mocu_imap_mcp.credentials.os.urandom", lambda length: nonce)
            sealed = vault.encrypt("account-a", "synthetic-password-only")
        assert sealed.ciphertext[0] == ord("x")
    assert vault.decrypt("account-a", sealed) == "synthetic-password-only"
    assert vault.encrypt("account-a", "synthetic-password-only").nonce != sealed.nonce
    changed_ciphertext = bytes([sealed.ciphertext[0] ^ 1]) + sealed.ciphertext[1:]
    changed_nonce = bytes([sealed.nonce[0] ^ 1]) + sealed.nonce[1:]
    changed_tag = sealed.ciphertext[:-1] + bytes([sealed.ciphertext[-1] ^ 1])
    assert changed_ciphertext != sealed.ciphertext
    assert changed_nonce != sealed.nonce
    assert changed_tag != sealed.ciphertext
    for other, account, blob in [
        (vault, "account-b", sealed),
        (CredentialVault(b"x" * 32), "account-a", sealed),
        (vault, "account-a", dataclasses.replace(sealed, ciphertext=changed_ciphertext)),
        (vault, "account-a", dataclasses.replace(sealed, nonce=changed_nonce)),
        (vault, "account-a", dataclasses.replace(sealed, ciphertext=changed_tag)),
    ]:
        with pytest.raises(CredentialError):
            other.decrypt(account, blob)


def test_storage_rotation_backup_and_no_plaintext(runtime: Runtime, tmp_path: Path) -> None:
    account_id = add_account(runtime)
    assert runtime.store.password(account_id).get_secret_value() == "synthetic-password-only"
    assert b"synthetic-password-only" not in runtime.store.path.read_bytes()
    assert "synthetic-password-only" not in repr(account_input()) + account_input().model_dump_json()
    old_vault = runtime.store.vault
    backup = tmp_path / "backup.sqlite3"
    runtime.store.backup(backup)
    new_vault = CredentialVault(b"n" * 32)
    runtime.store.rotate(new_vault)
    restored = AccountStore(runtime.store.path, new_vault)
    assert restored.password(account_id).get_secret_value() == "synthetic-password-only"
    with pytest.raises(CredentialError):
        AccountStore(runtime.store.path, old_vault)
    assert AccountStore(backup, old_vault).get(account_id).id == account_id


def test_tokens_single_claim_and_bounded_retries(runtime: Runtime) -> None:
    owner = require_access()
    token, _ = runtime.store.begin_setup(owner=owner)

    def claim() -> bool:
        try:
            runtime.store.claim(token, owner=owner)
            return True
        except AccountError:
            return False

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert sum(executor.map(lambda _: claim(), range(4))) == 1
    runtime.store.finish(token, account_input())
    with pytest.raises(AccountError):
        runtime.store.claim(token, owner=owner)
    token, _ = runtime.store.begin_setup(owner=owner)
    for _ in range(3):
        runtime.store.claim(token, owner=owner)
        runtime.store.release(token)
    with pytest.raises(AccountError):
        runtime.store.claim(token, owner=owner)


def test_expired_and_disabled_accounts(runtime: Runtime) -> None:
    token, _ = runtime.store.begin_setup(owner=require_access())
    with runtime.store.connection() as db:
        db.execute("UPDATE setup_tokens SET expires_at=0")
    with pytest.raises(AccountError):
        runtime.store.claim(token, owner=require_access())
    account_id = add_account(runtime)
    revision = runtime.store.get(account_id).revision
    runtime.store.set_enabled(account_id, False)
    with pytest.raises(AccountError):
        runtime.store.password(account_id, revision)
    runtime.store.set_enabled(account_id, True)
    with pytest.raises(AccountError):
        runtime.store.password(account_id, revision)
    runtime.store.delete(account_id)
    assert runtime.store.list() == []


def test_failed_rotation_rolls_back(runtime: Runtime, monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = add_account(runtime), add_account(runtime)
    before = runtime.store.path.read_bytes()
    original = runtime.store.vault.decrypt
    calls = 0

    def decrypt(*args: object) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise CredentialError("synthetic failure")
        return original(*args)  # type: ignore[arg-type]

    monkeypatch.setattr(runtime.store.vault, "decrypt", decrypt)
    with pytest.raises(CredentialError):
        runtime.store.rotate(CredentialVault(b"r" * 32))
    assert runtime.store.path.read_bytes() == before
    assert {a.id for a in runtime.store.list()} == {first, second}


def test_setup_failure_preserves_account_and_redacts(runtime: Runtime, monkeypatch: pytest.MonkeyPatch) -> None:
    account_id = add_account(runtime)
    revision = runtime.store.get(account_id).revision
    token, _ = runtime.store.begin_setup(account_id, owner=require_access())

    def fail(*args: object, **kwargs: object) -> None:
        raise TimeoutError("synthetic failure")

    monkeypatch.setattr("mocu_imap_mcp.runtime.connection_factory", fail)
    with pytest.raises(Exception, match="IMAP-Verbindung"):
        runtime.setup(token, account_input(), require_access())
    assert runtime.store.get(account_id).revision == revision
    assert runtime.store.password(account_id).get_secret_value() == "synthetic-password-only"
    runtime.store.claim(token, owner=require_access())


def test_example_runtime_config_is_parseable() -> None:
    from mocu_imap_mcp.runtime import RuntimeSettings

    for filename in (".env.example", "deploy/mocu-imap-mcp.env.example"):
        config = RuntimeSettings(_env_file=filename)
        assert isinstance(config.mcp_allowed_hosts, list)
        assert config.access_mode == "local"
