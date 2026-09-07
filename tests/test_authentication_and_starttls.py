from __future__ import annotations

import imaplib

from mocu_imap_mcp.config import Settings
from mocu_imap_mcp.imap_client import ImapClient
from mocu_imap_mcp.security import AuthenticationError, ImapConnectionError


def test_starttls_connect_sequence() -> None:
    calls: list[str] = []

    class _FakeImap:
        def __init__(self, _host: str, port: int, timeout: int, **_kwargs: object) -> None:
            calls.append("connect")
            self.port = port
            self.timeout = timeout

        def capability(self) -> tuple[str, list[bytes]]:
            calls.append("capability")
            return "OK", [b"IMAP4rev1 STARTTLS"]

        def starttls(self, _context: object | None = None) -> tuple[str, list[bytes]]:
            calls.append("starttls")
            return "OK", [b""]

        def login(self, _user: str, _password: str) -> tuple[str, list[bytes]]:
            calls.append("login")
            return "OK", [b""]

        def logout(self) -> tuple[str, list[bytes]]:
            calls.append("logout")
            return "OK", [b""]

    original_imap4 = __import__("mocu_imap_mcp.imap_client", fromlist=["imaplib"]).imaplib.IMAP4
    try:
        module = __import__("mocu_imap_mcp.imap_client", fromlist=["imaplib"])
        module.imaplib.IMAP4 = _FakeImap  # type: ignore[assignment]
        settings = Settings(
            imap_host="imap.example",
            imap_port=993,
            imap_username="user",
            imap_password="password",
            imap_tls_mode="starttls",
            cursor_signing_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        ImapClient(settings).connect()
    finally:
        module.imaplib.IMAP4 = original_imap4  # type: ignore[assignment]

    assert calls[:4] == ["connect", "capability", "starttls", "capability"]
    assert calls[-1] == "login"


def test_plaintext_password_is_not_replayed() -> None:
    class _FakeImapSSL:
        def __init__(self, host: str, port: int, timeout: int, ssl_context: object | None = None) -> None:
            pass

        def login(self, _user: str, _password: str) -> tuple[str, list[bytes]]:
            raise imaplib.IMAP4.error("AUTHENTICATIONFAILED user bad credentials")

        def logout(self) -> tuple[str, list[bytes]]:
            return "OK", [b""]

    module = __import__("mocu_imap_mcp.imap_client", fromlist=["imaplib"])
    original_imap4_ssl = module.imaplib.IMAP4_SSL
    try:
        module.imaplib.IMAP4_SSL = _FakeImapSSL  # type: ignore[assignment]
        settings = Settings(
            imap_host="imap.example",
            imap_port=993,
            imap_username="user",
            imap_password="super-secret-pass",
            cursor_signing_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        client = ImapClient(settings)
        client.connect()
    except AuthenticationError as exc:
        assert "super-secret-pass" not in str(exc)
    else:
        raise AssertionError("AuthenticationError wurde nicht ausgelöst")
    finally:
        module.imaplib.IMAP4_SSL = original_imap4_ssl  # type: ignore[assignment]


def test_timeout_during_login_becomes_connection_error() -> None:
    class _FakeImapTimeout:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.calls = 0

        def login(self, _user: str, _password: str) -> tuple[str, list[bytes]]:
            self.calls += 1
            raise TimeoutError("timeout")

        def logout(self) -> tuple[str, list[bytes]]:
            return "OK", [b""]

    module = __import__("mocu_imap_mcp.imap_client", fromlist=["imaplib"])
    original_imap4_ssl = module.imaplib.IMAP4_SSL
    try:
        module.imaplib.IMAP4_SSL = _FakeImapTimeout  # type: ignore[assignment]
        settings = Settings(
            imap_host="imap.example",
            imap_port=993,
            imap_username="user",
            imap_password="password",
            cursor_signing_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            imap_connection_retries=2,
        )
        client = ImapClient(settings)
        client.connect()
    except ImapConnectionError:
        pass
    else:
        raise AssertionError("ImapConnectionError wurde nicht ausgelöst")
    finally:
        module.imaplib.IMAP4_SSL = original_imap4_ssl  # type: ignore[assignment]
