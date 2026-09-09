from __future__ import annotations

import socket
import ssl

import pytest

from mocu_imap_mcp.network import NetworkPolicyError, connect_socket, connection_factory


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1",
                                      "::1", "fc00::1", "::ffff:127.0.0.1", "224.0.0.1"])
def test_nonpublic_and_mixed_dns_never_connect(address: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("mocu_imap_mcp.network.resolve", lambda *args: ["8.8.8.8", address])
    monkeypatch.setattr(socket, "socket", lambda *args: pytest.fail("socket created for forbidden address"))
    with pytest.raises(NetworkPolicyError):
        connect_socket("imap.example.org", 993, 1)


def test_pins_numeric_ip_without_second_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr("mocu_imap_mcp.network.resolve", lambda *args: ["8.8.8.8"])

    class FakeSocket:
        def settimeout(self, value: float) -> None:
            pass

        def connect(self, target: object) -> None:
            calls.append(target)

    monkeypatch.setattr(socket, "socket", lambda *args: FakeSocket())
    connect_socket("imap.example.org", 993, 1)
    assert calls == [("8.8.8.8", 993)]


def test_wrong_port_never_connects() -> None:
    with pytest.raises(NetworkPolicyError):
        connection_factory("ssl", "imap.example.org", 22, 1, ssl.create_default_context())
