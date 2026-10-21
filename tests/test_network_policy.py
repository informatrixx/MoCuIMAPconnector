from __future__ import annotations

import socket
import ssl

import pytest

from mocu_imap_mcp.network import NetworkPolicyError, connect_socket, connection_factory


@pytest.mark.parametrize("failure", ["refused", "timeout", "all"])
def test_ip_fallback_shared_deadline(failure: str, monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    clock = [0.0]
    sockets = []
    targets = []
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])

    def dns(*args: object) -> list[str]:
        clock[0] += 2
        return ["2001:4860:4860::8888", "8.8.8.8"]

    monkeypatch.setattr("mocu_imap_mcp.network.resolve", dns)

    class FakeSocket:
        def __init__(self, *args: object) -> None:
            self.closed = False
            self.timeout = 0.0
            sockets.append(self)

        def settimeout(self, value: float) -> None:
            self.timeout = value

        def connect(self, target: object) -> None:
            targets.append(target)
            if len(targets) == 1 or failure == "all":
                if failure != "refused":
                    clock[0] += self.timeout
                raise TimeoutError("synthetic network failure")

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(socket, "socket", FakeSocket)
    if failure == "all":
        with pytest.raises(OSError):
            connect_socket("imap.example.org", 993, 10)
        assert all(s.closed for s in sockets)
    else:
        result = connect_socket("imap.example.org", 993, 10)
        assert result is sockets[1]
        assert sockets[0].closed and not sockets[1].closed
        assert sockets[1].timeout == 10  # regular I/O timeout restored
    assert targets == [("2001:4860:4860::8888", 993), ("8.8.8.8", 993)]
    assert clock[0] <= 10


def test_dns_deduplication_preserves_order(monkeypatch: pytest.MonkeyPatch) -> None:
    from mocu_imap_mcp.network import resolve

    addresses = ["8.8.8.8", "1.1.1.1", "8.8.8.8", "9.9.9.9"]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 993)) for a in addresses
    ])
    assert resolve("imap.example.org", 993, 1) == list(dict.fromkeys(addresses))


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
