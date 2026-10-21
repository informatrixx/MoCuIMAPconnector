"""Connect only to validated numeric addresses; retain hostname for TLS/SNI."""
from __future__ import annotations

import imaplib
import ipaddress
import queue
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable
from typing import Any, cast


class NetworkPolicyError(ValueError):
    """IMAP target violates operator policy."""


_DNS_SLOTS = threading.BoundedSemaphore(4)


def resolve(host: str, port: int, timeout: float) -> list[str]:
    """Bound DNS latency and outstanding resolver threads without global monkeypatches."""
    if not _DNS_SLOTS.acquire(blocking=False):
        raise NetworkPolicyError("DNS ausgelastet")
    result: queue.Queue[list[str] | None] = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            result.put(list(dict.fromkeys(str(x[4][0]) for x in records)))
        except OSError:
            result.put(None)
        finally:
            _DNS_SLOTS.release()

    threading.Thread(target=worker, daemon=True).start()
    try:
        addresses = result.get(timeout=timeout)
    except queue.Empty:
        raise NetworkPolicyError("DNS-Zeitlimit erreicht") from None
    if not addresses:
        raise NetworkPolicyError("IMAP-Ziel nicht aufloesbar")
    return addresses


def connect_socket(host: str, port: int, timeout: float) -> socket.socket:
    # One DNS/TCP budget per attempt. TLS and subsequent IMAP I/O use the
    # restored regular timeout; outer connection retries remain independently bounded.
    deadline = time.monotonic() + timeout
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise NetworkPolicyError("Ungueltiger IMAP-Hostname") from None
    if not re.fullmatch(r"[a-zA-Z0-9.:-]{1,253}", host):
        raise NetworkPolicyError("Ungueltiger IMAP-Hostname")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("IMAP-Verbindungszeitlimit erreicht")
    addresses = list(dict.fromkeys(resolve(host, port, remaining)))
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise NetworkPolicyError("IMAP-Ziel ist nicht oeffentlich erlaubt")
    for index, target in enumerate(addresses):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("IMAP-Verbindungszeitlimit erreicht")
        sock = None
        try:
            sock = socket.socket(socket.AF_INET6 if ":" in target else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(remaining / (len(addresses) - index))
            sock.connect((target, port))
            if time.monotonic() >= deadline:
                raise TimeoutError("IMAP-Verbindungszeitlimit erreicht")
            sock.settimeout(timeout)
            return sock
        except OSError:
            if sock is not None:
                sock.close()
    raise OSError("Keine gepruefte IMAP-Adresse erreichbar") from None


class PinnedIMAP(imaplib.IMAP4):
    def _create_socket(self, timeout: float | None) -> socket.socket:
        return connect_socket(self.host, self.port, timeout or 30)


class PinnedIMAPS(imaplib.IMAP4_SSL):
    def _create_socket(self, timeout: float | None) -> socket.socket:
        sock = connect_socket(self.host, self.port, timeout or 30)
        try:
            return cast(socket.socket, self.ssl_context.wrap_socket(sock, server_hostname=self.host))
        except Exception:
            sock.close()
            raise


def connection_factory(mode: str, host: str, port: int, timeout: int,
                       context: ssl.SSLContext) -> imaplib.IMAP4:
    if (mode, port) not in {("ssl", 993), ("starttls", 143)}:
        raise NetworkPolicyError("Nur IMAPS:993 oder STARTTLS:143 erlaubt")
    constructor: Callable[..., Any] = PinnedIMAPS if mode == "ssl" else PinnedIMAP
    kwargs: dict[str, Any] = {"timeout": timeout}
    if mode == "ssl":
        kwargs["ssl_context"] = context
    return constructor(host, port, **kwargs)  # type: ignore[no-any-return]
