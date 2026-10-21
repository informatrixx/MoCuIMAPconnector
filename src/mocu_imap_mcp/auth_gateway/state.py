"""Bounded single-process, volatile state. Restart invalidates all sessions."""
from __future__ import annotations

import hmac
import re
import secrets
import threading
import time
from dataclasses import dataclass

from ..auth_context import Principal


def safe_return(value: str) -> str:
    if value != "/auth/session" and not re.fullmatch(r"/setup/[A-Za-z0-9_-]{43}", value):
        raise ValueError("Ungueltiges Rueckkehrziel")
    return value


@dataclass
class Transaction:
    state: str
    browser: str
    nonce: str
    verifier: str
    return_to: str
    expires: float


@dataclass
class Session:
    identity: Principal
    csrf: str
    created: float
    touched: float


class BrowserState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.transactions: dict[str, Transaction] = {}
        self.sessions: dict[str, Session] = {}

    def begin(self, return_to: str) -> Transaction:
        safe_return(return_to)
        with self.lock:
            now = time.monotonic()
            self.transactions = {k: v for k, v in self.transactions.items() if v.expires > now}
            if len(self.transactions) >= 1000:
                raise ValueError("Zu viele Anmeldungen")
            item = Transaction(secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(32),
                               secrets.token_urlsafe(48), return_to, now + 180)
            self.transactions[item.state] = item
            return item

    def consume(self, state: str, browser: str) -> Transaction:
        with self.lock:
            item = self.transactions.get(state)
            if item is None or not hmac.compare_digest(item.browser, browser) or item.expires <= time.monotonic():
                raise ValueError("Anmeldung ungueltig")
            del self.transactions[state]
            return item

    def create(self, identity: Principal, previous: str = "") -> str:
        with self.lock:
            now = time.monotonic()
            self.sessions = {k: v for k, v in self.sessions.items() if now - v.created < 300}
            self.sessions.pop(previous, None)
            if len(self.sessions) >= 1000:
                raise ValueError("Zu viele Sitzungen")
            sid = secrets.token_urlsafe(32)
            self.sessions[sid] = Session(identity, secrets.token_urlsafe(32), now, now)
            return sid

    def get(self, sid: str, idle: int, absolute: int) -> Session:
        with self.lock:
            item = self.sessions.get(sid)
            now = time.monotonic()
            if item is None or now - item.touched >= idle or now - item.created >= absolute:
                self.sessions.pop(sid, None)
                raise ValueError("Sitzung abgelaufen")
            item.touched = now
            return item

    def logout(self, sid: str, csrf: str) -> None:
        with self.lock:
            item = self.sessions.get(sid)
            if item is None or not hmac.compare_digest(item.csrf, csrf):
                raise ValueError("CSRF ungueltig")
            del self.sessions[sid]
