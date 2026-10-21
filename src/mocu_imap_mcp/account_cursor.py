"""Bounded, authenticated continuation state for multi-account searches."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from .accounts import AccountError


def encode_cursor(state: dict[str, Any], key: bytes) -> str:
    payload = json.dumps({**state, "v": 4, "exp": int(time.time()) + 3600},
                         sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.digest(key, payload, "sha256")
    return base64.urlsafe_b64encode(payload + signature).decode()


def decode_cursor(token: str, key: bytes, query_hash: str) -> dict[str, Any]:
    try:
        if len(token) > 16384:
            raise ValueError
        raw = base64.b64decode(token, altchars=b"-_", validate=True)
        payload, signature = raw[:-32], raw[-32:]
        if not hmac.compare_digest(signature, hmac.digest(key, payload, "sha256")):
            raise ValueError
        state = json.loads(payload)
        if not isinstance(state, dict) or state.get("v") != 4 or state.get("q") != query_hash:
            raise ValueError
        if type(state.get("exp")) is not int or state["exp"] < time.time():
            raise ValueError
        return state
    except (ValueError, KeyError, TypeError):
        raise AccountError("Cursor ungueltig oder veraltet; Suche neu starten") from None


def fingerprint(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
