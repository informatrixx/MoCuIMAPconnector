"""Canonical public URLs; proxy headers never select the deployment prefix."""
from __future__ import annotations

import re
from urllib.parse import urlsplit


def validate_base_url(value: str) -> str:
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or
            any(ord(c) < 33 or ord(c) > 126 or c in {'"', '\\'} for c in value)):
        raise ValueError("Exakte HTTPS-Basis-URL ohne Credentials erforderlich")
    path = url.path.removesuffix("/")
    if not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*", path):
        raise ValueError("Ungueltiger oeffentlicher Basispfad")
    return value.removesuffix("/")


def url_origin(value: str) -> str:
    url = urlsplit(value)
    return f"{url.scheme}://{url.netloc}"


def metadata_url(resource: str) -> str:
    validate_base_url(resource)
    return url_origin(resource) + "/.well-known/oauth-protected-resource" + urlsplit(resource).path
