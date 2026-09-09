from __future__ import annotations

import logging
import time
from collections.abc import Callable
from contextvars import ContextVar
from datetime import UTC, datetime
from functools import wraps
from typing import Any
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError, ToolError
from mcp.types import ToolAnnotations

from .accounts import AccountError
from .mail_content import read_email
from .multi_search import search
from .runtime import Runtime
from .security import (
    PROMPT_INJECTION_WARNING,
    AttachmentTooLargeError,
    MessageNotFoundError,
    MessageTooLargeError,
)
from .tools.attachments import _RESOURCE_MIME_MAP, _resource_prefix

role: ContextVar[str] = ContextVar("mocu_role", default="")


def require_admin() -> None:
    if role.get() != "admin":
        raise AccountError("Administrative Authentifizierung erforderlich")


def safe_call(function: Callable[..., Any], *, resource: bool = False) -> Callable[..., Any]:
    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        started = time.monotonic()
        logger = logging.getLogger("mocu_imap_mcp.tools")
        try:
            result = function(*args, **kwargs)
            count = result.get("count") if isinstance(result, dict) else None
            logger.info("tool=%s duration=%.3f count=%s", function.__name__, time.monotonic() - started, count)
            return result
        except Exception as exc:
            logger.warning("tool=%s error_class=%s", function.__name__, type(exc).__name__)
            error_type = ResourceError if resource else ToolError
            message = "Vorgang fehlgeschlagen; Referenz, Konfiguration oder Verbindung pruefen"
            if isinstance(exc, (AccountError, MessageNotFoundError, MessageTooLargeError, AttachmentTooLargeError)):
                message = str(exc)
            raise error_type(message) from None
    return wrapped


def safe_resource(function: Callable[..., Any]) -> Callable[..., Any]:
    return safe_call(function, resource=True)


def register(server: MCPServer, runtime: Runtime) -> None:
    read = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)
    write = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False)

    def tool(**kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
            return server.tool(**kwargs)(safe_call(function))
        return decorate

    @tool(description="Verfuegbare Konten ohne Zugangsdaten", annotations=read)
    def list_accounts() -> dict[str, Any]:
        return {"accounts": [a.model_dump() for a in runtime.store.list()]}

    @tool(description="Startet administrative HTTPS-Einrichtung; keine Credentials eingeben", annotations=write)
    def begin_account_setup(account_id: str | None = None) -> dict[str, Any]:
        require_admin()
        token, expires = runtime.store.begin_setup(account_id)
        return {"setup_url": runtime.settings.public_base_url.rstrip("/") + "/setup/" + token,
                "expires_at": datetime.fromtimestamp(expires, UTC).isoformat()}

    @tool(description="Loescht ausschliesslich lokale Kontokonfiguration; keine Mailbox-Aenderungen",
                 annotations=write)
    def delete_account(account_id: str) -> dict[str, bool]:
        require_admin()
        runtime.store.delete(account_id)
        return {"deleted": True}

    @tool(description="Aktiviert/deaktiviert ausschliesslich lokale Kontokonfiguration", annotations=write)
    def set_account_enabled(account_id: str, enabled: bool) -> dict[str, bool]:
        require_admin()
        runtime.store.set_enabled(account_id, enabled)
        return {"enabled": enabled}

    @tool(description="Prueft eine read-only IMAP-Verbindung", annotations=read)
    def get_account_status(account_id: str) -> dict[str, Any]:
        with runtime.client(account_id) as client:
            count = len(client.list_mailboxes())
        return {"account_id": account_id, "status": "connected", "mailbox_count": count}

    @tool(description=PROMPT_INJECTION_WARNING, annotations=read)
    def list_mailboxes(account_id: str) -> dict[str, Any]:
        with runtime.client(account_id) as client:
            items = [{"name": m.name, "selectable": m.selectable} for m in client.list_mailboxes()]
        return {"account_id": account_id, "mailboxes": items}

    @tool(description=PROMPT_INJECTION_WARNING, annotations=read)
    def search_emails(account_ids: list[str] | None = None, mailboxes: list[str] | None = None,
                      date_from: str | None = None, date_to: str | None = None,
                      from_address: str | None = None, to_address: str | None = None,
                      subject: str | None = None, text: str | None = None, has_attachment: bool | None = None,
                      attachment_filename: str | None = None, attachment_extension: str | None = None,
                      limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
        return search(runtime, account_ids=account_ids, mailboxes=mailboxes, date_from=date_from, date_to=date_to,
                      from_address=from_address, to_address=to_address, subject=subject, text=text,
                      has_attachment=has_attachment, attachment_filename=attachment_filename,
                      attachment_extension=attachment_extension, limit=limit, cursor=cursor)

    @tool(description="Nur deterministische Rechnungskandidaten. " + PROMPT_INJECTION_WARNING, annotations=read)
    def find_invoice_candidates(date_from: str, date_to: str, account_ids: list[str] | None = None,
                                mailboxes: list[str] | None = None, limit: int = 50,
                                cursor: str | None = None) -> dict[str, Any]:
        return search(runtime, date_from=date_from, date_to=date_to, account_ids=account_ids,
                      mailboxes=mailboxes, limit=limit, cursor=cursor, invoices=True)

    @tool(description=PROMPT_INJECTION_WARNING, annotations=read)
    def get_email(account_id: str, mailbox: str, uidvalidity: int, uid: int,
                  include_body: bool = True) -> dict[str, Any]:
        with runtime.client(account_id) as client:
            client.pin_mailbox(mailbox, uidvalidity)
            result = read_email(client, mailbox, uid, include_body)
        return {**result, "account_id": account_id, "uidvalidity": uidvalidity}

    @tool(description=PROMPT_INJECTION_WARNING, annotations=read)
    def list_attachments(account_id: str, mailbox: str, uidvalidity: int, uid: int) -> dict[str, Any]:
        with runtime.client(account_id) as client:
            client.pin_mailbox(mailbox, uidvalidity)
            items = [{**a.model_dump(), "sha256": None} for a in client.list_attachments(mailbox, uid)]
        return {"account_id": account_id, "uidvalidity": uidvalidity, "attachments": items}

    @tool(description=PROMPT_INJECTION_WARNING, annotations=read)
    def get_attachment(account_id: str, mailbox: str, uidvalidity: int, uid: int, part_id: str) -> dict[str, Any]:
        with runtime.client(account_id) as client:
            client.pin_mailbox(mailbox, uidvalidity)
            attachment = next((a for a in client.list_attachments(mailbox, uid) if a.part_id == part_id), None)
            if attachment is None:
                raise AccountError("Anhang nicht gefunden")
            prefix = _resource_prefix(attachment.content_type)
        uri = f"mocu://attachment-{prefix}/{account_id}/{quote(mailbox, safe='')}/{uidvalidity}/{uid}/{part_id}"
        return {"uri": uri,
                "filename": attachment.filename, "content_type": attachment.content_type, "size": attachment.size}

    def resource(prefix: str, mime_type: str) -> None:
        @server.resource(
            f"mocu://attachment-{prefix}/{{account_id}}/{{mailbox_token}}/{{uidvalidity}}/{{uid}}/{{part_id}}",
            mime_type=mime_type, description=PROMPT_INJECTION_WARNING,
        )
        @safe_resource
        def read_attachment(account_id: str, mailbox_token: str, uidvalidity: int, uid: int, part_id: str) -> bytes:
            # MCP's URI-template matcher already decoded this segment once.
            mailbox = mailbox_token
            with runtime.client(account_id) as client:
                client.pin_mailbox(mailbox, uidvalidity)
                attachment = next((a for a in client.list_attachments(mailbox, uid) if a.part_id == part_id), None)
                if attachment is None or _resource_prefix(attachment.content_type) != prefix:
                    raise AccountError("Resource-MIME-Prefix passt nicht zum Attachment-Inhalt")
                return client.read_attachment(mailbox, uid, part_id)

    for mime in sorted({v for _, v in _RESOURCE_MIME_MAP} | {"application/octet-stream"}):
        resource(_resource_prefix(mime), mime)
