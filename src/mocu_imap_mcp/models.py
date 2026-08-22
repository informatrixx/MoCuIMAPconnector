from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class MailAddress(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str | None = None
    address: str | None = None


class MailSummary(BaseModel):
    mailbox: str
    uid: int
    message_id: str | None = Field(default=None, alias="message_id")
    date: str | None = None
    internal_date: str | None = None
    from_: MailAddress | None = Field(default=None, alias="from")
    to: list[MailAddress] = Field(default_factory=list)
    subject: str | None = None
    has_attachments: bool = False
    attachment_count: int = 0
    attachment_names: list[str] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class MailDetail(BaseModel):
    mailbox: str
    uid: int
    message_id: str | None = None
    date: str | None = None
    internal_date: str | None = None
    from_: MailAddress | None = Field(default=None, alias="from")
    to: list[MailAddress] = Field(default_factory=list)
    cc: list[MailAddress] = Field(default_factory=list)
    subject: str | None = None
    text_body: str = ""
    html_available: bool = False
    attachments: list[AttachmentInfo] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class AttachmentInfo(BaseModel):
    part_id: str
    filename: str | None = None
    content_type: str | None = None
    size: int | None = None
    sha256: str | None = None


class AttachmentMeta(BaseModel):
    part_id: str
    filename: str | None = None
    content_type: str
    size: int | None = None
    inline: bool = False


class InvoiceCandidate(BaseModel):
    mailbox: str
    uid: int
    date: str | None = None
    from_: str | None = Field(default=None, alias="from")
    subject: str | None = None
    attachments: list[str] = Field(default_factory=list)
    matched_by: list[str] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


def format_datetime_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=None).isoformat()
    return value.isoformat()
