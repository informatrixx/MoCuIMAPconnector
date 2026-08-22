from __future__ import annotations

from email import policy
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from mocu_imap_mcp.mail_parser import (
    decode_filename,
    decode_header_value,
    extract_body_text_and_html,
    find_attachments,
    message_from_bytes,
)


def test_decode_header_utf8_q_encoded() -> None:
    raw = "=?UTF-8?Q?Rechnung_f=C3=BCr_M=C3=A4rz?="
    assert decode_header_value(raw) == "Rechnung für März"


def test_decode_filename_rfc2231() -> None:
    raw = "Rechnung%20f%C3%BCr%20M%C3%A4rz%20-%202025.pdf"
    assert decode_filename(raw) == "Rechnung für März - 2025.pdf"


def test_multipart_with_plain_html_and_pdf_attachments() -> None:
    msg = MIMEMultipart("mixed")
    msg["Subject"] = "Rechnung 12345"
    msg["From"] = "noreply@example.com"
    msg["To"] = "buchhaltung@example.org"

    msg.attach(MIMEText("Hallo Team", "plain", "utf-8"))
    msg.attach(MIMEText("<p>Hallo <strong>Team</strong></p>", "html", "utf-8"))
    pdf = MIMEApplication(b"%PDF-1.4\\n%...sample...", _subtype="pdf")
    pdf.add_header("Content-Disposition", "attachment", filename="Rechnung-2025-12345.pdf")
    msg.attach(pdf)

    raw = msg.as_bytes(policy=policy.default)
    message = message_from_bytes(raw)

    attachments = find_attachments(message)
    assert len(attachments) == 1
    assert attachments[0].filename == "Rechnung-2025-12345.pdf"

    body, has_html = extract_body_text_and_html(message)
    assert "Hallo Team" in body
    assert has_html is False


def test_singlepart_html_is_sanitized() -> None:
    raw = (
        "<html><style>.x{}</style><script>alert(1)</script>"
        "<body><p>Rechnung <strong>123</strong></p>"
        "<img src=\"https://tracker.example/1.gif\"></body></html>"
    )
    msg = MIMEText(raw, "html", "utf-8")
    msg["Subject"] = "Rechnung"
    msg["From"] = "billing@example.org"
    msg["To"] = "konto@example.org"
    parsed = message_from_bytes(msg.as_bytes(policy=policy.default))

    body, has_html = extract_body_text_and_html(parsed)
    assert body == "Rechnung 123"
    assert has_html is True
