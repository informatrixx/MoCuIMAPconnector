from __future__ import annotations

from mocu_imap_mcp.bodystructure import iter_attachments_from_bodystructure


def test_bodystructure_multipart_mixed_plain_and_pdf() -> None:
    raw = (
        '((("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 128 4) '
        '("APPLICATION" "PDF" ("NAME" "rechnung.pdf") NIL NIL "BASE64" 2048 NIL '
        '("ATTACHMENT" ("FILENAME" "rechnung.pdf")) NIL) "MIXED"))'
    )
    items = iter_attachments_from_bodystructure(raw)
    assert [(item.part_id, item.filename, item.content_type) for item in items] == [
        ("2", "rechnung.pdf", "application/pdf")
    ]


def test_bodystructure_nested_multipart_alternative() -> None:
    raw = (
        '(((("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 128 4) '
        '("TEXT" "HTML" ("CHARSET" "UTF-8") NIL NIL "7BIT" 128 4) "ALTERNATIVE") '
        '("APPLICATION" "PDF" ("NAME" "rechnung.pdf") NIL NIL "BASE64" 2048 NIL '
        '("ATTACHMENT" ("FILENAME" "rechnung.pdf")) NIL) "MIXED"))'
    )
    items = iter_attachments_from_bodystructure(raw)
    assert any(item.part_id == "2" and item.filename == "rechnung.pdf" for item in items)


def test_bodystructure_multipart_related_with_inline_and_pdf() -> None:
    raw = (
        '((("IMAGE" "PNG" ("NAME" "logo.png") NIL NIL "BASE64" 1234 NIL '
        '("INLINE" ("FILENAME" "logo.png")) NIL)'
        '("TEXT" "HTML" ("CHARSET" "UTF-8") NIL NIL "7BIT" 256 4 "RELATED")'
        '("APPLICATION" "PDF" ("NAME" "rechnung.pdf") NIL NIL "BASE64" 2048 NIL '
        '("ATTACHMENT" ("FILENAME" "rechnung.pdf")) NIL) "RELATED"))'
    )
    items = iter_attachments_from_bodystructure(raw)
    assert any(item.part_id == "3" and item.filename == "rechnung.pdf" for item in items)


def test_bodystructure_multipart_with_extensions_after_subtype() -> None:
    raw = (
        '((("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 128 4)'
        '("APPLICATION" "PDF" ("NAME" "rechnung.pdf") NIL NIL "BASE64" 2048 NIL '
        '("ATTACHMENT" ("FILENAME" "rechnung.pdf")) NIL) "MIXED" ("BOUNDARY" "abc") NIL NIL))'
    )
    items = iter_attachments_from_bodystructure(raw)
    assert any(item.part_id == "2" and item.filename == "rechnung.pdf" for item in items)


def test_bodystructure_text_csv_attachment() -> None:
    raw = (
        '((("TEXT" "CSV" ("NAME" "rechnungsdaten.csv") NIL NIL "7BIT" 64 4 '
        'NIL ("ATTACHMENT" ("FILENAME" "rechnungsdaten.csv")) NIL) "MIXED"))'
    )
    items = iter_attachments_from_bodystructure(raw)
    assert len(items) == 1
    assert items[0].filename == "rechnungsdaten.csv"
    assert items[0].part_id == "1"


def test_bodystructure_filename_in_content_type() -> None:
    raw = (
        '((("APPLICATION" "PDF" ("NAME" "rechnung-type.pdf") NIL NIL "BASE64" 2048 NIL NIL) "MIXED"))'
    )
    items = iter_attachments_from_bodystructure(raw)
    assert items[0].filename == "rechnung-type.pdf"


def test_bodystructure_filename_in_content_disposition() -> None:
    raw = (
        '((("APPLICATION" "PDF" NIL NIL NIL "BASE64" 2048 NIL '
        '("ATTACHMENT" ("FILENAME" "rechnung-disp.pdf")) NIL) "MIXED"))'
    )
    items = iter_attachments_from_bodystructure(raw)
    assert items[0].filename == "rechnung-disp.pdf"
