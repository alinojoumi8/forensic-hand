from __future__ import annotations

import re

import pytest
from conftest import append_fake_signature, append_info_update, scan_pdf, text_pdf

from forensic_hand.pdf_audit import audit_pdf, parse_pdf_date


def _audit(tmp_path, data: bytes, name="doc.pdf"):
    path = tmp_path / name
    path.write_bytes(data)
    return audit_pdf(path)


def _codes(result):
    return {f["code"]: f["level"] for f in result["findings"]}


def test_a_plain_pdf_has_no_notice_and_no_warning(tmp_path):
    result = _audit(tmp_path, text_pdf())
    facts = result["facts"]
    assert facts["pages"] == 1
    assert facts["incremental_updates"] == 0
    assert facts["info"]["Producer"] == "TestWriter 1.0"
    assert facts["info"]["CreationDate"] == "2024-01-01T12:00:00+00:00"
    assert [f for f in result["findings"] if f["level"] != "info"] == []


def test_an_incremental_update_is_detected(tmp_path):
    base = text_pdf()
    result = _audit(tmp_path, append_info_update(base))
    facts = result["facts"]
    assert facts["incremental_updates"] == 1
    assert _codes(result).get("PDF-INCREMENTAL") == "notice"
    first = facts["revisions"][0]
    assert first["end"] == len(base) and first["opens"] is True
    assert facts["info"]["Producer"] == "EditTool 9"
    assert first["producer"] == "TestWriter 1.0"


def test_a_modify_date_after_the_create_date_is_reported(tmp_path):
    result = _audit(tmp_path, text_pdf(mod="D:20250615093000Z"))
    assert _codes(result).get("PDF-MODIFIED-DATE") == "notice"


def test_a_linearized_pdf_is_not_counted_as_an_update(tmp_path):
    result = _audit(tmp_path, text_pdf(linearize=True))
    assert result["facts"]["linearized"] is True
    assert result["facts"]["incremental_updates"] == 0
    assert "PDF-INCREMENTAL" not in _codes(result)


def test_a_signature_that_covers_the_whole_file_is_reported_as_such(tmp_path):
    result = _audit(tmp_path, append_fake_signature(text_pdf()))
    sigs = result["facts"]["signatures"]
    assert len(sigs) == 1 and sigs[0]["covers_whole_file"] is True
    assert sigs[0]["signing_time_claimed"] == "2024-01-05T10:00:00+00:00"
    codes = _codes(result)
    assert codes.get("PDF-SIG-PRESENT") == "info"
    assert "PDF-SIG-AFTER" not in codes


def test_bytes_added_after_the_last_signature_get_a_warning(tmp_path):
    signed = append_fake_signature(text_pdf())
    changed = append_info_update(signed)
    result = _audit(tmp_path, changed)
    after = [f for f in result["findings"] if f["code"] == "PDF-SIG-AFTER"]
    assert after and after[0]["level"] == "warning"
    assert after[0]["data"]["bytes_after_signature"] == len(changed) - len(signed)


def test_a_low_resolution_scan_inside_a_pdf_gets_a_warning(tmp_path):
    result = _audit(tmp_path, scan_pdf(px=(850, 1100)))
    image = result["facts"]["page_images"][0]
    assert image["page"] == 1 and image["width"] == 850
    assert image["dpi_x"] == pytest.approx(100, abs=0.5)
    assert image["page_coverage"] == pytest.approx(1.0, abs=0.01)
    assert _codes(result).get("PDF-IMG-DPI-LOW") == "warning"


def test_a_200_dpi_scan_inside_a_pdf_gets_a_notice(tmp_path):
    result = _audit(tmp_path, scan_pdf(px=(1700, 2200)))
    assert _codes(result).get("PDF-IMG-DPI-BELOW-300") == "notice"


def test_an_a4_page_scanned_at_150_dpi_is_not_called_too_low(tmp_path):
    """Found with a real Edge file: 1240 pixels across an A4 page computes to 149.9 DPI, not 150."""
    result = _audit(tmp_path, scan_pdf(px=(1240, 1754), page_size=(595.276, 841.89)))
    codes = _codes(result)
    assert result["facts"]["page_images"][0]["dpi_x"] == pytest.approx(149.98, abs=0.05)
    assert "PDF-IMG-DPI-LOW" not in codes
    assert codes.get("PDF-IMG-DPI-BELOW-300") == "notice"


def test_a_reader_warning_is_reported_with_its_text_and_the_same_text_each_time(tmp_path):
    """Found with a real pyHanko file: a wrong object count in the trailer."""
    data = re.sub(rb"/Size \d\b", b"/Size 9", text_pdf())
    assert b"/Size 9" in data
    first = _audit(tmp_path, data)
    second = _audit(tmp_path, data, "again.pdf")
    warning = [f for f in first["findings"] if f["code"] == "PDF-READER-WARNING"]
    assert warning and "number of objects" in warning[0]["detail"]
    assert first["facts"]["reader_warnings"] == second["facts"]["reader_warnings"]
    assert "0x" not in warning[0]["detail"]


def test_a_small_image_on_top_of_a_scan_is_reported(tmp_path):
    result = _audit(tmp_path, scan_pdf(extra_image=True))
    overlay = [f for f in result["findings"] if f["code"] == "PDF-IMAGE-OVERLAY"]
    assert overlay and overlay[0]["level"] == "notice" and overlay[0]["data"]["page"] == 1
    assert "PDF-IMAGE-OVERLAY" not in _codes(_audit(tmp_path, scan_pdf(), "plain.pdf"))


def test_visible_typed_text_on_top_of_a_scan_is_reported(tmp_path):
    result = _audit(tmp_path, scan_pdf(text=True))
    assert _codes(result).get("PDF-TEXT-OVER-SCAN") == "notice"


def test_an_invisible_text_layer_is_reported_as_ocr_only(tmp_path):
    codes = _codes(_audit(tmp_path, scan_pdf(text=True, invisible=True)))
    assert codes.get("PDF-OCR-LAYER") == "info"
    assert "PDF-TEXT-OVER-SCAN" not in codes


def test_annotations_on_a_page_are_reported(tmp_path):
    result = _audit(tmp_path, scan_pdf(annotation=True))
    annots = [f for f in result["findings"] if f["code"] == "PDF-ANNOTATIONS"]
    assert annots and annots[0]["data"]["by_type"] == {"FreeText": 1}


def test_bytes_after_the_end_marker_are_reported(tmp_path):
    result = _audit(tmp_path, text_pdf() + b"\nHIDDEN PAYLOAD " * 20)
    trailing = [f for f in result["findings"] if f["code"] == "PDF-TRAILING-DATA"]
    assert trailing and trailing[0]["data"]["bytes"] >= 300


def test_a_file_that_is_not_a_pdf_does_not_crash(tmp_path):
    result = _audit(tmp_path, b"this is not a pdf at all")
    assert _codes(result).get("PDF-UNREADABLE") == "warning"


def test_every_finding_says_what_it_does_not_prove(tmp_path):
    data = append_info_update(append_fake_signature(scan_pdf(extra_image=True, text=True, annotation=True)))
    for f in _audit(tmp_path, data)["findings"]:
        assert f["title"] and f["limits"], f["code"]


@pytest.mark.parametrize("raw, expected", [
    ("D:20240101120000Z", "2024-01-01T12:00:00+00:00"),
    ("D:20240101120000+05'30'", "2024-01-01T12:00:00+05:30"),
    ("D:20240101120000-08'00'", "2024-01-01T12:00:00-08:00"),
    ("D:202401011200", "2024-01-01T12:00:00"),
    ("D:2024", "2024-01-01T00:00:00"),
    ("20240101120000Z", "2024-01-01T12:00:00+00:00"),
    ("yesterday", None),
    ("", None),
    ("D:20241340999999Z", None),
])
def test_parse_pdf_date(raw, expected):
    assert parse_pdf_date(raw) == expected
