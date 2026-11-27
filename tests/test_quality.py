from __future__ import annotations

import numpy as np
from conftest import make_stroke_image, save_image, tiff_with_preview_block
from PIL import Image

from forensic_hand.quality import analyse_image_file, edge_sharpness, estimate_jpeg_quality


def _codes(result):
    return {f["code"]: f["level"] for f in result["findings"]}


def test_sharp_strokes_score_higher_than_blurred_strokes():
    sharp = edge_sharpness(np.asarray(make_stroke_image()))
    soft = edge_sharpness(np.asarray(make_stroke_image(blur=2.0)))
    blurred = edge_sharpness(np.asarray(make_stroke_image(blur=6.0)))
    assert sharp["score"] > soft["score"] > blurred["score"] > 0


def test_a_sharp_300_dpi_scan_has_no_notice_and_no_warning(sharp_png):
    result = analyse_image_file(sharp_png)
    assert result["metrics"]["width"] == 1200 and result["metrics"]["height"] == 800
    assert result["metrics"]["dpi"] == [300, 300]
    assert [f for f in result["findings"] if f["level"] != "info"] == []


def test_a_blurred_scan_gets_a_warning(tmp_path):
    path = save_image(tmp_path / "blur.png", make_stroke_image(blur=6.0), dpi=(300, 300))
    assert _codes(analyse_image_file(path)).get("IMG-BLUR") == "warning"


def test_a_low_dpi_scan_gets_a_warning(tmp_path):
    path = save_image(tmp_path / "low.png", make_stroke_image(), dpi=(96, 96))
    assert _codes(analyse_image_file(path)).get("IMG-DPI-LOW") == "warning"


def test_a_200_dpi_scan_gets_a_notice(tmp_path):
    path = save_image(tmp_path / "mid.png", make_stroke_image(), dpi=(200, 200))
    assert _codes(analyse_image_file(path)).get("IMG-DPI-BELOW-300") == "notice"


def test_an_image_with_no_dpi_gets_a_notice(tmp_path):
    path = save_image(tmp_path / "nodpi.png", make_stroke_image())
    result = analyse_image_file(path)
    assert result["metrics"]["dpi"] is None
    assert _codes(result).get("IMG-DPI-UNKNOWN") == "notice"


def test_heavy_jpeg_compression_gets_a_warning(tmp_path):
    path = save_image(tmp_path / "q30.jpg", make_stroke_image(), quality=30, dpi=(300, 300))
    result = analyse_image_file(path)
    assert abs(result["metrics"]["jpeg_quality_estimate"] - 30) <= 8
    assert _codes(result).get("IMG-JPEG-QUALITY") == "warning"


def test_light_jpeg_compression_is_not_flagged(tmp_path):
    path = save_image(tmp_path / "q95.jpg", make_stroke_image(), quality=95, dpi=(300, 300))
    result = analyse_image_file(path)
    assert result["metrics"]["jpeg_quality_estimate"] >= 88
    assert "IMG-JPEG-QUALITY" not in _codes(result)


def test_jpeg_quality_estimate_needs_tables():
    assert estimate_jpeg_quality(None) is None
    assert estimate_jpeg_quality({}) is None


def test_a_black_and_white_only_scan_gets_a_notice(tmp_path):
    path = save_image(tmp_path / "bw.png", make_stroke_image(mode="1"), dpi=(300, 300))
    assert _codes(analyse_image_file(path)).get("IMG-BILEVEL") == "notice"


def test_a_blank_page_is_not_called_blurred(tmp_path):
    path = save_image(tmp_path / "blank.png", Image.new("L", (1000, 1000), 255), dpi=(300, 300))
    result = analyse_image_file(path)
    codes = _codes(result)
    assert "IMG-BLUR" not in codes and "IMG-SOFT" not in codes
    assert codes.get("IMG-NO-DETAIL") == "notice"
    assert result["metrics"]["sharpness"] is None


def test_a_very_small_image_gets_a_warning(tmp_path):
    path = save_image(tmp_path / "tiny.png", make_stroke_image(size=(200, 120)), dpi=(300, 300))
    assert _codes(analyse_image_file(path)).get("IMG-SMALL") == "warning"


def test_a_broken_image_file_does_not_crash(tmp_path):
    path = tmp_path / "broken.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"not really a png")
    result = analyse_image_file(path)
    assert _codes(result).get("IMG-UNREADABLE") == "warning"


def test_a_tiff_with_a_preview_block_is_screened(tmp_path):
    # Found on the CVL database: 91 TIFF scans with a JPEG preview block crashed the screen (TypeError).
    path = tiff_with_preview_block(tmp_path / "scan.tif")
    plain = save_image(tmp_path / "plain.tif", make_stroke_image(), dpi=(300, 300))
    result, expected = analyse_image_file(path), analyse_image_file(plain)
    assert result["metrics"]["frames"] == 1 and result["metrics"]["width"] == 1200
    assert result["metrics"]["sharpness"] == expected["metrics"]["sharpness"]    # the first page is unchanged
    codes = _codes(result)
    assert codes.get("IMG-EXTRA-BLOCK") == "info" and "IMG-UNREADABLE" not in codes
    assert all(f["limits"] for f in result["findings"])


def test_a_two_page_tiff_still_counts_two_pages(tmp_path):
    path = tmp_path / "two.tif"
    make_stroke_image().save(path, save_all=True, append_images=[make_stroke_image()], dpi=(300, 300))
    result = analyse_image_file(path)
    assert result["metrics"]["frames"] == 2 and "IMG-EXTRA-BLOCK" not in _codes(result)


def test_every_finding_says_what_it_does_not_prove(tmp_path):
    path = save_image(tmp_path / "blur.jpg", make_stroke_image(blur=6.0), quality=30)
    for f in analyse_image_file(path)["findings"]:
        assert f["title"] and f["limits"], f["code"]
