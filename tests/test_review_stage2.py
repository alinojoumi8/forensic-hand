"""Tests for the findings of CodeRabbit review 5 (Stage 2 workbench), 2026-11-26.

All files are synthetic. They prove the logic only.
"""

from __future__ import annotations

import io

import numpy as np
import pytest
from conftest import save_image
from PIL import Image
from test_workbench import signature_image

from forensic_hand import clones, exhibit
from forensic_hand.case import Case
from forensic_hand.imaging import on_white
from forensic_hand.pages import MAX_PREVIEW_SIDE, render_preview
from forensic_hand.report import build_report, write_report
from forensic_hand.work import add_crop, make_exhibit, run_clone_check


def transparent_signature() -> Image.Image:
    """Black writing on fully transparent BLACK: convert('RGB') would make it all black."""
    ink = signature_image(5)
    alpha = Image.eval(ink, lambda v: 255 - v)          # writing opaque, paper transparent
    rgba = Image.new("RGBA", ink.size, (0, 0, 0, 0))
    rgba.putalpha(alpha)
    return rgba


def _case_with(tmp_path, *images, dpi=(300, 300)):
    case = Case.create(tmp_path / "c", title="t")
    for i, img in enumerate(images):
        path = tmp_path / f"in{i}.png"
        img.save(path, dpi=dpi) if dpi else img.save(path)
        rec = case.add_evidence(path, role="questioned" if i == 0 else "known")
        add_crop(case, rec["id"], page=1, box=[0, 0, img.width, img.height])
    return case


# ------------------------------------------------ copy check: symmetric and rotation-safe shape gate

def test_the_shape_gate_does_not_depend_on_the_order_of_the_crops():
    a = clones.prepare(signature_image(5), 160, 0.002)
    b = clones.prepare(signature_image(9), 160, 0.002)
    ab = clones.compare(a, b, [0], 0.10)
    ba = clones.compare(b, a, [0], 0.10)
    assert (ab["score"] is None) == (ba["score"] is None)


def test_a_copy_turned_3_degrees_is_still_compared_and_flagged(tmp_path):
    original = signature_image(5)
    turned = original.rotate(3, resample=Image.BICUBIC, expand=True, fillcolor=255)
    buf = io.BytesIO()
    turned.save(buf, "JPEG", quality=85)
    case = _case_with(tmp_path, Image.open(buf).convert("L"), original)
    pair = run_clone_check(case)["pairs"][0]
    assert pair["score"] is not None and pair["score"] >= 0.95, pair


def test_elongation_is_the_same_when_the_ink_is_turned():
    flat = clones.prepare(signature_image(5), 160, 0.002)
    turned = clones.prepare(signature_image(5).rotate(3, expand=True, fillcolor=255), 160, 0.002)
    assert abs(flat["elongation"] / turned["elongation"] - 1) < 0.05


# ------------------------------------------------ transparent pictures stay readable

def test_on_white_turns_transparent_paper_white_and_keeps_the_writing():
    rgb = np.asarray(on_white(transparent_signature()).convert("L"))
    assert rgb[0, 0] == 255 and rgb.min() < 60


def test_a_transparent_png_preview_is_not_black(tmp_path):
    path = tmp_path / "t.png"
    transparent_signature().save(path)
    case = Case.create(tmp_path / "c", title="t")
    rec = case.add_evidence(path, role="questioned")
    gray = np.asarray(render_preview(case, rec, 1, 450).convert("L"))
    assert gray.mean() > 200 and gray.min() < 100


def test_a_transparent_crop_works_in_the_copy_check_chart_and_report(tmp_path):
    case = _case_with(tmp_path, transparent_signature(), signature_image(5))
    pair = run_clone_check(case)["pairs"][0]
    assert pair["score"] is not None and pair["score"] >= 0.95, pair
    ex = make_exhibit(case, title="T", panels=[{"crop_id": "C1"}])
    chart = np.asarray(Image.open(case.path / ex["file"]).convert("L"))
    assert chart.mean() > 200                                     # mostly white, not a black block
    html, _ = build_report(case)
    assert 'src="data:image/png;base64,' in html


# ------------------------------------------------ size limits

def test_a_very_tall_picture_gives_a_bounded_preview(tmp_path):
    path = save_image(tmp_path / "tall.png", Image.new("L", (100, 100_000), 255))
    case = Case.create(tmp_path / "c", title="t")
    rec = case.add_evidence(path, role="other")
    img = render_preview(case, rec, 1, 1600)
    assert img.height <= MAX_PREVIEW_SIDE and img.width * img.height <= 40_000_000


def test_a_chart_of_a_very_thin_crop_with_no_resolution_stays_small(tmp_path):
    case = _case_with(tmp_path, Image.new("L", (10_000, 4), 0), signature_image(5).resize((600, 600)), dpi=None)
    ex = make_exhibit(case, title="T", panels=[{"crop_id": "C1"}, {"crop_id": "C2"}])
    assert ex["to_scale"] is False
    assert max(max(size) for size in ex["panel_sizes"]) <= exhibit.MAX_PANEL_SIDE
    assert ex["width"] * ex["height"] < 30_000_000


# ------------------------------------------------ overlay: no false claim of one scale

def test_an_overlay_with_blue_resized_by_hand_does_not_claim_one_scale(tmp_path):
    case = _case_with(tmp_path, signature_image(5), signature_image(5))
    ex = make_exhibit(case, title="T", kind="overlay",
                      overlay={"a": "C1", "b": "C2", "dx": 0, "dy": 0, "rotation": 0, "scale": 2})
    assert ex["to_scale"] is False and ex["blue_resized_by_hand"] is True and ex["scale_dpi"] == 300
    same = make_exhibit(case, title="T", kind="overlay",
                        overlay={"a": "C1", "b": "C2", "dx": 0, "dy": 0, "rotation": 0, "scale": 1})
    assert same["to_scale"] is True and same["blue_resized_by_hand"] is False


# ------------------------------------------------ report: one writer

def test_the_report_is_built_and_written_while_holding_the_case_lock(tmp_path, monkeypatch):
    from forensic_hand import report

    case = _case_with(tmp_path, signature_image(5))
    seen = {}
    real = report.build_report

    def watch(c):
        seen["depth"] = c.ledger.lock().depth
        return real(c)
    monkeypatch.setattr(report, "build_report", watch)
    write_report(case)
    assert seen["depth"] >= 1


@pytest.mark.parametrize("name", ["app.js"])
def test_the_screen_guards_against_stale_async_results(name):
    """The two race fixes in the screen: a build counter and a page check after the picture loads."""
    from importlib import resources

    code = resources.files("forensic_hand").joinpath("web", name).read_text(encoding="utf-8")
    assert "if (build !== this.buildId) return;" in code
    assert "if (ui.item !== item || ui.page !== page) return;" in code
    assert 'c.fillStyle = "#fff";' in code
