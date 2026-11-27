"""Stage 2 core: pages, crops, notes, measurements, copy check, exhibits, ledger lock.

All files are synthetic. They prove the logic only.
"""

from __future__ import annotations

import hashlib
import io
import math
import os
import random
import stat
import threading

import numpy as np
import pikepdf
import pytest
from conftest import (
    is_read_only,
    make_stroke_image,
    save_image,
    tiff_with_preview_block,
    tiff_with_unreadable_page,
)
from PIL import Image, ImageDraw

from forensic_hand import verify_case as vc
from forensic_hand.case import Case, CaseError
from forensic_hand.ledger import Ledger
from forensic_hand.pages import page_geometry, render_preview
from forensic_hand.report import build_report
from forensic_hand.seal import create_seal
from forensic_hand.work import (
    add_crop,
    add_measurement,
    add_note,
    make_exhibit,
    run_clone_check,
)

# ---------------------------------------------------------------- synthetic files

def signature_image(seed: int = 1, jitter: float = 0.0, size=(900, 300), width=4, background=255) -> Image.Image:
    """A signature-like line. Same seed and no jitter give the same line."""
    rng = random.Random(seed)
    base = [(60 + i * 26, 150 + 70 * math.sin(i * 0.7) + rng.uniform(-40, 40)) for i in range(30)]
    jit = random.Random(seed * 1000 + int(jitter * 1000))
    pts = [(x + jit.uniform(-jitter, jitter) * 300, y + jit.uniform(-jitter, jitter) * 300) for x, y in base]
    img = Image.new("L", size, background)
    d = ImageDraw.Draw(img)
    d.line(pts, fill=20, width=width, joint="curve")
    d.arc([200, 60, 330, 230], 30, 320, fill=20, width=width)
    return img


def pdf_with_image(img: Image.Image, page=(612, 792), rotate=0) -> bytes:
    pdf = pikepdf.new()
    p = pdf.add_blank_page(page_size=page)
    gray = img.convert("L")
    xobj = pdf.make_stream(gray.tobytes(), Type=pikepdf.Name.XObject, Subtype=pikepdf.Name.Image,
                           Width=gray.width, Height=gray.height, ColorSpace=pikepdf.Name.DeviceGray,
                           BitsPerComponent=8)
    p.obj["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Im0=xobj))
    p.obj["/Contents"] = pdf.make_stream(b"q %f 0 0 %f 0 0 cm /Im0 Do Q" % page)
    if rotate:
        p.obj["/Rotate"] = rotate
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


@pytest.fixture
def wcase(tmp_path):
    """A case with a PNG (300 DPI), a 2-frame TIFF and a PDF scan."""
    png = save_image(tmp_path / "q.png", signature_image(1), dpi=(300, 300))
    tif = tmp_path / "k.tif"
    signature_image(2).save(tif, save_all=True, append_images=[signature_image(3)], dpi=(200, 200))
    pdf = tmp_path / "scan.pdf"
    pdf.write_bytes(pdf_with_image(make_stroke_image(size=(1275, 1650))))   # 150 DPI on Letter
    case = Case.create(tmp_path / "case", title="Workbench")
    case.add_evidence(png, role="questioned")
    case.add_evidence(tif, role="known")
    case.add_evidence(pdf, role="known")
    return case


def _ok(case):
    return vc.verify_case(case.path, check_tsa_signature=False)


# ---------------------------------------------------------------- pages

def test_page_geometry_of_images_and_pdf(wcase, tmp_path):
    rec = {r["id"]: r for r in wcase.state()["evidence"]}
    assert page_geometry(wcase, rec["Q1"]) == [{"page": 1, "units": "px", "width": 900, "height": 300, "dpi": [300, 300]}]
    tif = page_geometry(wcase, rec["K1"])
    assert [p["page"] for p in tif] == [1, 2] and tif[0]["dpi"] == [200, 200]
    pdf = page_geometry(wcase, rec["K2"])
    assert pdf[0]["units"] == "pt" and (pdf[0]["width"], pdf[0]["height"]) == (612.0, 792.0)
    assert pdf[0]["dpi"] == [150, 150]      # from the scan picture that fills the page


def test_page_geometry_follows_pdf_rotation(tmp_path):
    path = tmp_path / "rot.pdf"
    path.write_bytes(pdf_with_image(make_stroke_image(), rotate=90))
    case = Case.create(tmp_path / "c", title="t")
    rec = case.add_evidence(path, role="questioned")
    geo = page_geometry(case, rec)
    assert (geo[0]["width"], geo[0]["height"]) == (792.0, 612.0)


def test_a_tiff_with_a_preview_block_has_one_page(tmp_path):
    # Found on the CVL database: the page count of Pillow fails on a JPEG preview block (TypeError).
    case = Case.create(tmp_path / "c", title="t")
    rec = case.add_evidence(tiff_with_preview_block(tmp_path / "scan.tif"), role="questioned")
    assert page_geometry(case, rec) == [{"page": 1, "units": "px", "width": 1200, "height": 800, "dpi": [300, 300]}]
    assert render_preview(case, rec, page=1, width=300).size == (300, 200)


def test_an_unreadable_page_is_never_hidden_from_the_page_list(tmp_path):
    # CodeRabbit review 18: listing page 1 only would hide page 2 and page 3.
    case = Case.create(tmp_path / "c", title="t")
    rec = case.add_evidence(tiff_with_unreadable_page(tmp_path / "three.tif"), role="questioned")
    with pytest.raises(CaseError, match="page 2"):
        page_geometry(case, rec)


def test_preview_has_the_asked_width_and_page_shape(wcase):
    rec = {r["id"]: r for r in wcase.state()["evidence"]}
    img = render_preview(wcase, rec["K2"], page=1, width=600)
    assert img.width == 600 and abs(img.height - 600 * 792 / 612) <= 1
    img = render_preview(wcase, rec["K1"], page=2, width=450)
    assert img.size == (450, 150)


def test_preview_of_a_missing_page_is_an_error(wcase):
    rec = {r["id"]: r for r in wcase.state()["evidence"]}
    with pytest.raises(CaseError):
        render_preview(wcase, rec["Q1"], page=2, width=100)


# ---------------------------------------------------------------- crops

def test_a_raster_crop_holds_the_exact_source_pixels(wcase):
    crop = add_crop(wcase, "Q1", page=1, box=[100, 50, 500, 250], label="Signature")
    stored = wcase.path / crop["file"]
    src = Image.open(wcase.path / wcase.state()["evidence"][0]["stored_as"])
    assert np.array_equal(np.asarray(Image.open(stored)), np.asarray(src.crop((100, 50, 500, 250))))
    assert crop["crop_id"] == "C1" and crop["method"] == "pixels" and crop["dpi"] == [300, 300]
    assert crop["sha256"] == hashlib.sha256(stored.read_bytes()).hexdigest()
    assert is_read_only(stored)
    assert wcase.state()["crops"][0]["label"] == "Signature"


def test_a_crop_of_the_second_tiff_frame_uses_that_frame(wcase):
    crop = add_crop(wcase, "K1", page=2, box=[0, 0, 900, 300])
    frame = Image.open(wcase.path / wcase.state()["evidence"][1]["stored_as"])
    frame.seek(1)
    assert np.array_equal(np.asarray(Image.open(wcase.path / crop["file"])), np.asarray(frame.convert("L")))


def test_a_pdf_crop_is_rendered_at_the_scan_resolution_by_default(wcase):
    crop = add_crop(wcase, "K2", page=1, box=[72, 72, 216, 144])   # 2 x 1 inch
    assert crop["method"] == "pdfium-render" and crop["render_dpi"] == 150
    assert (crop["width"], crop["height"]) == (300, 150)
    assert crop["renderer"]["name"] == "pdfium" and crop["renderer"]["version"]
    crop2 = add_crop(wcase, "K2", page=1, box=[72, 72, 216, 144], dpi=600)
    assert (crop2["width"], crop2["height"]) == (1200, 600) and crop2["crop_id"] == "C2"


def test_the_same_pdf_crop_twice_gives_the_same_bytes(wcase):
    a = add_crop(wcase, "K2", page=1, box=[100, 100, 300, 200])
    b = add_crop(wcase, "K2", page=1, box=[100, 100, 300, 200])
    assert a["sha256"] == b["sha256"] and a["file"] == b["file"]


@pytest.mark.parametrize("kwargs", [
    {"evidence_id": "Z9", "page": 1, "box": [0, 0, 10, 10]},
    {"evidence_id": "Q1", "page": 3, "box": [0, 0, 10, 10]},
    {"evidence_id": "Q1", "page": 1, "box": [10, 10, 10, 50]},
    {"evidence_id": "Q1", "page": 1, "box": [-5, 0, 10, 10]},
    {"evidence_id": "Q1", "page": 1, "box": [0, 0, 901, 10]},
    {"evidence_id": "Q1", "page": 1, "box": [0, 0, "a", 10]},
    {"evidence_id": "K2", "page": 1, "box": [0, 0, 600, 700], "dpi": 2400},
])
def test_bad_crops_are_refused_and_nothing_is_recorded(wcase, kwargs):
    count = len(wcase.ledger.entries())
    with pytest.raises(CaseError):
        add_crop(wcase, **kwargs)
    assert len(wcase.ledger.entries()) == count
    assert not (wcase.path / "derived").exists() or list((wcase.path / "derived").iterdir()) == []


def test_crops_and_their_tampering_are_checked_by_the_checker(wcase):
    crop = add_crop(wcase, "Q1", page=1, box=[0, 0, 200, 100])
    assert _ok(wcase)["ok"] is True
    path = wcase.path / crop["file"]
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    path.write_bytes(path.read_bytes() + b"x")
    result = _ok(wcase)
    assert result["ok"] is False and any("C1" in p for p in result["problems"])


def test_an_unknown_file_in_the_derived_folder_is_a_problem(wcase):
    add_crop(wcase, "Q1", page=1, box=[0, 0, 200, 100])
    (wcase.path / "derived" / "planted.png").write_bytes(b"x")
    assert any("planted.png" in p for p in _ok(wcase)["problems"])


def test_a_seal_lists_crops_and_the_checker_compares_them(wcase):
    crop = add_crop(wcase, "Q1", page=1, box=[0, 0, 200, 100])
    seal = create_seal(wcase)
    import json

    body = json.loads((wcase.path / seal["file"]).read_bytes())
    assert body["format"] == 2 and body["derived"] == [{"id": "C1", "sha256": crop["sha256"]}]
    assert _ok(wcase)["ok"] is True


# ---------------------------------------------------------------- notes and measurements

def test_a_note_is_recorded_and_a_correction_keeps_the_old_text(wcase):
    n1 = add_note(wcase, target="Q1", text="Pen lift before the final stroke.")
    n2 = add_note(wcase, target="Q1", text="Pen lift before the last loop.", supersedes="N1")
    notes = wcase.state()["notes"]
    assert [n["note_id"] for n in notes] == ["N1", "N2"] and n1["note_id"] == "N1"
    assert notes[0]["superseded_by"] == "N2" and n2["supersedes"] == "N1"


@pytest.mark.parametrize("kwargs", [
    {"target": "Q9", "text": "x"}, {"target": "Q1", "text": "  "}, {"target": "Q1", "text": "x", "supersedes": "N7"},
])
def test_bad_notes_are_refused(wcase, kwargs):
    with pytest.raises(CaseError):
        add_note(wcase, **kwargs)


def test_a_line_measurement_gives_length_in_mm_and_angle(wcase):
    add_crop(wcase, "Q1", page=1, box=[0, 0, 900, 300])                 # 300 DPI
    m = add_measurement(wcase, crop_id="C1", kind="line", points=[[100, 200], [400, 200]])
    assert m["measure_id"] == "M1" and m["length_px"] == 300.0
    assert m["length_mm"] == pytest.approx(25.4)
    assert m["angle_deg"] == pytest.approx(0.0)
    up = add_measurement(wcase, crop_id="C1", kind="line", points=[[100, 200], [200, 100]])
    assert up["angle_deg"] == pytest.approx(45.0)                        # y grows downward on screen


def test_an_angle_measurement_gives_the_angle_between_two_lines(wcase):
    add_crop(wcase, "Q1", page=1, box=[0, 0, 900, 300])
    m = add_measurement(wcase, crop_id="C1", kind="angle",
                        points=[[0, 200], [300, 200], [100, 200], [200, 100]])
    assert m["angle_between_deg"] == pytest.approx(45.0)


def test_a_crop_with_no_dpi_gives_no_mm(tmp_path):
    png = save_image(tmp_path / "nodpi.png", signature_image(1))
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(png, role="questioned")
    add_crop(case, "Q1", page=1, box=[0, 0, 300, 300])
    m = add_measurement(case, crop_id="C1", kind="line", points=[[0, 0], [30, 40]])
    assert m["length_px"] == 50.0 and m["length_mm"] is None


@pytest.mark.parametrize("kwargs", [
    {"crop_id": "C9", "kind": "line", "points": [[0, 0], [1, 1]]},
    {"crop_id": "C1", "kind": "circle", "points": [[0, 0], [1, 1]]},
    {"crop_id": "C1", "kind": "line", "points": [[0, 0]]},
    {"crop_id": "C1", "kind": "line", "points": [[0, 0], [5000, 1]]},
    {"crop_id": "C1", "kind": "line", "points": [[0, 0], [0, 0]]},
])
def test_bad_measurements_are_refused(wcase, kwargs):
    add_crop(wcase, "Q1", page=1, box=[0, 0, 900, 300])
    with pytest.raises(CaseError):
        add_measurement(wcase, **kwargs)


# ---------------------------------------------------------------- copy check

def _crop_of(case, img: Image.Image, name: str, dpi=(300, 300)):
    path = case.path.parent / name
    img.save(path, dpi=dpi)
    rec = case.add_evidence(path, role="questioned" if name.startswith("q") else "known")
    return add_crop(case, rec["id"], page=1, box=[0, 0, img.width, img.height])


def test_a_digital_copy_is_flagged_even_after_scaling_and_jpeg(tmp_path):
    case = Case.create(tmp_path / "c", title="t")
    original = signature_image(5)
    pasted = Image.new("L", (1000, 380), 245)
    small = original.resize((720, 240), Image.LANCZOS)
    buf = io.BytesIO()
    small.save(buf, "JPEG", quality=70)
    pasted.paste(Image.open(buf), (140, 60))
    _crop_of(case, original, "k-orig.png")
    _crop_of(case, pasted, "q-pasted.png")
    result = run_clone_check(case)
    pair = result["pairs"][0]
    assert pair["score"] >= 0.95
    assert [f["code"] for f in result["findings"]] == ["CLONE-NEAR-IDENTICAL"]
    assert result["findings"][0]["level"] == "warning" and set(result["findings"][0]["data"]["crops"]) == {"C1", "C2"}


def test_a_pasted_copy_on_a_printed_signature_line_is_still_flagged(tmp_path):
    """Found in the browser test: a printed line in the crop hid a real copy (score 0.054)."""
    case = Case.create(tmp_path / "c", title="t")
    original = signature_image(5)
    form = Image.new("L", (700, 300), 250)
    ImageDraw.Draw(form).line([(0, 250), (700, 250)], fill=60, width=3)       # the printed signature line
    buf = io.BytesIO()
    original.resize((540, 180), Image.LANCZOS).save(buf, "JPEG", quality=75)
    form.paste(Image.open(buf), (60, 80))
    _crop_of(case, original, "k-orig.png")
    _crop_of(case, form, "q-form.png", dpi=(200, 200))
    result = run_clone_check(case)
    assert result["pairs"][0]["score"] >= 0.95, result["pairs"]


def test_long_straight_runs_are_found_but_curves_are_not():
    from forensic_hand.clones import long_runs, remove_ruling_lines

    ink = np.zeros((50, 200), dtype=bool)
    ink[20, 10:190] = True                      # a long line
    ink[30:34, 40] = True                       # a short mark
    assert long_runs(ink, 60, axis=1)[20, 100] and not long_runs(ink, 60, axis=1)[31, 40]
    cleaned = remove_ruling_lines(ink, 0.3)
    assert not cleaned[20].any() and cleaned[30:34, 40].all()


def test_two_drawings_of_the_same_line_with_natural_variation_are_not_flagged(tmp_path):
    case = Case.create(tmp_path / "c", title="t")
    _crop_of(case, signature_image(5, jitter=0.0), "k-a.png")
    _crop_of(case, signature_image(5, jitter=0.03, width=5), "k-b.png")
    _crop_of(case, signature_image(9), "q-other.png")
    result = run_clone_check(case)
    assert all(p["score"] is None or p["score"] < 0.9 for p in result["pairs"]), result["pairs"]
    assert result["findings"] == []


def test_a_blank_crop_is_skipped_not_matched(tmp_path):
    case = Case.create(tmp_path / "c", title="t")
    _crop_of(case, Image.new("L", (400, 200), 255), "q-blank.png")
    _crop_of(case, Image.new("L", (400, 200), 255), "k-blank2.png")
    result = run_clone_check(case)
    assert result["skipped"] == ["C1", "C2"] and result["findings"] == []


def test_the_copy_check_is_recorded_with_its_settings(wcase):
    add_crop(wcase, "Q1", page=1, box=[0, 0, 900, 300])
    add_crop(wcase, "K1", page=1, box=[0, 0, 900, 300])
    result = run_clone_check(wcase)
    last = wcase.ledger.entries()[-1]
    assert last["type"] == "clone.checked" and last["data"]["settings"]["warning_at"] == 0.95
    assert wcase.state()["clone_check"]["pairs"] == result["pairs"]


# ---------------------------------------------------------------- exhibits

def test_an_exhibit_puts_crops_at_the_same_scale_and_records_it(wcase):
    add_crop(wcase, "Q1", page=1, box=[0, 0, 600, 300])     # 300 DPI: 2 x 1 inch
    add_crop(wcase, "K1", page=1, box=[0, 0, 400, 200])     # 200 DPI: 2 x 1 inch
    ex = make_exhibit(wcase, title="Questioned and known", panels=[{"crop_id": "C1"}, {"crop_id": "C2"}])
    assert ex["exhibit_id"] == "E1" and ex["to_scale"] is True and ex["scale_dpi"] == 300
    sizes = ex["panel_sizes"]
    assert sizes[0] == sizes[1] == [600, 300]                # same physical size, same pixels
    path = wcase.path / ex["file"]
    assert path.is_file() and is_read_only(path)
    assert _ok(wcase)["ok"] is True


def test_an_exhibit_is_the_same_bytes_each_time(wcase):
    add_crop(wcase, "Q1", page=1, box=[0, 0, 600, 300])
    add_crop(wcase, "K1", page=1, box=[0, 0, 400, 200])
    a = make_exhibit(wcase, title="T", panels=[{"crop_id": "C1"}, {"crop_id": "C2"}])
    b = make_exhibit(wcase, title="T", panels=[{"crop_id": "C1"}, {"crop_id": "C2"}])
    assert a["sha256"] == b["sha256"]


def test_an_exhibit_with_an_unknown_scale_says_not_to_scale(tmp_path):
    png = save_image(tmp_path / "nodpi.png", signature_image(1))
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(png, role="questioned")
    add_crop(case, "Q1", page=1, box=[0, 0, 300, 300])
    ex = make_exhibit(case, title="T", panels=[{"crop_id": "C1"}])
    assert ex["to_scale"] is False and ex["scale_dpi"] is None


def test_an_overlay_exhibit_records_the_alignment(wcase):
    add_crop(wcase, "Q1", page=1, box=[0, 0, 600, 300])
    add_crop(wcase, "K1", page=1, box=[0, 0, 400, 200])
    ex = make_exhibit(wcase, title="Overlay", kind="overlay",
                      overlay={"a": "C1", "b": "C2", "dx": 12, "dy": -4, "rotation": 1.5, "scale": 1.02})
    assert ex["kind"] == "overlay" and ex["overlay"]["rotation"] == 1.5
    assert (wcase.path / ex["file"]).is_file()


@pytest.mark.parametrize("kwargs", [
    {"title": "T", "panels": []},
    {"title": "T", "panels": [{"crop_id": "C9"}]},
    {"title": "", "panels": [{"crop_id": "C1"}]},
    {"title": "T", "panels": [{"crop_id": "C1"}] * 13},
    {"title": "T", "kind": "overlay", "overlay": {"a": "C1", "b": "C1", "dx": 0, "dy": 0, "rotation": 99, "scale": 1}},
])
def test_bad_exhibits_are_refused(wcase, kwargs):
    add_crop(wcase, "Q1", page=1, box=[0, 0, 600, 300])
    with pytest.raises(CaseError):
        make_exhibit(wcase, **kwargs)


# ---------------------------------------------------------------- report

def test_the_report_shows_the_examiner_work(wcase):
    add_crop(wcase, "Q1", page=1, box=[0, 0, 600, 300], label="Questioned signature")
    add_crop(wcase, "K1", page=1, box=[0, 0, 400, 200])
    add_note(wcase, target="C1", text="Blunt start <b>here</b>")
    add_measurement(wcase, crop_id="C1", kind="line", points=[[0, 0], [300, 0]])
    run_clone_check(wcase)
    make_exhibit(wcase, title="Chart 1", panels=[{"crop_id": "C1"}, {"crop_id": "C2"}])
    html, data = build_report(wcase)
    assert "Questioned signature" in html and "Chart 1" in html and "M1" in html
    assert "Blunt start &lt;b&gt;here&lt;/b&gt;" in html
    assert 'src="data:image/png;base64,' in html
    assert [c["crop_id"] for c in data["crops"]] == ["C1", "C2"]


# ---------------------------------------------------------------- ledger lock

def test_many_threads_can_append_and_the_chain_stays_valid(tmp_path):
    lg = Ledger(tmp_path / "ledger.log")
    lg.append("case.created", {"case_id": "x", "title": "t"})

    def work(n):
        for i in range(25):
            lg.append("test.event", {"thread": n, "i": i})
    threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    entries, errors = vc.parse_ledger(lg.path)
    assert errors == [] and len(entries) == 151


def test_the_ledger_lock_can_be_taken_twice_by_the_same_thread(tmp_path):
    lg = Ledger(tmp_path / "ledger.log")
    with lg.lock(), lg.lock():
        lg.append("a", {})
    assert len(lg.entries()) == 1


def test_the_lock_file_is_not_put_in_an_export(wcase, tmp_path):
    import zipfile

    from forensic_hand.export import export_case

    add_crop(wcase, "Q1", page=1, box=[0, 0, 100, 100])
    out = tmp_path / "x.zip"
    export_case(wcase, out)
    names = zipfile.ZipFile(out).namelist()
    assert "ledger.lock" not in names and any(n.startswith("derived/") for n in names)
