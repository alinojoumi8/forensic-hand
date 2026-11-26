"""Shared test helpers.

All files made here are synthetic. They prove the logic. They are NOT proof on real case files.
"""

from __future__ import annotations

import io
import re
from datetime import UTC, datetime
from pathlib import Path

import pikepdf
import pytest
from pikepdf import Dictionary, Name
from PIL import Image, ImageDraw, ImageFilter


@pytest.fixture(autouse=True)
def _no_real_signature_check_for_fake_tokens(request, monkeypatch):
    """The fake time stamp tokens below have no real signature.

    Outside network tests, the signature check at intake reports "could not run", the same as a
    computer with no OpenSSL. A test that needs another answer patches seal._check_signature itself.
    The stand-alone checker (verify_case) is never patched here.
    """
    if request.node.get_closest_marker("network"):
        return
    from forensic_hand import seal

    monkeypatch.setattr(seal, "_check_signature",
                        lambda *a, **k: ("unavailable", "test token: the signature is not checked in tests"))


# ---------------------------------------------------------------- images

def make_stroke_image(size=(1200, 800), blur=0.0, mode="L") -> Image.Image:
    """White page with dark pen-like strokes."""
    img = Image.new("L", size, 255)
    d = ImageDraw.Draw(img)
    for i in range(12):
        y = 50 + i * 58
        d.line([(60, y), (size[0] - 60, y + 18)], fill=0, width=3)
        d.arc([90 + i * 70, y - 28, 210 + i * 70, y + 38], 0, 300, fill=0, width=2)
    if blur:
        img = img.filter(ImageFilter.GaussianBlur(blur))
    return img.convert(mode)


def save_image(path: Path, img: Image.Image, **kw) -> Path:
    img.save(path, **kw)
    return path


@pytest.fixture
def sharp_png(tmp_path) -> Path:
    return save_image(tmp_path / "sharp.png", make_stroke_image(), dpi=(300, 300))


@pytest.fixture
def other_png(tmp_path) -> Path:
    return save_image(tmp_path / "other.png", make_stroke_image(size=(1300, 900)), dpi=(300, 300))


@pytest.fixture
def case(tmp_path, sharp_png, other_png):
    """A small checked case: one questioned PDF and two known images."""
    from forensic_hand.case import Case
    from forensic_hand.checks import run_checks

    pdf = tmp_path / "doc.pdf"
    pdf.write_bytes(text_pdf())
    c = Case.create(tmp_path / "case", title="Seal test")
    c.add_evidence(pdf, role="questioned", doc_date="2024-06-01")
    c.add_evidence(sharp_png, role="known", doc_date="2023-05-01")
    c.add_evidence(other_png, role="known", doc_date="2023-07-01")
    run_checks(c)
    return c


# ---------------------------------------------------------------- PDFs

def _save_classic(pdf: pikepdf.Pdf, **kw) -> bytes:
    buf = io.BytesIO()
    pdf.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.disable, deterministic_id=True, **kw)
    return buf.getvalue()


def _add_font(pdf: pikepdf.Pdf, page) -> None:
    font = pdf.make_indirect(Dictionary(Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica))
    res = page.obj.get("/Resources", Dictionary())
    res["/Font"] = Dictionary(F1=font)
    page.obj["/Resources"] = res


def text_pdf(
    producer="TestWriter 1.0",
    creation="D:20240101120000Z",
    mod="D:20240101120000Z",
    linearize=False,
) -> bytes:
    """A one-page PDF with typed text only."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(612, 792))
    _add_font(pdf, page)
    page.obj["/Contents"] = pdf.make_stream(b"BT /F1 24 Tf 72 700 Td (Hello) Tj ET")
    pdf.docinfo["/Producer"] = producer
    pdf.docinfo["/CreationDate"] = creation
    if mod:
        pdf.docinfo["/ModDate"] = mod
    return _save_classic(pdf, linearize=linearize)


def scan_pdf(px=(850, 1100), extra_image=False, text=False, invisible=False, annotation=False,
             page_size=(612, 792)) -> bytes:
    """A one-page PDF that looks like a scan: one image that fills the page."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=page_size)
    img = make_stroke_image(size=px)
    xobjects = Dictionary()
    xobjects["/Im0"] = pdf.make_stream(
        img.tobytes(), Type=Name.XObject, Subtype=Name.Image, Width=px[0], Height=px[1],
        ColorSpace=Name.DeviceGray, BitsPerComponent=8,
    )
    content = b"q %f 0 0 %f 0 0 cm /Im0 Do Q\n" % page_size
    if extra_image:
        small = make_stroke_image(size=(400, 160))
        xobjects["/Im1"] = pdf.make_stream(
            small.tobytes(), Type=Name.XObject, Subtype=Name.Image, Width=400, Height=160,
            ColorSpace=Name.DeviceGray, BitsPerComponent=8,
        )
        content += b"q 150 0 0 60 300 100 cm /Im1 Do Q\n"
    page.obj["/Resources"] = Dictionary(XObject=xobjects)
    if text:
        _add_font(pdf, page)
        mode = b"3 Tr " if invisible else b""
        content += b"BT /F1 12 Tf " + mode + b"72 500 Td (Typed text on top) Tj ET\n"
    if annotation:
        annot = pdf.make_indirect(Dictionary(
            Type=Name.Annot, Subtype=Name.FreeText, Rect=[100, 100, 300, 140],
            Contents=pikepdf.String("added later"),
        ))
        page.obj["/Annots"] = pikepdf.Array([annot])
    page.obj["/Contents"] = pdf.make_stream(content)
    pdf.docinfo["/Producer"] = "ScanTool 2"
    pdf.docinfo["/CreationDate"] = "D:20240101120000Z"
    return _save_classic(pdf)


def form_bomb_pdf(levels: int = 6, fanout: int = 10) -> bytes:
    """A tiny PDF whose drawings reuse each other: fanout ** (levels + 1) image placements."""
    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(612, 792))
    img = pdf.make_stream(b"\x80" * 4, Type=Name.XObject, Subtype=Name.Image, Width=2, Height=2,
                          ColorSpace=Name.DeviceGray, BitsPerComponent=8)
    draw = b"".join(b"q 1 0 0 1 %d 0 cm /X Do Q\n" % i for i in range(fanout))
    inner = pdf.make_stream(b"q 10 0 0 10 0 0 cm /X Do Q\n", Type=Name.XObject, Subtype=Name.Form,
                            BBox=[0, 0, 612, 792], Resources=Dictionary(XObject=Dictionary(X=img)))
    for _ in range(levels):
        inner = pdf.make_stream(draw, Type=Name.XObject, Subtype=Name.Form, BBox=[0, 0, 612, 792],
                                Resources=Dictionary(XObject=Dictionary(X=inner)))
    page.obj["/Resources"] = Dictionary(XObject=Dictionary(X=inner))
    page.obj["/Contents"] = pdf.make_stream(draw)
    return _save_classic(pdf)


def _trailer_facts(data: bytes) -> dict:
    with pikepdf.open(io.BytesIO(data)) as pdf:
        info = pdf.trailer.get("/Info")
        return {
            "root": pdf.Root.objgen[0],
            "size": int(pdf.trailer["/Size"]),
            "info": info.objgen[0] if info is not None else None,
        }


def append_update(data: bytes, new_objects: dict[int, bytes]) -> bytes:
    """Append a hand-made incremental update (the way an editor saves a change)."""
    facts = _trailer_facts(data)
    prev = int(re.findall(rb"startxref\s+(\d+)", data)[-1])
    out = bytearray(data)
    if not out.endswith(b"\n"):
        out += b"\n"
    offsets = {}
    for num, body in new_objects.items():
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n"
    for num in sorted(offsets):
        out += b"%d 1\n" % num + b"%010d 00000 n \n" % offsets[num]
    size = max(facts["size"], max(offsets) + 1)
    out += b"trailer\n<< /Size %d /Root %d 0 R /Prev %d" % (size, facts["root"], prev)
    if facts["info"]:
        out += b" /Info %d 0 R" % facts["info"]
    out += b" >>\nstartxref\n%d\n%%%%EOF\n" % xref_pos
    return bytes(out)


def append_info_update(data: bytes, producer="EditTool 9", mod="D:20250615093000Z") -> bytes:
    """Rewrite the Info dictionary in an incremental update (new producer, new ModDate)."""
    info = _trailer_facts(data)["info"]
    body = b"<< /Producer (%s) /CreationDate (D:20240101120000Z) /ModDate (%s) >>" % (
        producer.encode(), mod.encode())
    return append_update(data, {info: body})


def append_fake_signature(data: bytes) -> bytes:
    """Append a signature dictionary whose /ByteRange covers the whole final file.

    The signature value is zeros. Only the byte-range layout is real.
    """
    num = _trailer_facts(data)["size"]
    body = (
        b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached"
        b" /M (D:20240105100000Z)"
        b" /ByteRange [0000000000 1111111111 2222222222 3333333333]"
        b" /Contents <" + b"00" * 64 + b"> >>"
    )
    out = bytearray(append_update(data, {num: body}))
    marker = out.rindex(b"/Contents <") + len(b"/Contents ")
    c_start = marker
    c_end = out.index(b">", marker) + 1
    values = [0, c_start, c_end, len(out) - c_end]
    for placeholder, value in zip((b"0000000000", b"1111111111", b"2222222222", b"3333333333"), values):
        pos = out.rindex(b"/ByteRange [")
        idx = out.index(placeholder, pos)
        out[idx:idx + 10] = b"%010d" % value
    return bytes(out)


# ---------------------------------------------------------------- time stamps

def fake_tsr(digest: bytes, nonce: int | None, status="granted",
             gen_time=datetime(2026, 11, 26, 15, 30, 0, tzinfo=UTC)) -> bytes:
    """A time stamp response built by an independent library (asn1crypto). It has no real signature."""
    from asn1crypto import cms, tsp

    if status != "granted":
        # A refusal has a status and no token. asn1crypto cannot write that shape, so wrap by hand.
        status_info = tsp.PKIStatusInfo({"status": status}).dump()
        return bytes([0x30, len(status_info)]) + status_info
    info = {
        "version": "v1",
        "policy": "1.2.3.4.5",
        "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": digest},
        "serial_number": 4242,
        "gen_time": gen_time,
    }
    if nonce is not None:
        info["nonce"] = nonce
    signed = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [{"algorithm": "sha256"}],
        "encap_content_info": {"content_type": "tst_info", "content": tsp.TSTInfo(info)},
        "signer_infos": [],
    })
    token = cms.ContentInfo({"content_type": "signed_data", "content": signed})
    return tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": token}).dump()
