"""Tests for the 12 findings of the first CodeRabbit review (2026-11-26).

Each test names the finding it proves. The files are synthetic: they prove the logic only.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import stat
import time

import pytest
from conftest import fake_tsr, form_bomb_pdf, is_read_only

from forensic_hand import seal as seal_mod
from forensic_hand import store as store_mod
from forensic_hand import tsa
from forensic_hand import verify_case as vc
from forensic_hand.case import Case, CaseError
from forensic_hand.cli import main
from forensic_hand.pdf_audit import audit_pdf
from forensic_hand.seal import SealError, create_seal, timestamp_seal


def _verify(case):
    return vc.verify_case(case.path, check_tsa_signature=False)


def _writable(path):
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)


def _tsa_returns(monkeypatch, nonce=7):
    monkeypatch.setattr(tsa, "request_timestamp", lambda url, digest, timeout=20: (fake_tsr(digest, nonce), nonce))


def _fail_append(monkeypatch, case, kind, *, after_write=False):
    real = case.ledger.append

    def flaky(type, data, time=None):
        if type == kind:
            if after_write:
                real(type, data, time)
            raise OSError("disk full")
        return real(type, data, time)
    monkeypatch.setattr(case.ledger, "append", flaky)


# ------------------------------------------------ 1. PDF: limit work across the complete Form traversal

def test_1_a_form_bomb_pdf_stops_quickly_and_says_screening_is_incomplete(tmp_path):
    path = tmp_path / "bomb.pdf"
    path.write_bytes(form_bomb_pdf(levels=6, fanout=10))   # 10 million placements if not limited
    started = time.perf_counter()
    result = audit_pdf(path)
    assert time.perf_counter() - started < 30
    incomplete = [f for f in result["findings"] if f["code"] == "PDF-SCREEN-INCOMPLETE"]
    assert incomplete and incomplete[0]["level"] == "warning" and incomplete[0]["data"]["stopped_on_page"] == 1
    assert len(result["facts"]["page_images"]) <= 1000


def test_1_a_normal_pdf_with_repeated_drawings_is_screened_in_full(tmp_path):
    path = tmp_path / "small.pdf"
    path.write_bytes(form_bomb_pdf(levels=2, fanout=3))    # 27 placements: inside the limits
    result = audit_pdf(path)
    assert "PDF-SCREEN-INCOMPLETE" not in {f["code"] for f in result["findings"]}
    assert result["facts"]["page_facts"][0]["images"] == 27


# ------------------------------------------------ 2. checker: check every record for a shared file

def test_2_every_record_that_names_a_shared_file_is_checked(tmp_path, sharp_png):
    case = Case.create(tmp_path / "c", title="t")
    rec = case.add_evidence(sharp_png, role="questioned")
    assert _verify(case)["ok"] is True
    case.ledger.append("evidence.added", {**rec, "id": "K1", "role": "known", "size": rec["size"] + 1})
    result = _verify(case)
    assert result["ok"] is False
    assert any(p.startswith("evidence K1:") and "does not match" in p for p in result["problems"])


# ------------------------------------------------ 3. checker: validate event fields before use

@pytest.mark.parametrize("events", [
    [("seal.created", {"seal_no": [1], "file": "seals/seal-0001.json"})],
    [("seal.created", {"seal_no": "1"})],
    [("seal.created", {"seal_no": 1}), ("seal.timestamped", {"seal_no": 1, "tsr_file": "seals/seal-0001.tsr"})],
    [("seal.timestamped", {"seal_no": {"a": 1}, "tsr_file": ["x"]})],
    [("evidence.added", {"id": ["Q"], "stored_as": 5})],
])
def test_3_bad_field_types_are_problems_not_crashes(tmp_path, events):
    case = Case.create(tmp_path / "c", title="t")
    for kind, data in events:
        case.ledger.append(kind, data)
    result = _verify(case)
    assert result["status"] == "problems" and result["problems"]
    assert not any("unexpected error" in p for p in result["problems"])


def test_3_an_unexpected_error_fails_closed(case, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr(vc, "_check_seals", boom)
    result = _verify(case)
    assert result["ok"] is False and any("NOT verified" in p for p in result["problems"])


# ------------------------------------------------ 4. checker: say that it cannot prove the copy is complete

def test_4_the_checker_states_it_cannot_prove_the_copy_is_the_newest(case, capsys):
    seal = create_seal(case)
    assert vc.main([str(case.path), "--skip-tsa-signature"]) == 0
    out = capsys.readouterr().out
    assert "newest copy" in out and "separate, trusted route" in out
    assert f"Last seal:      1, sha256 {seal['sha256']}" in out
    assert "newest copy" in vc.__doc__


def test_4_an_older_copy_still_passes_which_is_why_the_limit_is_stated(case, tmp_path):
    import shutil

    create_seal(case)
    older = tmp_path / "older"
    shutil.copytree(case.path, older)
    create_seal(case)
    old = vc.verify_case(older, check_tsa_signature=False)
    new = vc.verify_case(case.path, check_tsa_signature=False)
    assert old["ok"] and new["ok"]
    assert old["summary"]["last_seal"] != new["summary"]["last_seal"]


# ------------------------------------------------ 5. seal: recover when the ledger append does not commit

def test_5_a_failed_seal_append_removes_the_new_file_and_a_retry_works(case, monkeypatch):
    _fail_append(monkeypatch, case, "seal.created")
    with pytest.raises(SealError, match="disk full"):
        create_seal(case)
    assert list((case.path / "seals").iterdir()) == []
    monkeypatch.undo()
    assert create_seal(case)["seal_no"] == 1
    assert _verify(case)["ok"] is True


def test_5_when_the_append_did_commit_the_seal_file_is_kept(case, monkeypatch):
    _fail_append(monkeypatch, case, "seal.created", after_write=True)
    with pytest.raises(SealError):
        create_seal(case)
    assert (case.path / "seals" / "seal-0001.json").is_file()
    assert _verify(case)["ok"] is True


def test_5_a_seal_file_left_by_a_hard_stop_is_taken_over_when_it_matches(case):
    state = case.state()
    seq, head = case.ledger.head()
    orphan = case.path / "seals" / "seal-0001.json"
    orphan.write_bytes(seal_mod.seal_bytes(state, 1, seq, head))   # as if the process died here
    seal = create_seal(case)
    assert seal["sha256"] == hashlib.sha256(orphan.read_bytes()).hexdigest()
    assert is_read_only(orphan)
    assert _verify(case)["ok"] is True


def test_5_a_seal_file_that_does_not_match_is_refused_and_kept(case, tmp_path):
    state = case.state()
    seq, head = case.ledger.head()
    orphan = case.path / "seals" / "seal-0001.json"
    orphan.write_bytes(seal_mod.seal_bytes(state, 1, seq, head))
    extra = tmp_path / "extra.txt"
    extra.write_text("more")
    case.add_evidence(extra, role="other")                            # the case moved on
    with pytest.raises(SealError, match="cut short"):
        create_seal(case)
    assert orphan.is_file()


# ------------------------------------------------ 6. checker: no success when a requested check cannot run

def test_6_cli_verify_returns_3_when_the_signature_check_cannot_run(tmp_path, sharp_png, other_png, monkeypatch, capsys):
    _tsa_returns(monkeypatch)
    case_dir = tmp_path / "c"
    assert main(["intake", str(case_dir), "--title", "t", "--questioned", str(sharp_png),
                 "--known", str(other_png), "--timestamp"]) == 0
    capsys.readouterr()
    assert main(["verify", str(case_dir), "--openssl", str(tmp_path / "missing.exe")]) == 3
    out = capsys.readouterr().out
    assert "RESULT: INCOMPLETE" in out and "UNCHECKED:" in out
    assert main(["verify", str(case_dir), "--skip-tsa-signature"]) == 0


# ------------------------------------------------ 7. store: read-only before publishing

def test_7_a_writable_stored_copy_is_made_read_only_again_on_reuse(tmp_path, sharp_png):
    case = Case.create(tmp_path / "c", title="t")
    rec = case.add_evidence(sharp_png, role="questioned")
    stored = case.path / rec["stored_as"]
    _writable(stored)
    case.add_evidence(sharp_png, role="known")
    assert is_read_only(stored)


def test_7_a_failed_publish_leaves_no_file_and_records_nothing(tmp_path, sharp_png, monkeypatch):
    case = Case.create(tmp_path / "c", title="t")
    count = len(case.ledger.entries())

    def broken_replace(src, dst):
        raise OSError("device busy")
    monkeypatch.setattr(store_mod.os, "replace", broken_replace)
    with pytest.raises(CaseError, match="device busy"):
        case.add_evidence(sharp_png, role="questioned")
    assert list((case.path / "evidence").iterdir()) == []
    assert len(case.ledger.entries()) == count


def test_7_the_new_file_is_read_only_before_it_gets_its_final_name(tmp_path, sharp_png, monkeypatch):
    seen = {}
    real_replace = os.replace

    def watch(src, dst):
        seen["writable"] = not is_read_only(src)
        return real_replace(src, dst)
    monkeypatch.setattr(store_mod.os, "replace", watch)
    Case.create(tmp_path / "c", title="t").add_evidence(sharp_png, role="questioned")
    assert seen["writable"] is False


# ------------------------------------------------ 8. time stamp: a failed append is retryable

def test_8_a_failed_time_stamp_append_removes_the_file_and_a_retry_works(case, monkeypatch):
    create_seal(case)
    _tsa_returns(monkeypatch)
    _fail_append(monkeypatch, case, "seal.timestamped")
    with pytest.raises(SealError, match="disk full"):
        timestamp_seal(case, url="http://tsa.invalid/tsr")
    assert list((case.path / "seals").glob("*.tsr")) == []
    monkeypatch.setattr(case.ledger, "append", type(case.ledger).append.__get__(case.ledger))
    assert timestamp_seal(case, url="http://tsa.invalid/tsr")["seal_no"] == 1
    assert _verify(case)["ok"] is True


def test_8_a_time_stamp_file_left_by_a_hard_stop_is_taken_over_with_no_new_request(case, monkeypatch):
    seal = create_seal(case)
    orphan = case.path / "seals" / "seal-0001.tsr"
    orphan.write_bytes(fake_tsr(bytes.fromhex(seal["sha256"]), 99))

    def no_network(*a, **k):
        raise AssertionError("a new request was sent")
    monkeypatch.setattr(tsa, "request_timestamp", no_network)
    stamp = timestamp_seal(case, url="http://tsa.invalid/tsr")
    assert stamp["recovered_from_earlier_run"] is True
    assert is_read_only(orphan)
    assert _verify(case)["ok"] is True


def test_8_a_time_stamp_file_for_other_data_is_refused_and_kept(case):
    create_seal(case)
    orphan = case.path / "seals" / "seal-0001.tsr"
    orphan.write_bytes(fake_tsr(hashlib.sha256(b"other").digest(), 99))
    with pytest.raises(SealError, match="cut short"):
        timestamp_seal(case, url="http://tsa.invalid/tsr")
    assert orphan.is_file()


# ------------------------------------------------ 9. time stamp: check the signature before recording

def test_9_a_time_stamp_with_a_bad_signature_is_refused_and_not_recorded(case, monkeypatch):
    create_seal(case)
    _tsa_returns(monkeypatch)
    monkeypatch.setattr(seal_mod, "_check_signature", lambda *a, **k: ("failed", "bad signature"))
    count = len(case.ledger.entries())
    with pytest.raises(SealError, match="signature check failed"):
        timestamp_seal(case, url="http://tsa.invalid/tsr")
    assert len(case.ledger.entries()) == count
    assert list((case.path / "seals").glob("*.tsr")) == []


def test_9_a_good_signature_is_recorded_as_checked(case, monkeypatch):
    create_seal(case)
    _tsa_returns(monkeypatch)
    monkeypatch.setattr(seal_mod, "_check_signature", lambda *a, **k: ("ok", "OpenSSL 3.6.1, roots"))
    stamp = timestamp_seal(case, url="http://tsa.invalid/tsr")
    assert stamp["signature_check"] == "ok"
    assert case.state()["seals"][0]["timestamp"]["signature_check"] == "ok"


def test_9_a_signature_that_could_not_be_checked_is_recorded_as_not_checked(case, monkeypatch, capsys):
    create_seal(case)
    _tsa_returns(monkeypatch)
    assert main(["stamp", str(case.path), "--tsa-url", "http://tsa.invalid/tsr"]) == 0
    out = capsys.readouterr().out
    assert "Signature:  NOT checked" in out
    from forensic_hand.report import build_report

    assert "not checked" in build_report(case)[0]


def test_9_the_real_check_refuses_an_unsigned_token(case, monkeypatch):
    if vc.find_openssl() is None:
        pytest.skip("OpenSSL is not installed")
    create_seal(case)
    _tsa_returns(monkeypatch)
    monkeypatch.setattr(seal_mod, "_check_signature",
                        lambda reply, digest, info, ca_file=None, openssl=None:
                        vc.openssl_verify_timestamp(reply, digest, info, ca_file, openssl))
    with pytest.raises(SealError, match="signature check failed"):
        timestamp_seal(case, url="http://tsa.invalid/tsr")


# ------------------------------------------------ 10. covered in test_seal_verify.py
#   test_openssl_checks_the_given_bytes_and_digest_not_the_files


# ------------------------------------------------ 11. checker: reject duplicate seal numbers

def test_11_a_duplicate_seal_number_is_a_problem(case):
    seal = create_seal(case)
    case.ledger.append("seal.created", dict(seal))
    result = _verify(case)
    assert result["ok"] is False
    assert any("more than once" in p for p in result["problems"])


def test_11_a_duplicate_time_stamp_record_is_a_problem(case, monkeypatch):
    create_seal(case)
    _tsa_returns(monkeypatch)
    stamp = timestamp_seal(case, url="http://tsa.invalid/tsr")
    case.ledger.append("seal.timestamped", dict(stamp))
    assert any("more than one time stamp" in p for p in _verify(case)["problems"])


# ------------------------------------------------ 12. checker: unreadable files are problems

def test_12_an_unreadable_evidence_file_is_a_problem(case, monkeypatch):
    def denied(path):
        raise PermissionError(13, "Access is denied")
    monkeypatch.setattr(vc, "hash_file", denied)
    result = _verify(case)
    assert result["ok"] is False
    assert any("cannot be read" in p for p in result["problems"])


def test_12_an_unreadable_seal_file_is_a_problem(case, monkeypatch):
    create_seal(case)
    real = pathlib.Path.read_bytes

    def read(self):
        if self.name.startswith("seal-"):
            raise PermissionError(13, "Access is denied")
        return real(self)
    monkeypatch.setattr(pathlib.Path, "read_bytes", read)
    result = _verify(case)
    assert result["ok"] is False
    assert any("seal 1" in p and "cannot be read" in p for p in result["problems"])


# ================================================ CodeRabbit review 2 (2026-11-26)

def _crowded_scan_pdf(tiny: int) -> bytes:
    """`tiny` small pictures first, then a full-page 100 DPI scan, then visible typed text."""
    import io

    import pikepdf
    from conftest import make_stroke_image
    from pikepdf import Dictionary, Name

    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(612, 792))
    dot = pdf.make_stream(b"\x00" * 4, Type=Name.XObject, Subtype=Name.Image, Width=2, Height=2,
                          ColorSpace=Name.DeviceGray, BitsPerComponent=8)
    scan = make_stroke_image(size=(850, 1100))
    big = pdf.make_stream(scan.tobytes(), Type=Name.XObject, Subtype=Name.Image, Width=850, Height=1100,
                          ColorSpace=Name.DeviceGray, BitsPerComponent=8)
    font = pdf.make_indirect(Dictionary(Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica))
    page.obj["/Resources"] = Dictionary(XObject=Dictionary(D=dot, S=big), Font=Dictionary(F1=font))
    content = b"".join(b"q 1 0 0 1 %d %d cm /D Do Q\n" % (i % 600, i // 600) for i in range(tiny))
    content += b"q 612 0 0 792 0 0 cm /S Do Q\nBT /F1 12 Tf 72 500 Td (Typed on top) Tj ET\n"
    page.obj["/Contents"] = pdf.make_stream(content)
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def test_r2_a_crowded_page_keeps_the_scan_checks_and_says_screening_is_incomplete(tmp_path):
    path = tmp_path / "crowded.pdf"
    path.write_bytes(_crowded_scan_pdf(tiny=1200))
    result = audit_pdf(path)
    codes = {f["code"]: f for f in result["findings"]}
    assert "PDF-IMG-DPI-LOW" in codes                 # the full-page scan was still found
    assert "PDF-TEXT-OVER-SCAN" in codes
    assert codes["PDF-SCREEN-INCOMPLETE"]["data"]["crowded_pages"] == [1]
    assert result["facts"]["page_facts"][0]["images"] == 1201


def test_r2_a_page_under_the_picture_cap_is_unchanged(tmp_path):
    path = tmp_path / "busy.pdf"
    path.write_bytes(_crowded_scan_pdf(tiny=50))
    codes = {f["code"] for f in audit_pdf(path)["findings"]}
    assert "PDF-SCREEN-INCOMPLETE" not in codes and "PDF-IMG-DPI-LOW" in codes


def test_r2_a_compressed_drawing_bomb_is_never_read_into_memory(tmp_path, monkeypatch):
    import io
    import zlib

    import pikepdf
    from pikepdf import Name

    from forensic_hand import pdf_audit

    pdf = pikepdf.new()
    page = pdf.add_blank_page(page_size=(612, 792))
    huge = b"q Q\n" * (3 * 1024 * 1024)             # 12 MB of drawing commands when decoded
    page.obj["/Contents"] = pdf.make_stream(zlib.compress(huge, 9), Filter=Name.FlateDecode)
    buf = io.BytesIO()
    pdf.save(buf, compress_streams=False)
    assert len(buf.getvalue()) < 200_000             # small in the file
    path = tmp_path / "zbomb.pdf"
    path.write_bytes(buf.getvalue())

    parsed = []
    real_parse = pikepdf.parse_content_stream
    monkeypatch.setattr(pdf_audit.pikepdf, "parse_content_stream",
                        lambda target, *a: parsed.append(1) or real_parse(target, *a))
    result = audit_pdf(path)
    incomplete = [f for f in result["findings"] if f["code"] == "PDF-SCREEN-INCOMPLETE"]
    assert incomplete and "MB when decoded" in incomplete[0]["detail"]
    assert parsed == []                               # the drawing list was never built


def test_r2_decoded_size_is_measured_with_a_cap():
    import zlib

    import pikepdf
    from pikepdf import Name

    from forensic_hand.pdf_audit import decoded_size_bound

    pdf = pikepdf.new()
    small = pdf.make_stream(zlib.compress(b"q Q\n" * 100), Filter=Name.FlateDecode)
    plain = pdf.make_stream(b"q Q\n" * 100)
    big = pdf.make_stream(zlib.compress(b"x" * 5000), Filter=Name.FlateDecode)
    assert decoded_size_bound(small) == 400
    assert decoded_size_bound(plain) == 400
    assert decoded_size_bound(big, limit=1000) is None


def test_r2_the_guide_says_an_unchecked_signature_is_recorded_as_not_checked():
    readme = (pathlib.Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
    assert '"not checked"' in readme and "INCOMPLETE" in readme


# ================================================ CodeRabbit review 3 (2026-11-26)

def _stream(pdf, data: bytes, filters):
    from pikepdf import Array, Name

    if not filters:
        return pdf.make_stream(data)
    names = [Name(f) for f in filters]
    return pdf.make_stream(data, Filter=names[0] if len(names) == 1 else Array(names))


def test_r3_a_two_stage_flate_bomb_is_bounded():
    import zlib

    import pikepdf

    from forensic_hand.pdf_audit import decoded_size_bound

    inner = zlib.compress(b"q Q\n" * (3 * 1024 * 1024), 9)      # 12 MB when fully decoded
    outer = zlib.compress(inner, 9)
    pdf = pikepdf.new()
    stream = _stream(pdf, outer, ["/FlateDecode", "/FlateDecode"])
    assert len(outer) < 4096
    assert decoded_size_bound(stream) is None


def test_r3_common_filter_chains_are_measured_exactly():
    import base64
    import binascii
    import zlib

    import pikepdf

    from forensic_hand.pdf_audit import decoded_size_bound

    body = b"q Q\n" * 100
    pdf = pikepdf.new()
    a85 = base64.a85encode(zlib.compress(body)) + b"~>"
    ahx = binascii.hexlify(zlib.compress(body)) + b">"
    assert decoded_size_bound(_stream(pdf, a85, ["/ASCII85Decode", "/FlateDecode"])) == 400
    assert decoded_size_bound(_stream(pdf, ahx, ["/ASCIIHexDecode", "/FlateDecode"])) == 400
    assert decoded_size_bound(_stream(pdf, body, [])) == 400


def test_r3_an_unmeasured_filter_inside_a_chain_is_not_trusted():
    import zlib

    import pikepdf

    from forensic_hand.pdf_audit import decoded_size_bound

    pdf = pikepdf.new()
    stream = _stream(pdf, zlib.compress(b"\x80" * 10), ["/FlateDecode", "/RunLengthDecode"])
    assert decoded_size_bound(stream) == 10 * 1000                # last stage: estimate
    stream = _stream(pdf, b"\x00a\x80", ["/RunLengthDecode", "/FlateDecode"])
    assert decoded_size_bound(stream) is None                     # inside the chain: refused


def test_r3_a_large_plain_drawing_is_refused_by_size(tmp_path):
    import pikepdf

    from forensic_hand.pdf_audit import decoded_size_bound

    pdf = pikepdf.new()
    assert decoded_size_bound(_stream(pdf, b"q Q\n" * (3 * 1024 * 1024), [])) is None


def test_r3_a_pdf_over_the_size_limit_is_stored_but_not_screened(tmp_path, monkeypatch):
    from conftest import text_pdf

    from forensic_hand import pdf_audit

    path = tmp_path / "big.pdf"
    path.write_bytes(text_pdf())
    monkeypatch.setattr(pdf_audit, "MAX_PDF_BYTES", 100)
    result = audit_pdf(path)
    assert [f["code"] for f in result["findings"]] == ["PDF-TOO-LARGE"]


@pytest.mark.parametrize("mode", [0o100420, 0o100402, 0o100644])
def test_r3_any_write_bit_on_a_stored_copy_is_removed_on_reuse(tmp_path, sharp_png, monkeypatch, mode):
    case = Case.create(tmp_path / "c", title="t")
    rec = case.add_evidence(sharp_png, role="questioned")
    stored = case.path / rec["stored_as"]
    real_stat, calls = os.stat, []

    def fake_stat(path, *a, **k):
        result = real_stat(path, *a, **k)
        if pathlib.Path(path) == stored:
            return os.stat_result((mode, *tuple(result)[1:]))
        return result

    def record_chmod(path, value):
        calls.append(value)
    monkeypatch.setattr(store_mod.os, "stat", fake_stat)
    monkeypatch.setattr(store_mod.os, "chmod", record_chmod)
    case.add_evidence(sharp_png, role="known")
    assert stat.S_IREAD in calls
