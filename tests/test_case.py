from __future__ import annotations

import hashlib

import pytest
from conftest import is_read_only

from forensic_hand.case import Case, CaseError
from forensic_hand.checks import run_checks


def test_create_then_open(tmp_path):
    case = Case.create(tmp_path / "c1", title="Will of A. Example")
    again = Case.open(tmp_path / "c1")
    state = again.state()
    assert state["title"] == "Will of A. Example"
    assert state["case_id"] == case.state()["case_id"] != ""
    assert (tmp_path / "c1" / "verify_case.py").is_file()


def test_create_refuses_a_folder_that_has_files(tmp_path):
    (tmp_path / "busy").mkdir()
    (tmp_path / "busy" / "x.txt").write_text("x")
    with pytest.raises(CaseError):
        Case.create(tmp_path / "busy", title="t")


def test_open_refuses_a_folder_that_is_not_a_case(tmp_path):
    with pytest.raises(CaseError):
        Case.open(tmp_path)


def test_add_evidence_stores_identical_bytes_read_only(tmp_path, sharp_png):
    before = sharp_png.read_bytes()
    case = Case.create(tmp_path / "c", title="t")
    rec = case.add_evidence(sharp_png, role="questioned")
    stored = case.path / rec["stored_as"]
    assert rec["id"] == "Q1"
    assert rec["name"] == "sharp.png"
    assert rec["media_type"] == "png"
    assert rec["sha256"] == hashlib.sha256(before).hexdigest()
    assert rec["blake2b"] == hashlib.blake2b(before).hexdigest()
    assert rec["size"] == len(before)
    assert stored.read_bytes() == before
    assert is_read_only(stored)
    assert sharp_png.read_bytes() == before


def test_ids_count_up_inside_each_role(tmp_path, sharp_png, other_png):
    case = Case.create(tmp_path / "c", title="t")
    ids = [
        case.add_evidence(sharp_png, role="questioned")["id"],
        case.add_evidence(other_png, role="known")["id"],
        case.add_evidence(other_png, role="known")["id"],
        case.add_evidence(sharp_png, role="other")["id"],
    ]
    assert ids == ["Q1", "K1", "K2", "X1"]


@pytest.mark.parametrize("kwargs", [
    {"role": "suspect"},
    {"role": "known", "doc_date": "12/05/2021"},
    {"role": "known", "doc_date": "2021-13-40"},
])
def test_bad_input_is_rejected_and_nothing_is_recorded(tmp_path, sharp_png, kwargs):
    case = Case.create(tmp_path / "c", title="t")
    count = len(case.ledger.entries())
    with pytest.raises(CaseError):
        case.add_evidence(sharp_png, **kwargs)
    assert len(case.ledger.entries()) == count


def test_a_missing_file_is_rejected(tmp_path):
    case = Case.create(tmp_path / "c", title="t")
    with pytest.raises(CaseError):
        case.add_evidence(tmp_path / "nope.png", role="known")


def test_a_correction_is_a_new_event_not_an_edit(tmp_path, sharp_png):
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(sharp_png, role="known", doc_date="2020-01-01")
    first_lines = case.ledger.path.read_bytes()
    case.annotate("K1", doc_date="2021-05-03", signer="A. Example")
    rec = case.state()["evidence"][0]
    assert (rec["doc_date"], rec["signer"]) == ("2021-05-03", "A. Example")
    assert case.ledger.path.read_bytes().startswith(first_lines)
    assert case.ledger.entries()[-1]["type"] == "evidence.annotated"


def test_annotate_unknown_id_is_rejected(tmp_path):
    case = Case.create(tmp_path / "c", title="t")
    with pytest.raises(CaseError):
        case.annotate("K9", doc_date="2021-05-03")


def test_the_ledger_keeps_the_file_name_but_not_the_folder_path(tmp_path, sharp_png):
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(sharp_png, role="questioned")
    text = case.ledger.path.read_text(encoding="utf-8")
    assert "sharp.png" in text
    assert str(sharp_png.parent) not in text
    assert str(sharp_png.parent).replace("\\", "\\\\") not in text


def _codes(findings):
    return {f["code"] for f in findings}


def test_same_bytes_added_twice_is_flagged(tmp_path, sharp_png, other_png):
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(sharp_png, role="questioned")
    case.add_evidence(sharp_png, role="known")
    case.add_evidence(other_png, role="known")
    result = run_checks(case)
    dup = [f for f in result["case_findings"] if f["code"] == "CASE-DUPLICATE"]
    assert dup and dup[0]["level"] == "warning"
    assert set(dup[0]["data"]["ids"]) == {"Q1", "K1"}


def test_case_with_no_known_samples_is_flagged(tmp_path, sharp_png):
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(sharp_png, role="questioned")
    assert "CASE-NO-KNOWN" in _codes(run_checks(case)["case_findings"])


def test_few_known_samples_is_flagged(tmp_path, sharp_png, other_png):
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(sharp_png, role="questioned")
    case.add_evidence(other_png, role="known")
    few = [f for f in run_checks(case)["case_findings"] if f["code"] == "CASE-FEW-KNOWN"]
    assert few and few[0]["level"] == "warning" and few[0]["data"]["known_count"] == 1


def test_known_samples_far_in_time_from_the_questioned_item_are_flagged(tmp_path, sharp_png, other_png):
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(sharp_png, role="questioned", doc_date="2024-06-01")
    case.add_evidence(other_png, role="known", doc_date="2012-01-15")
    findings = run_checks(case)["case_findings"]
    far = [f for f in findings if f["code"] == "CASE-NOT-CONTEMPORANEOUS"]
    assert far and far[0]["data"]["questioned"] == "Q1"


def test_known_sample_close_in_time_is_not_flagged(tmp_path, sharp_png, other_png):
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(sharp_png, role="questioned", doc_date="2024-06-01")
    case.add_evidence(other_png, role="known", doc_date="2023-01-15")
    assert "CASE-NOT-CONTEMPORANEOUS" not in _codes(run_checks(case)["case_findings"])


def test_missing_dates_are_flagged(tmp_path, sharp_png, other_png):
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(sharp_png, role="questioned")
    case.add_evidence(other_png, role="known")
    missing = [f for f in run_checks(case)["case_findings"] if f["code"] == "CASE-DATE-MISSING"]
    assert missing and set(missing[0]["data"]["ids"]) == {"Q1", "K1"}


def test_checks_are_recorded_in_the_ledger_with_the_settings_used(tmp_path, sharp_png):
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(sharp_png, role="questioned")
    run_checks(case)
    types = [e["type"] for e in case.ledger.entries()]
    assert "env.recorded" in types and "check.file" in types and "check.case" in types
    env = [e for e in case.ledger.entries() if e["type"] == "env.recorded"][-1]["data"]
    assert env["config"]["dpi_warning_below"] == 150
    assert len(env["config_sha256"]) == 64
    assert env["packages"]["pikepdf"]
    assert case.state()["files"]["Q1"]["kind"] == "image"


def test_unknown_file_type_is_stored_and_flagged(tmp_path):
    blob = tmp_path / "notes.xyz"
    blob.write_bytes(b"\x00\x01 some bytes that are not a known format")
    case = Case.create(tmp_path / "c", title="t")
    rec = case.add_evidence(blob, role="other")
    assert rec["media_type"] == "unknown"
    result = run_checks(case)
    assert "FILE-UNKNOWN-TYPE" in _codes(result["files"]["X1"]["findings"])


def test_wrong_file_extension_is_flagged(tmp_path, sharp_png):
    fake = tmp_path / "looks-like.pdf"
    fake.write_bytes(sharp_png.read_bytes())
    case = Case.create(tmp_path / "c", title="t")
    case.add_evidence(fake, role="questioned")
    result = run_checks(case)
    assert "FILE-EXT-MISMATCH" in _codes(result["files"]["Q1"]["findings"])
    assert result["files"]["Q1"]["kind"] == "image"
