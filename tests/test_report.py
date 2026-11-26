from __future__ import annotations

import json

from conftest import append_info_update, fake_tsr, text_pdf

from forensic_hand import tsa
from forensic_hand.case import Case
from forensic_hand.checks import run_checks
from forensic_hand.report import build_report, write_report
from forensic_hand.seal import create_seal, timestamp_seal


def test_the_report_shows_hashes_limits_and_the_ledger_head(case):
    create_seal(case)
    html, data = build_report(case)
    state = case.state()
    for rec in state["evidence"]:
        assert rec["sha256"] in html
    assert state["ledger_head"] in html
    assert "indentation" in html.lower()
    assert "not an opinion" in html.lower()
    assert "No trusted time stamp" in html
    assert [e["id"] for e in data["evidence"]] == ["Q1", "K1", "K2"]
    assert data["ledger"]["head"] == state["ledger_head"]


def test_the_report_shows_the_time_stamp_when_there_is_one(case, monkeypatch):
    create_seal(case)
    monkeypatch.setattr(tsa, "request_timestamp", lambda url, digest, timeout=20: (fake_tsr(digest, 5), 5))
    timestamp_seal(case, url="http://tsa.invalid/tsr")
    html, data = build_report(case)
    assert "2026-11-26T15:30:00Z" in html
    assert "No trusted time stamp" not in html
    assert data["seals"][0]["timestamp"]["gen_time"] == "2026-11-26T15:30:00Z"


def test_the_report_shows_findings_with_their_limits(tmp_path, sharp_png):
    pdf = tmp_path / "edited.pdf"
    pdf.write_bytes(append_info_update(text_pdf()))
    case = Case.create(tmp_path / "c", title="Findings")
    case.add_evidence(pdf, role="questioned")
    run_checks(case)
    html, data = build_report(case)
    assert "PDF-INCREMENTAL" in html
    finding = next(f for f in data["files"]["Q1"]["findings"] if f["code"] == "PDF-INCREMENTAL")
    assert finding["limits"] in html or finding["limits"].replace("'", "&#x27;") in html


def test_hostile_text_is_escaped(tmp_path):
    pdf = tmp_path / "x.pdf"
    pdf.write_bytes(text_pdf(producer="<script>alert(1)</script>"))
    case = Case.create(tmp_path / "c", title='<img src=x onerror="alert(2)">')
    case.add_evidence(pdf, role="questioned", signer="</td><iframe src=//evil>", note="<b>bold</b>")
    run_checks(case)
    html, _ = build_report(case)
    lowered = html.lower()
    assert "<script" not in lowered and "<img" not in lowered and "<iframe" not in lowered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_the_report_loads_nothing_from_the_network(case):
    html, _ = build_report(case)
    lowered = html.lower()
    for needle in ('src="http', "src='http", "<link", "<script", "url(http", "@import", "<iframe"):
        assert needle not in lowered


def test_write_report_makes_an_html_file_and_a_json_file(case):
    path = write_report(case)
    assert path.name == "report.html" and path.is_file()
    data = json.loads((path.parent / "report.json").read_text(encoding="utf-8"))
    assert data["case"]["title"] == "Seal test"
    assert data["tool"]["name"] == "forensic-hand"


def test_the_report_of_a_case_with_no_checks_says_so(tmp_path, sharp_png):
    case = Case.create(tmp_path / "c", title="Empty")
    case.add_evidence(sharp_png, role="questioned")
    html, _ = build_report(case)
    assert "not checked yet" in html.lower()
