"""The locked score in a case (Stage 4, phase 4).

The signatures are synthetic, and the release is built on a synthetic set marked as real in its
manifest (test only), with fake time stamp tokens whose signature check is patched here. That
proves the logic of the lock and of the checker. It is not proof on real casework.
"""

from __future__ import annotations

import json
import os
import stat
from html import escape

import numpy as np
import pytest
from PIL import Image
from test_release import CFG, EASY, T1, T2, _as_real, _stamp

from forensic_hand import calibrate as cal
from forensic_hand import prereg, release, synth, work
from forensic_hand import verify_case as vc
from forensic_hand.case import Case, CaseError
from forensic_hand.checks import run_checks
from forensic_hand.cli import main
from forensic_hand.report import build_report
from forensic_hand.server import start_server
from forensic_hand.validation import run_validation, write_dossier


@pytest.fixture(autouse=True)
def _signatures_pass(monkeypatch):
    monkeypatch.setattr(release, "_check_signature", lambda *a, **k: ("ok", "test token"))


@pytest.fixture(scope="module")
def released(tmp_path_factory):
    """A release file (fake stamps), and a demo calibration file."""
    root = tmp_path_factory.mktemp("score")
    synth.generate_dataset(root / "cal", writers=4, genuine=4, forgeries=2, seed=51, strata=("clean",),
                           writer_prefix="c")
    synth.generate_dataset(root / "test", writers=3, genuine=4, forgeries=2, seed=52, strata=("clean",),
                           writer_prefix="t")
    calibration = cal.calibrate([_as_real(root / "cal" / "manifest.json")], "skilled-forgery", config=CFG)
    cal.save_calibration(calibration, root / "cal.json")
    test_manifest = _as_real(root / "test" / "manifest.json")
    prereg.save_criteria(prereg.write_criteria(calibration, [test_manifest], EASY), root / "criteria.json")
    _stamp(root / "criteria.json", T1)
    dossier = run_validation([test_manifest], purpose="publish", config=CFG, blur_samples=1, jpeg_samples=1,
                             calibration=calibration, criteria=prereg.load_criteria(root / "criteria.json"))
    write_dossier(dossier, root / "run")
    _stamp(root / "run" / "dossier.json", T2)
    with pytest.MonkeyPatch.context() as mp:     # this fixture runs before the per-test patch
        mp.setattr(release, "_check_signature", lambda *a, **k: ("ok", "test token"))
        bundle = release.make_release(root / "cal.json", root / "criteria.json", root / "run" / "dossier.json")
    release.save_release(bundle, root / "release.json")
    return {"release": root / "release.json", "calibration": calibration, "cal_path": root / "cal.json"}


def _page(sig: Image.Image, dpi: int = 300, jpeg: int | None = None, folder=None, name="p.png"):
    """A page with one signature on it, saved as a file."""
    page = Image.new("RGB", (1400, 900), (250, 250, 247))
    page.paste(sig, (300, 300))
    path = folder / name
    if jpeg:
        page.save(path.with_suffix(".jpg"), "JPEG", quality=jpeg, dpi=(dpi, dpi))
        return path.with_suffix(".jpg")
    page.save(path, dpi=(dpi, dpi))
    return path


def _case(tmp_path, q_dpi=300, q_jpeg=None, check=True, seed=61):
    rng = np.random.default_rng([seed, 1, 0])
    w = synth.new_writer(rng)
    sigs = [synth.render(synth.genuine(w, rng), 300, rng) for _ in range(4)]
    if q_dpi != 300:
        sigs[0] = sigs[0].resize((round(sigs[0].width * q_dpi / 300), round(sigs[0].height * q_dpi / 300)))
    case = Case.create(tmp_path / "case", title="Score test")
    case.add_evidence(_page(sigs[0], q_dpi, q_jpeg, tmp_path, "q.png"), role="questioned")
    for n, sig in enumerate(sigs[1:], start=1):
        case.add_evidence(_page(sig, folder=tmp_path, name=f"k{n}.png"), role="known")
    if check:
        run_checks(case)
    for rec, sig in zip(case.state()["evidence"], sigs, strict=True):
        work.add_crop(case, rec["id"], 1, [290, 290, 310 + sig.width, 310 + sig.height])
    return case


# ---------------------------------------------------------------- the lock

def test_a_case_without_a_release_is_locked_and_the_report_says_so(tmp_path):
    case = _case(tmp_path)
    status = work.score_status(case)
    assert status["locked"] is True and "no released calibration" in status["reason"]
    html, data = build_report(case)
    assert "No score" in html and data["scores"] == []


def test_a_plain_calibration_file_is_not_a_release(tmp_path, released):
    case = _case(tmp_path)
    raw = released["cal_path"].read_bytes()
    with pytest.raises(CaseError, match="not a released calibration"):
        work.add_release(case, raw)


def test_a_release_whose_stamps_cannot_be_checked_is_refused(tmp_path, released, monkeypatch):
    case = _case(tmp_path)
    monkeypatch.setattr(release, "_check_signature", lambda *a, **k: ("unavailable", "OpenSSL was not found"))
    with pytest.raises(CaseError, match="signature"):
        work.add_release(case, released["release"].read_bytes())


# ---------------------------------------------------------------- a score

@pytest.fixture
def scored(tmp_path, released):
    case = _case(tmp_path)
    rel = work.add_release(case, released["release"].read_bytes())
    result = work.run_score(case, "C1", ["C2", "C3", "C4"], rel["release_id"])
    return case, rel, result


def test_a_release_gives_a_score_and_an_lr_in_the_ledger(scored, released):
    case, rel, result = scored
    model = released["calibration"]["model"]
    assert result["score_id"] == "S1" and result["release_id"] == rel["release_id"] == "R1"
    assert result["questioned"] == "C1" and result["known"] == ["C2", "C3", "C4"]
    assert model["lower"] <= result["log10_lr"] <= model["upper"]
    assert result["log10_lr"] == cal.apply(released["calibration"], result["score"])["log10_lr"]
    assert result["propositions"]["id"] == "skilled-forgery" and "Hp" not in result["propositions"]["hp"]
    assert result["verbal"] == cal.verbal(result["log10_lr"])
    assert set(result["features"]) == {"C1", "C2", "C3", "C4"}
    state = case.state()
    assert [s["score_id"] for s in state["scores"]] == ["S1"]
    path = case.path / rel["file"]
    assert path.is_file() and not os.stat(path).st_mode & stat.S_IWUSR


def test_the_same_release_is_stored_once(scored, released):
    case, rel, _ = scored
    again = work.add_release(case, released["release"].read_bytes())
    assert again["release_id"] == rel["release_id"] and len(case.state()["releases"]) == 1


def test_the_checker_accepts_a_scored_and_sealed_case(scored):
    from forensic_hand.seal import create_seal

    case, rel, _ = scored
    seal = create_seal(case)
    body = json.loads((case.path / seal["file"]).read_text(encoding="utf-8"))
    assert {"id": rel["release_id"], "sha256": rel["sha256"]} in body["derived"]
    result = vc.verify_case(case.path, check_tsa_signature=False)
    assert result["status"] == "ok", result["problems"]
    assert result["summary"]["scores"] == 1


def test_the_checker_recomputes_each_lr(scored):
    case, _, result = scored
    case.ledger.append("score.computed", {**result, "score_id": "S2", "log10_lr": result["log10_lr"] + 0.5})
    problems = vc.verify_case(case.path, check_tsa_signature=False)["problems"]
    assert any("S2" in p and "does not follow" in p for p in problems)


def test_the_checker_finds_a_changed_release_file(scored):
    case, rel, _ = scored
    path = case.path / rel["file"]
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    path.write_bytes(path.read_bytes().replace(b'"status": "released"', b'"status": "released" '))
    problems = vc.verify_case(case.path, check_tsa_signature=False)["problems"]
    assert any("does not match the ledger" in p for p in problems)


def test_the_report_shows_the_lr_its_propositions_and_its_limits(scored):
    case, _, result = scored
    html, data = build_report(case)
    hd = escape(result["propositions"]["hd"], quote=True)      # the report escapes every text
    assert "Likelihood ratio" in html and hd in html and result["verbal"] in html
    assert "The examiner decides" in html and data["scores"][0]["score_id"] == "S1"


def test_a_crop_file_changed_on_disk_is_refused_before_it_is_measured(tmp_path, released):
    # CodeRabbit review 13: the score must measure the crop bytes that the ledger recorded.
    case = _case(tmp_path)
    rel = work.add_release(case, released["release"].read_bytes())
    crop = case.state()["crops"][0]
    path = case.path / crop["file"]
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    path.write_bytes((case.path / case.state()["crops"][1]["file"]).read_bytes())
    with pytest.raises(CaseError, match="C1.*changed"):
        work.run_score(case, "C1", ["C2", "C3", "C4"], rel["release_id"])


def test_a_case_with_an_older_checker_cannot_take_a_release(tmp_path, released):
    # CodeRabbit review 13: a checker from before Stage 4 cannot check scores, so the case may not get one.
    case = _case(tmp_path)
    checker = case.path / "verify_case.py"
    checker.write_text(checker.read_text(encoding="utf-8").replace("CHECKS_SCORES = True", ""), encoding="utf-8")
    with pytest.raises(CaseError, match="older checker"):
        work.add_release(case, released["release"].read_bytes())


def test_the_checker_ties_the_calibration_to_the_stamped_files_in_the_release(scored):
    # CodeRabbit review 13: a release whose outer calibration was replaced must not pass the checker,
    # even when the replacement has a matching hash and the ledger was rebuilt around it.
    import base64
    import hashlib

    from forensic_hand.calibrate import _hash
    from forensic_hand.store import store_bytes

    case, rel, result = scored
    bundle = json.loads((case.path / rel["file"]).read_text(encoding="utf-8"))
    forged = {**bundle["calibration"], "model": {**bundle["calibration"]["model"], "b": 3.0, "upper": 3.0}}
    forged["results_sha256"] = _hash(forged)
    bundle["calibration"] = forged
    raw = json.dumps(bundle).encode("utf-8")
    stored = store_bytes(raw, case.path / "models", ".json")
    case.ledger.append("release.added", {**rel, "release_id": "R2", "file": stored["file"], "sha256": stored["sha256"],
                                         "size": stored["size"], "calibration_sha256": forged["results_sha256"]})
    model = {k: forged["model"][k] for k in ("a", "b", "lower", "upper")}
    lr = min(model["upper"], max(model["lower"], model["a"] * result["score"] + model["b"]))
    case.ledger.append("score.computed", {**result, "score_id": "S2", "release_id": "R2",
                                          "release_sha256": stored["sha256"], "calibration_sha256": forged["results_sha256"],
                                          "model": model, "log10_lr": round(lr, 6)})
    assert base64.b64decode(bundle["files"]["calibration.json"]) != json.dumps(forged).encode()
    assert hashlib.sha256(raw).hexdigest() == stored["sha256"]
    problems = vc.verify_case(case.path, check_tsa_signature=False)["problems"]
    assert any("R2" in p and "calibration" in p for p in problems)


# ---------------------------------------------------------------- refusals

@pytest.fixture
def ready(tmp_path, released):
    def make(**kw):
        case = _case(tmp_path, **kw)
        return case, work.add_release(case, released["release"].read_bytes())["release_id"]
    return make


def test_exactly_the_calibrated_number_of_known_crops_is_needed(ready):
    case, rid = ready()
    with pytest.raises(CaseError, match="exactly 3 known"):
        work.run_score(case, "C1", ["C2", "C3"], rid)


def test_a_known_crop_must_come_from_a_known_item(ready):
    case, rid = ready()
    with pytest.raises(CaseError, match="known item"):
        work.run_score(case, "C2", ["C1", "C3", "C4"], rid)


def test_a_resolution_outside_the_tested_range_is_refused(ready):
    case, rid = ready(q_dpi=200)
    with pytest.raises(CaseError, match="resolution"):
        work.run_score(case, "C1", ["C2", "C3", "C4"], rid)


def test_a_case_that_was_not_checked_is_refused(ready):
    case, rid = ready(check=False)
    with pytest.raises(CaseError, match="fhand check"):
        work.run_score(case, "C1", ["C2", "C3", "C4"], rid)


def test_a_quality_warning_outside_the_tested_conditions_is_refused(ready):
    case, rid = ready(q_jpeg=25)
    with pytest.raises(CaseError, match="jpeg"):
        work.run_score(case, "C1", ["C2", "C3", "C4"], rid)


def test_the_verbal_scale():
    assert cal.verbal(0.0) == "no support for either proposition"
    assert cal.verbal(1.5) == "moderate support for Hp"
    assert cal.verbal(-2.5) == "moderately strong support for Hd"
    assert cal.verbal(6.5) == "extremely strong support for Hp"
    assert cal.lr_text(2.0) == "100" and cal.lr_text(-1.0) == "1/10" and cal.lr_text(0.3) == "2.0"


# ---------------------------------------------------------------- command and workbench

def test_the_score_command(tmp_path, released, capsys):
    case = _case(tmp_path)
    assert main(["score", str(case.path), "--release", str(released["release"]), "--questioned", "C1",
                 "--known", "C2", "C3", "C4"]) == 0
    out = capsys.readouterr().out
    assert "S1" in out and "LR" in out and "The examiner decides" in out
    assert main(["score", str(case.path), "--release", str(released["cal_path"]), "--questioned", "C1",
                 "--known", "C2", "C3", "C4"]) == 2
    assert "not a released calibration" in capsys.readouterr().err


def test_the_workbench_shows_the_lock_and_computes_a_score(tmp_path, released):
    from test_server import jcall

    case = _case(tmp_path)
    server, _thread = start_server(case.path, port=0)
    try:
        status, state = jcall(server, "GET", "/api/state")
        assert status == 200 and state["score"]["locked"] is True and state["scores"] == []
        status, body = jcall(server, "POST", "/api/score", {"questioned": "C1", "known": ["C2", "C3", "C4"]})
        assert status == 400 and "no released calibration" in body["error"]
        work.add_release(case, released["release"].read_bytes())
        status, state = jcall(server, "GET", "/api/state")
        assert state["score"]["locked"] is False and state["score"]["known_count"] == 3
        status, body = jcall(server, "POST", "/api/score", {"questioned": "C1", "known": ["C2", "C3", "C4"]})
        assert status == 200 and body["score_id"] == "S1"
    finally:
        server.shutdown()
        server.server_close()
