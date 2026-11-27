"""Pass marks and the release gate (Stage 4, phase 3).

The data here is synthetic. To test the gate, some tests mark a synthetic set as real in its
manifest: that proves the logic of the gate, never real error rates. The time stamps are fake
tokens built by an independent library; their signature check is patched in this module only.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime

import pytest
from conftest import fake_tsr

from forensic_hand import calibrate as cal
from forensic_hand import prereg, release, synth, tsa
from forensic_hand.cli import main
from forensic_hand.config import DEFAULTS
from forensic_hand.datasets import build_from_csv
from forensic_hand.validation import run_validation, write_dossier

CFG = {**DEFAULTS, "score_min_known": 3}
EASY = {"cllr_max": 5.0, "cllr_upper95_max": 10.0, "misleading_hp_max": 1.0, "misleading_hp_upper95_max": 1.0,
        "misleading_hd_max": 1.0, "misleading_hd_upper95_max": 1.0, "min_writers": 2,
        "min_hd_pairs_per_writer": 1, "min_forgers": 2}
T1 = datetime(2027, 1, 10, 9, 0, 0, tzinfo=UTC)
T2 = datetime(2027, 2, 20, 9, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _signatures_pass(monkeypatch):
    monkeypatch.setattr(release, "_check_signature", lambda *a, **k: ("ok", "test token"))
    monkeypatch.setattr(prereg, "_check_signature", lambda *a, **k: ("ok", "test token"))


def _as_real(manifest_path, forger_ids: bool = True):
    """Mark a synthetic set as real (test only), and give the forgeries two forgers."""
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["synthetic"] = False
    if forger_ids:
        for n, item in enumerate(i for i in data["items"] if i["kind"] == "forgery-skilled"):
            item["forger_id"] = f"f{n % 2 + 1}"
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    return manifest_path


def _stamp(path, when):
    tsr = path.with_name(path.name + ".tsr")
    tsr.write_bytes(fake_tsr(hashlib.sha256(path.read_bytes()).digest(), None, gen_time=when))
    return tsr


@pytest.fixture(scope="module")
def sets(tmp_path_factory):
    root = tmp_path_factory.mktemp("release")
    synth.generate_dataset(root / "cal", writers=4, genuine=4, forgeries=2, seed=41, strata=("clean",),
                           writer_prefix="c")
    synth.generate_dataset(root / "test", writers=3, genuine=4, forgeries=2, seed=42, strata=("clean",),
                           writer_prefix="t")
    synth.generate_dataset(root / "demo", writers=4, genuine=4, forgeries=2, seed=43, strata=("clean",))
    cal_manifest = _as_real(root / "cal" / "manifest.json")
    test_manifest = _as_real(root / "test" / "manifest.json")
    real = cal.calibrate([cal_manifest], "skilled-forgery", config=CFG)
    demo = cal.calibrate([root / "demo" / "manifest.json"], "skilled-forgery", config=CFG)
    cal.save_calibration(real, root / "cal.json")
    cal.save_calibration(demo, root / "demo.json")
    return {"root": root, "cal_manifest": cal_manifest, "test_manifest": test_manifest, "real": real,
            "cal_path": root / "cal.json", "demo_path": root / "demo.json"}


def _criteria(sets, folder, marks=EASY, manifests=None, calibration=None):
    body = prereg.write_criteria(calibration or sets["real"], manifests or [sets["test_manifest"]], marks)
    path = folder / "criteria.json"
    prereg.save_criteria(body, path)
    return path


def _dossier(sets, folder, criteria_path, manifests=None, purpose="publish"):
    dossier = run_validation(manifests or [sets["test_manifest"]], purpose=purpose, config=CFG, blur_samples=1,
                             jpeg_samples=1, calibration=sets["real"], criteria=prereg.load_criteria(criteria_path))
    write_dossier(dossier, folder / "dossier")
    return folder / "dossier" / "dossier.json"


@pytest.fixture(scope="module")
def good(sets, tmp_path_factory):
    folder = tmp_path_factory.mktemp("good")
    criteria = _criteria(sets, folder)
    _stamp(criteria, T1)
    dossier = _dossier(sets, folder, criteria)
    _stamp(dossier, T2)
    return {"criteria": criteria, "dossier": dossier}


def _release(sets, criteria, dossier, calibration=None):
    return release.make_release(calibration or sets["cal_path"], criteria, dossier)


# ---------------------------------------------------------------- pass marks

def test_pass_marks_name_the_calibration_the_test_data_and_each_mark(sets, good):
    body = prereg.load_criteria(good["criteria"])
    assert body["kind"] == "forensic-hand pass marks"
    assert body["calibration_sha256"] == sets["real"]["results_sha256"]
    assert body["propositions"] == "skilled-forgery"
    assert [d["title"] for d in body["test_data"]] == ["Synthetic signatures (seed 42)"]
    assert body["marks"] == EASY


def test_the_proposed_marks_are_the_plan_values():
    marks = prereg.DEFAULT_MARKS
    assert marks["cllr_max"] == 0.5 and marks["cllr_upper95_max"] == 1.0
    assert marks["misleading_hd_max"] == 0.05 and marks["misleading_hd_upper95_max"] == 0.10
    assert marks["min_writers"] == 30 and marks["min_hd_pairs_per_writer"] == 5 and marks["min_forgers"] == 2


def test_an_unknown_mark_is_refused(sets):
    with pytest.raises(prereg.PreregError, match="unknown pass mark"):
        prereg.write_criteria(sets["real"], [sets["test_manifest"]], {**EASY, "accuracy_min": 0.9})


def test_the_dossier_records_the_pass_marks_and_how_each_one_went(good):
    dossier = json.loads(good["dossier"].read_text(encoding="utf-8"))
    marks = dossier["pass_marks"]
    assert marks["criteria_sha256"] == hashlib.sha256(good["criteria"].read_bytes()).hexdigest()
    assert marks["passed"] is True and {m["mark"] for m in marks["results"]} == set(EASY)


# ---------------------------------------------------------------- release

def test_a_release_needs_every_check_to_pass_and_holds_every_file(sets, good):
    bundle = _release(sets, good["criteria"], good["dossier"])
    assert bundle["kind"] == "forensic-hand released calibration" and bundle["status"] == "released"
    assert set(bundle["files"]) == {"calibration.json", "criteria.json", "criteria.json.tsr", "dossier.json",
                                    "dossier.json.tsr"}
    assert base64.b64decode(bundle["files"]["dossier.json"]) == good["dossier"].read_bytes()
    facts = release.check_release(bundle)
    assert facts["criteria_stamp"]["gen_time"] == "2027-01-10T09:00:00Z"
    assert facts["dossier_stamp"]["gen_time"] == "2027-02-20T09:00:00Z"
    assert facts["calibration"]["results_sha256"] == sets["real"]["results_sha256"]
    assert all(m["pass"] for m in facts["marks"])


def test_a_demo_calibration_is_never_released(sets, good):
    with pytest.raises(release.ReleaseError, match="synthetic data"):
        _release(sets, good["criteria"], good["dossier"], calibration=sets["demo_path"])


def test_pass_marks_stamped_after_the_test_are_refused(sets, good, tmp_path):
    criteria = tmp_path / "criteria.json"
    criteria.write_bytes(good["criteria"].read_bytes())
    _stamp(criteria, T2)
    dossier = tmp_path / "dossier.json"
    dossier.write_bytes(good["dossier"].read_bytes())
    _stamp(dossier, T1)
    with pytest.raises(release.ReleaseError, match="before the pass marks"):
        _release(sets, criteria, dossier)


def test_pass_marks_changed_after_their_stamp_are_refused(sets, good, tmp_path):
    criteria = tmp_path / "criteria.json"
    criteria.write_bytes(good["criteria"].read_bytes())
    (tmp_path / "criteria.json.tsr").write_bytes(good["criteria"].with_name("criteria.json.tsr").read_bytes())
    criteria.write_bytes(criteria.read_bytes().replace(b'"cllr_max": 5.0', b'"cllr_max": 50.0'))
    with pytest.raises(release.ReleaseError, match="changed after its time stamp"):
        _release(sets, criteria, good["dossier"])


def test_a_changed_dossier_is_refused(sets, good, tmp_path):
    data = json.loads(good["dossier"].read_text(encoding="utf-8"))
    data["tasks"]["lr"]["cllr"] = 0.01
    dossier = tmp_path / "dossier.json"
    dossier.write_text(json.dumps(data), encoding="utf-8")
    _stamp(dossier, T2)
    with pytest.raises(release.ReleaseError, match="dossier was changed"):
        _release(sets, good["criteria"], dossier)


def test_a_signature_that_cannot_be_checked_stops_the_release(sets, good, monkeypatch):
    monkeypatch.setattr(release, "_check_signature", lambda *a, **k: ("unavailable", "OpenSSL was not found"))
    with pytest.raises(release.ReleaseError, match="signature"):
        _release(sets, good["criteria"], good["dossier"])


def test_a_test_on_the_writers_used_to_calibrate_is_refused(sets, tmp_path):
    criteria = _criteria(sets, tmp_path, manifests=[sets["cal_manifest"]])
    _stamp(criteria, T1)
    dossier = _dossier(sets, tmp_path, criteria, manifests=[sets["cal_manifest"]])
    _stamp(dossier, T2)
    with pytest.raises(release.ReleaseError, match="used to calibrate"):
        _release(sets, criteria, dossier)


def test_a_failed_pass_mark_is_refused(sets, tmp_path):
    criteria = _criteria(sets, tmp_path, marks={**EASY, "cllr_max": 0.0001})
    _stamp(criteria, T1)
    dossier = _dossier(sets, tmp_path, criteria)
    _stamp(dossier, T2)
    with pytest.raises(release.ReleaseError, match="pass mark cllr_max"):
        _release(sets, criteria, dossier)


def test_a_dossier_made_for_internal_benchmarks_only_is_refused(sets, tmp_path):
    criteria = _criteria(sets, tmp_path)
    _stamp(criteria, T1)
    dossier = _dossier(sets, tmp_path, criteria, purpose="benchmark")
    _stamp(dossier, T2)
    with pytest.raises(release.ReleaseError, match="publish"):
        _release(sets, criteria, dossier)


def test_a_test_without_forger_ids_fails_the_forger_mark(sets, tmp_path):
    synth.generate_dataset(tmp_path / "noid", writers=3, genuine=4, forgeries=2, seed=44, strata=("clean",),
                           writer_prefix="n")
    manifest = _as_real(tmp_path / "noid" / "manifest.json", forger_ids=False)
    criteria = _criteria(sets, tmp_path, manifests=[manifest])
    _stamp(criteria, T1)
    dossier = _dossier(sets, tmp_path, criteria, manifests=[manifest])
    _stamp(dossier, T2)
    with pytest.raises(release.ReleaseError, match="min_forgers"):
        _release(sets, criteria, dossier)


def test_a_changed_release_file_is_refused(sets, good, tmp_path):
    bundle = _release(sets, good["criteria"], good["dossier"])
    path = tmp_path / "release.json"
    release.save_release(bundle, path)
    assert release.load_release(path)["status"] == "released"
    bundle["calibration"]["model"]["upper"] = 9.0
    path.chmod(0o644)
    path.write_text(json.dumps(bundle), encoding="utf-8")
    with pytest.raises(release.ReleaseError):
        release.load_release(path)
    with pytest.raises(release.ReleaseError, match="exists already"):
        release.save_release(bundle, path)


def test_an_incomplete_lr_test_is_refused_without_a_crash(sets, good, tmp_path):
    # CodeRabbit review 12: a missing Cllr used to stop the release with a KeyError.
    from forensic_hand.validation import _results_hash

    data = json.loads(good["dossier"].read_text(encoding="utf-8"))
    del data["tasks"]["lr"]["cllr"]
    data["results_sha256"] = _results_hash(data)
    dossier = tmp_path / "dossier.json"
    dossier.write_text(json.dumps(data), encoding="utf-8")
    _stamp(dossier, T2)
    with pytest.raises(release.ReleaseError, match="not complete"):
        _release(sets, good["criteria"], dossier)


def test_loading_a_release_returns_the_checked_facts_not_the_stored_ones(sets, good, tmp_path):
    # CodeRabbit review 12: the stored summary was returned without a check.
    bundle = _release(sets, good["criteria"], good["dossier"])
    true_cllr = bundle["facts"]["summary"]["cllr"]
    bundle["facts"]["summary"]["cllr"] = 0.0
    path = tmp_path / "release.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert release.load_release(path)["facts"]["summary"]["cllr"] == true_cllr


@pytest.mark.parametrize("value", [float("inf"), float("nan")])
def test_a_pass_mark_must_be_a_finite_number(sets, value):
    # CodeRabbit review 12: inf and nan passed, and JSON readers reject them.
    with pytest.raises(prereg.PreregError, match="finite"):
        prereg.write_criteria(sets["real"], [sets["test_manifest"]], {**EASY, "cllr_max": value})
    raw = json.dumps({"kind": "forensic-hand pass marks", "format": 1, "marks": {**EASY, "cllr_max": value}})
    with pytest.raises(prereg.PreregError, match="finite"):
        prereg.parse_criteria(raw.encode("ascii"))


def test_a_forger_without_a_valid_consent_is_counted_out(sets, tmp_path):
    # CodeRabbit review 12: a forgery is the forger's own writing, so the forger's consent must cover the use.
    from forensic_hand.datasets import Manifest, usable_items

    data = json.loads(sets["test_manifest"].read_text(encoding="utf-8"))
    data["consent"] = {"required": True, "records": [{"consent_id": "w", "scopes": ["publish"]},
                                                     {"consent_id": "f1", "scopes": ["publish"]},
                                                     {"consent_id": "f2", "scopes": ["publish"], "withdrawn": True}]}
    for item in data["items"]:
        item["consent_id"] = "w"
        if item["kind"] == "forgery-skilled":
            item["forger_consent_id"] = "f1" if item["forger_id"] == "f1" else "f2"
    used, excluded = usable_items(Manifest(data, sets["test_manifest"], "x" * 64), "publish")
    forgers = {i.get("forger_id") for i in used if i["kind"] == "forgery-skilled"}
    assert forgers == {"f1"} and excluded == {"forger consent withdrawn": 3}
    last_forgery = [i for i in data["items"] if i["kind"] == "forgery-skilled" and i["forger_id"] == "f1"][-1]
    del last_forgery["forger_consent_id"]
    _, excluded = usable_items(Manifest(data, sets["test_manifest"], "x" * 64), "publish")
    assert excluded.get("no forger consent record") == 1


def test_two_clean_items_may_not_share_a_sample_name(sets):
    # CodeRabbit review 12: a shared name made a degraded scan pair with the wrong writer.
    from forensic_hand.datasets import DatasetError, check_manifest

    data = json.loads(sets["test_manifest"].read_text(encoding="utf-8"))
    clean = [i for i in data["items"] if i["stratum"] == "clean"]
    clean[0]["sample"] = clean[1]["sample"] = "scan1"
    with pytest.raises(DatasetError, match="sample name scan1"):
        check_manifest(data)


def test_only_forgers_whose_forgeries_were_scored_count(sets, tmp_path):
    # CodeRabbit review 12: a forgery with no clear ink gives no LR, so its forger must not count.
    from PIL import Image

    synth.generate_dataset(tmp_path / "blank", writers=3, genuine=4, forgeries=2, seed=45, strata=("clean",),
                           writer_prefix="b")
    path = _as_real(tmp_path / "blank" / "manifest.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data["items"]:
        if item["kind"] == "forgery-skilled" and item["forger_id"] == "f2":
            Image.new("RGB", (300, 150), (250, 250, 247)).save(path.parent / item["file"])
            raw = (path.parent / item["file"]).read_bytes()
            item["sha256"], item["size"] = hashlib.sha256(raw).hexdigest(), len(raw)
    path.write_text(json.dumps(data), encoding="utf-8")
    lr = run_validation([path], purpose="publish", config=CFG, blur_samples=1, jpeg_samples=1,
                        calibration=sets["real"])["tasks"]["lr"]
    assert lr["forgers"] == 1


def test_forger_ids_come_from_the_collection_spreadsheet(tmp_path):
    from PIL import Image
    for name in ("a.png", "b.png"):
        Image.new("L", (40, 20), 250).save(tmp_path / name)
    (tmp_path / "items.csv").write_text("file,writer_id,kind,forger_id\na.png,p1,genuine,\nb.png,p1,forgery-skilled,"
                                        "f7\n", encoding="utf-8")
    manifest = build_from_csv(tmp_path, tmp_path / "items.csv", "Pilot", "own", "Own collection")
    assert "forger_id" not in manifest["items"][0] and manifest["items"][1]["forger_id"] == "f7"


# ---------------------------------------------------------------- commands

def test_the_prereg_stamp_validate_and_release_commands(sets, tmp_path, capsys, monkeypatch):
    times = iter([T1, T2])
    monkeypatch.setattr(tsa, "request_timestamp",
                        lambda url, digest, timeout=20: (fake_tsr(digest, 99, gen_time=next(times)), 99))
    criteria, out = tmp_path / "criteria.json", tmp_path / "v"
    marks = [f"--{k.replace('_', '-')}={v}" for k, v in EASY.items()]
    assert main(["prereg", str(sets["cal_path"]), "--test", str(sets["test_manifest"]), "--out", str(criteria),
                 *marks]) == 0
    assert main(["stamp-file", str(criteria)]) == 0
    assert main(["validate", str(sets["test_manifest"]), "--out", str(out), "--purpose", "publish",
                 "--calibration", str(sets["cal_path"]), "--criteria", str(criteria), "--min-known", "3",
                 "--blur-samples", "1", "--jpeg-samples", "1"]) == 0
    assert main(["stamp-file", str(out / "dossier.json")]) == 0
    capsys.readouterr()
    assert main(["release", "--calibration", str(sets["cal_path"]), "--criteria", str(criteria),
                 "--dossier", str(out / "dossier.json"), "--out", str(tmp_path / "release.json")]) == 0
    assert "Released" in capsys.readouterr().out
    assert main(["release", "--calibration", str(sets["demo_path"]), "--criteria", str(criteria),
                 "--dossier", str(out / "dossier.json"), "--out", str(tmp_path / "again.json")]) == 2
    assert "synthetic data" in capsys.readouterr().err
