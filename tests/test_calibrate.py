"""Calibration of the writer score to a likelihood ratio (Stage 4, phase 2).

The data here is synthetic. It proves the logic. A synthetic calibration is always a demo.
"""

from __future__ import annotations

import json
import math

import numpy as np
import pytest

from forensic_hand import calibrate as cal
from forensic_hand import metrics, synth
from forensic_hand.cli import main
from forensic_hand.config import DEFAULTS
from forensic_hand.datasets import DatasetError
from forensic_hand.validation import dossier_html, run_validation

CFG = {**DEFAULTS, "score_min_known": 3}


# ---------------------------------------------------------------- metrics

def test_cllr_of_a_system_that_always_says_lr_1_is_1():
    assert metrics.cllr([0.0, 0.0], [0.0, 0.0, 0.0]) == pytest.approx(1.0)


def test_cllr_worked_by_hand():
    # LR 10 for the same writer, LR 1/10 for a different writer: Cllr = log2(1.1).
    assert metrics.cllr([1.0], [-1.0]) == pytest.approx(math.log2(1.1))


def test_cllr_of_strongly_correct_lrs_is_near_0_and_of_wrong_lrs_is_large():
    assert metrics.cllr([6.0] * 5, [-6.0] * 5) < 1e-5
    assert metrics.cllr([-3.0], [3.0]) > 9


def test_cllr_min_is_0_for_separated_scores_and_1_for_identical_scores():
    assert metrics.cllr_min([2.0, 3.0, 4.0], [-1.0, 0.0, 1.0]) == pytest.approx(0.0, abs=1e-9)
    assert metrics.cllr_min([0.5] * 4, [0.5] * 6) == pytest.approx(1.0)


def test_cllr_min_is_never_above_the_cllr_of_a_fitted_system():
    rng = np.random.default_rng(1)
    same, diff = rng.normal(1, 1, 200), rng.normal(-1, 1, 300)
    a, b = cal.fit(same, diff)
    to10 = 1 / math.log(10)
    cllr = metrics.cllr((a * same + b) * to10, (a * diff + b) * to10)
    assert metrics.cllr_min(same, diff) <= cllr + 1e-9


def test_misleading_evidence_rates_count_the_wrong_side_of_1():
    out = metrics.misleading([2.0, -0.5, 1.0, 0.3], [-1.0, 0.2, -2.0])
    assert (out["hp"]["k"], out["hp"]["n"]) == (1, 4)       # a genuine pair with LR below 1
    assert (out["hd"]["k"], out["hd"]["n"]) == (1, 3)       # a different-writer pair with LR above 1
    assert out["hp"]["ci95"][0] <= 0.25 <= out["hp"]["ci95"][1]


def test_the_writer_bootstrap_is_repeatable_and_resamples_whole_writers():
    items = [("w1", 1, 2.0), ("w1", 0, -1.0), ("w2", 1, 0.5), ("w2", 0, 0.5), ("w3", 1, 3.0), ("w3", 0, -3.0)]

    def stat(rows):
        return float(np.mean([v for _, _, v in rows]))

    first = metrics.bootstrap(items, stat, n=200, seed=4)
    assert first == metrics.bootstrap(items, stat, n=200, seed=4)
    # Every resample is a set of whole writers: the mean of one writer's pair is 0.5, 0.5 or 0.
    assert -0.01 <= first[0] <= first[1] <= 0.51


# ---------------------------------------------------------------- fit and bounds

def test_the_fit_finds_the_known_log_likelihood_ratio():
    # Same writer ~ N(1, 1), different writer ~ N(-1, 1): the true ln LR is 2 x score.
    q = (np.arange(1, 2000) / 2000.0)
    from statistics import NormalDist
    same = np.array([NormalDist(1, 1).inv_cdf(p) for p in q])
    diff = np.array([NormalDist(-1, 1).inv_cdf(p) for p in q])
    a, b = cal.fit(same, diff)
    assert a == pytest.approx(2.0, abs=0.1) and b == pytest.approx(0.0, abs=0.05)


def test_the_fit_does_not_care_about_the_number_of_pairs_in_each_class():
    rng = np.random.default_rng(2)
    same, diff = rng.normal(1, 1, 400), rng.normal(-1, 1, 400)
    a1, b1 = cal.fit(same, diff)
    a2, b2 = cal.fit(same[:80], diff)
    assert b2 == pytest.approx(b1, abs=0.35) and a2 == pytest.approx(a1, rel=0.3)


def test_a_score_that_does_not_separate_is_refused():
    with pytest.raises(cal.CalibrationError, match="separate"):
        cal.fit(np.array([-1.0, -2.0, -1.5]), np.array([1.0, 2.0, 1.5]))


def test_the_bounds_worked_by_hand():
    # 10 pairs each side, far apart. With one misleading result added to each side, the LR may not
    # go past (10 / 11) / (1 / 11) = 10: log10 bound 1.
    lower, upper = cal.bounds([5.0] * 10, [-5.0] * 10)
    assert upper == pytest.approx(1.0) and lower == pytest.approx(-1.0)


def test_a_system_with_no_information_gets_bounds_of_lr_1():
    assert cal.bounds([0.0] * 5, [0.0] * 5) == (0.0, 0.0)


def test_more_data_allows_larger_bounds():
    _, small = cal.bounds([5.0] * 10, [-5.0] * 10)
    _, large = cal.bounds([5.0] * 100, [-5.0] * 1000)
    assert large > small


# ---------------------------------------------------------------- the calibration file

@pytest.fixture(scope="module")
def cal_set(tmp_path_factory):
    folder = tmp_path_factory.mktemp("cal")
    synth.generate_dataset(folder, writers=4, genuine=4, forgeries=2, seed=31, strata=("clean", "blur"))
    return folder / "manifest.json"


@pytest.fixture(scope="module")
def other_set(tmp_path_factory):
    folder = tmp_path_factory.mktemp("val")
    synth.generate_dataset(folder, writers=3, genuine=4, forgeries=2, seed=32, strata=("clean",), writer_prefix="v")
    return folder / "manifest.json"


@pytest.fixture(scope="module")
def calibration(cal_set):
    return cal.calibrate([cal_set], "skilled-forgery", config=CFG)


def test_a_synthetic_calibration_is_a_demo(calibration):
    assert calibration["kind"] == "forensic-hand calibration"
    assert calibration["status"] == "demo"
    assert calibration["data"]["datasets"][0]["synthetic"] is True


def test_the_calibration_records_its_model_conditions_and_data(calibration):
    model = calibration["model"]
    assert model["a"] > 0 and model["lower"] <= 0 <= model["upper"]
    cond = calibration["conditions"]
    assert cond["strata"] == ["blur", "clean"] and cond["known_count"] == 3 and cond["dpi"] == [300, 300]
    assert calibration["data"]["writers"] == ["w001", "w002", "w003", "w004"]
    assert calibration["data"]["pairs"] == {"same": 32, "different": 16}
    assert calibration["propositions"]["id"] == "skilled-forgery"
    assert calibration["feature_version"] >= 1 and len(calibration["results_sha256"]) == 64


def test_the_same_data_gives_the_same_calibration(cal_set, calibration):
    again = cal.calibrate([cal_set], "skilled-forgery", config=CFG)
    assert again["results_sha256"] == calibration["results_sha256"]


def test_a_calibration_on_one_stratum_only_records_that_stratum(cal_set):
    only = cal.calibrate([cal_set], "skilled-forgery", config=CFG, strata=["clean"])
    assert only["conditions"]["strata"] == ["clean"] and only["data"]["pairs"]["same"] == 16


def test_applying_the_calibration_keeps_the_lr_inside_its_bounds(calibration):
    model = calibration["model"]
    high = cal.apply(calibration, 50.0)
    low = cal.apply(calibration, -50.0)
    assert high["log10_lr"] == model["upper"] and high["bounded"] is True
    assert low["log10_lr"] == model["lower"] and low["bounded"] is True
    mid = cal.apply(calibration, 0.0)
    assert mid["log10_lr"] == pytest.approx(max(model["lower"], min(model["upper"], model["b"])))


def test_a_changed_calibration_file_is_refused(tmp_path, calibration):
    path = tmp_path / "cal.json"
    cal.save_calibration(calibration, path)
    assert cal.load_calibration(path)["results_sha256"] == calibration["results_sha256"]
    data = json.loads(path.read_text(encoding="utf-8"))
    data["model"]["upper"] = 9.0
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(cal.CalibrationError, match="changed"):
        cal.load_calibration(path)


def test_saving_never_replaces_an_existing_calibration(tmp_path, calibration):
    # CodeRabbit review 11: the file is created exclusively, so a second run cannot overwrite the first.
    path = tmp_path / "cal.json"
    cal.save_calibration(calibration, path)
    first = path.read_bytes()
    with pytest.raises(cal.CalibrationError, match="exists already"):
        cal.save_calibration({**calibration, "status": "candidate"}, path)
    assert path.read_bytes() == first


def test_a_calibration_of_an_older_feature_version_is_refused(calibration):
    # CodeRabbit review 11: the measures changed in review 10, so the feature version went up to 2.
    assert calibration["score_settings"]["feature_version"] == 2
    old = {**calibration, "score_settings": {**calibration["score_settings"], "feature_version": 1}}
    with pytest.raises(cal.CalibrationError, match="feature version"):
        cal.apply(old, 0.0)


def test_the_same_seed_with_another_writer_prefix_gives_other_writers(tmp_path):
    # CodeRabbit review 11: a new prefix must not hide the same writers under new ids.
    a = synth.generate_dataset(tmp_path / "a", writers=1, genuine=1, forgeries=0, seed=9, strata=("clean",),
                               writer_prefix="a")
    b = synth.generate_dataset(tmp_path / "b", writers=1, genuine=1, forgeries=0, seed=9, strata=("clean",),
                               writer_prefix="b")
    w1 = synth.generate_dataset(tmp_path / "w1", writers=1, genuine=1, forgeries=0, seed=9, strata=("clean",))
    w2 = synth.generate_dataset(tmp_path / "w2", writers=1, genuine=1, forgeries=0, seed=9, strata=("clean",))
    assert a["items"][0]["sha256"] != b["items"][0]["sha256"]
    assert w1["items"][0]["sha256"] == w2["items"][0]["sha256"]       # the default prefix is unchanged


def test_a_calibration_of_other_settings_is_refused(calibration):
    with pytest.raises(cal.CalibrationError, match="settings"):
        cal.apply(calibration, 0.0, config={**CFG, "clone_ink_hue_deg": 30})


def test_research_only_data_cannot_calibrate(tmp_path):
    synth.generate_dataset(tmp_path, writers=2, genuine=4, forgeries=1, seed=33, strata=("clean",))
    path = tmp_path / "manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["license"]["class"] = "research-only"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(DatasetError, match="calibrate"):
        cal.calibrate([path], "skilled-forgery", config=CFG)


def test_data_without_consent_to_calibrate_is_left_out_and_reported(tmp_path):
    synth.generate_dataset(tmp_path, writers=2, genuine=4, forgeries=1, seed=34, strata=("clean",))
    path = tmp_path / "manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["consent"] = {"required": True, "records": [{"consent_id": "c1", "scopes": ["benchmark"]}]}
    for item in data["items"]:
        item["consent_id"] = "c1"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(cal.CalibrationError, match="consent does not cover calibrate"):
        cal.calibrate([path], "skilled-forgery", config=CFG)


def test_an_unknown_proposition_is_refused(cal_set):
    with pytest.raises(cal.CalibrationError, match="propositions"):
        cal.calibrate([cal_set], "disguise", config=CFG)


# ---------------------------------------------------------------- validation of a calibration

@pytest.fixture(scope="module")
def lr_dossier(other_set, calibration):
    return run_validation([other_set], purpose="benchmark", config=CFG, blur_samples=1, jpeg_samples=1,
                          calibration=calibration)


def test_the_validation_measures_the_lr_on_new_data(lr_dossier, calibration):
    task = lr_dossier["tasks"]["lr"]
    assert task["calibration_sha256"] == calibration["results_sha256"]
    assert task["status"] == "demo" and task["propositions"] == "skilled-forgery"
    assert task["pairs"] == {"same": 12, "different": 6}
    assert 0 <= task["cllr_min"] <= task["cllr"] + 1e-9
    assert task["cllr_cal"] == pytest.approx(task["cllr"] - task["cllr_min"], abs=1e-6)
    assert len(task["cllr_ci95"]) == 2 and task["cllr_ci95"][0] <= task["cllr"] <= task["cllr_ci95"][1] + 1e-9
    for side in ("hp", "hd"):
        assert 0 <= task["misleading"][side]["rate"] <= 1 and len(task["misleading"][side]["ci95_writers"]) == 2
    assert task["writers_overlap"] == []
    assert len(task["tippett"]["same"]) == 12 and task["tippett"]["same"] == sorted(task["tippett"]["same"])


def test_strata_outside_the_calibration_are_not_measured(tmp_path, calibration):
    synth.generate_dataset(tmp_path, writers=2, genuine=4, forgeries=1, seed=35, strata=("clean", "jpeg"),
                           writer_prefix="x")
    task = run_validation([tmp_path / "manifest.json"], purpose="benchmark", config=CFG, blur_samples=1,
                          jpeg_samples=1, calibration=calibration)["tasks"]["lr"]
    assert task["strata"] == ["clean"] and task["outside_conditions"] == ["jpeg"]


def test_writers_used_to_calibrate_are_reported_when_they_are_tested_again(cal_set, calibration):
    task = run_validation([cal_set], purpose="benchmark", config=CFG, blur_samples=1, jpeg_samples=1,
                          calibration=calibration)["tasks"]["lr"]
    assert task["writers_overlap"] == ["w001", "w002", "w003", "w004"]


def test_the_dossier_shows_the_lr_section_with_a_tippett_plot(lr_dossier):
    html = dossier_html(lr_dossier)
    assert "Likelihood ratio" in html and "<svg" in html and "Tippett" in html
    assert "demo calibration" in html


# ---------------------------------------------------------------- commands

def test_the_calibrate_and_validate_commands(tmp_path, capsys, cal_set, other_set):
    out = tmp_path / "cal.json"
    assert main(["calibrate", str(cal_set), "--propositions", "skilled-forgery", "--out", str(out),
                 "--min-known", "3"]) == 0
    text = capsys.readouterr().out
    assert "Status: demo" in text and out.is_file()
    assert main(["calibrate", str(cal_set), "--propositions", "skilled-forgery", "--out", str(out),
                 "--min-known", "3"]) == 2      # the file exists already
    assert main(["validate", str(other_set), "--out", str(tmp_path / "v"), "--calibration", str(out),
                 "--blur-samples", "1", "--jpeg-samples", "1"]) == 0
    text = capsys.readouterr().out
    assert "Cllr" in text
