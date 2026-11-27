"""Writer score (Stage 4, phase 1): features of a signature and a raw score against known signatures.

The signatures here are synthetic. They prove the logic, not error rates on real casework.
"""

from __future__ import annotations

import math

import numpy as np
import pytest
from PIL import Image

from forensic_hand import synth, writer
from forensic_hand.cli import main
from forensic_hand.config import DEFAULTS
from forensic_hand.validation import dossier_html, run_validation


def _writer(seed: int, genuine: int = 6, forged: int = 2, pen: str = "black"):
    rng = np.random.default_rng([seed, 1, 0])
    w = synth.new_writer(rng)
    g = [synth.render(synth.genuine(w, rng), 300, rng, pen=pen) for _ in range(genuine)]
    f = [synth.render(synth.skilled_forgery(w, rng), 300, rng, pen=pen) for _ in range(forged)]
    return w, g, f


def _features(img):
    out = writer.features(img, DEFAULTS)
    assert out is not None
    return out


# ---------------------------------------------------------------- features

def test_features_have_every_group_and_are_repeatable():
    _, genuine, _ = _writer(11, genuine=1, forged=0)
    first, second = _features(genuine[0]), _features(genuine[0].copy())
    assert first == second
    assert first["version"] == writer.FEATURE_VERSION
    assert set(first["groups"]) == set(writer.GROUPS)
    for name, (kind, _) in writer.GROUPS.items():
        value = first["groups"][name]
        if kind == "histogram":
            assert isinstance(value, list) and sum(value) == pytest.approx(1.0, abs=1e-6)
            assert all(v >= 0 for v in value)
        else:
            assert isinstance(value, float) and math.isfinite(value)


def test_a_blank_crop_has_no_features():
    assert writer.features(Image.new("L", (400, 200), 250), DEFAULTS) is None


def test_features_do_not_depend_on_the_scan_resolution():
    w, _, _ = _writer(12, genuine=0, forged=0)
    sample = synth.genuine(w, np.random.default_rng(3))
    low = _features(synth.render(sample, 300))
    high = _features(synth.render(sample, 600))
    for name, (kind, _) in writer.GROUPS.items():
        a, b = low["groups"][name], high["groups"][name]
        if kind == "histogram":
            assert writer.distance(kind, a, b) < 0.12, name
    assert abs(low["groups"]["slant"] - high["groups"]["slant"]) < 3.0
    assert abs(low["groups"]["stroke_width"] - high["groups"]["stroke_width"]) < 0.25


def test_a_stamp_of_another_colour_is_removed_before_the_features():
    w, _, _ = _writer(13, genuine=0, forged=0)
    img = synth.render(synth.genuine(w, np.random.default_rng(4)), 300, pen="blue")
    stamped, _, _ = synth.degrade(img, 300, "stamp", np.random.default_rng(5), pen="blue")
    clean, dirty = _features(img), _features(stamped)
    assert dirty["ink_separation"]["inks"] == 2
    assert writer.distance("histogram", clean["groups"]["layout"], dirty["groups"]["layout"]) < 0.15


# ---------------------------------------------------------------- score

def _flat(value: float) -> dict:
    """A feature record where every group has the same value, except where a test changes it."""
    groups = {name: ([1.0] + [0.0] * 3 if kind == "histogram" else 0.0)
              for name, (kind, _) in writer.GROUPS.items()}
    groups["slant"] = value
    return {"version": writer.FEATURE_VERSION, "groups": groups}


def test_the_score_is_minus_the_mean_log_ratio_worked_by_hand():
    knowns = [_flat(v) for v in (0.0, 1.0, 2.0, 3.0, 4.0)]
    result = writer.compare(_flat(2.0), knowns, min_known=5)
    # Slant: mean distance to the knowns 1.2; mean distance between the knowns 2.0 (20 / 10 pairs).
    floor = writer.FLOORS["slant"]
    ratio = (1.2 + floor) / (2.0 + floor)
    assert result["groups"]["slant"]["distance"] == pytest.approx(1.2)
    assert result["groups"]["slant"]["spread"] == pytest.approx(2.0)
    # Every other group is equal everywhere: its ratio is 1 and its log is 0.
    assert result["score"] == pytest.approx(-math.log(ratio) / len(writer.GROUPS), abs=1e-6)
    assert result["known_count"] == 5


def test_one_group_cannot_decide_the_score_alone():
    knowns = [_flat(v) for v in (0.0, 0.1, 0.2, 0.3, 0.4)]
    far = writer.compare(_flat(1e6), knowns, min_known=5)
    assert far["score"] == pytest.approx(-writer.LOG_RATIO_LIMIT / len(writer.GROUPS), abs=1e-6)


def test_too_few_known_signatures_are_refused():
    knowns = [_flat(v) for v in (0.0, 1.0, 2.0, 3.0)]
    with pytest.raises(writer.ScoreError, match="5"):
        writer.compare(_flat(2.0), knowns, min_known=5)


def test_a_feature_record_of_another_version_is_refused():
    knowns = [_flat(v) for v in (0.0, 1.0, 2.0, 3.0, 4.0)]
    old = {**_flat(2.0), "version": writer.FEATURE_VERSION + 1}
    with pytest.raises(writer.ScoreError, match="version"):
        writer.compare(old, knowns, min_known=5)


def test_genuine_signatures_score_higher_than_forgeries_and_other_writers():
    genuine, forged, other = [], [], []
    writers = [_writer(seed) for seed in (21, 22, 23, 24)]
    for n, (_, g, f) in enumerate(writers):
        knowns = [_features(img) for img in g[:5]]
        genuine.append(writer.compare(_features(g[5]), knowns, min_known=5)["score"])
        forged.extend(writer.compare(_features(img), knowns, min_known=5)["score"] for img in f)
        next_g = writers[(n + 1) % len(writers)][1]
        other.append(writer.compare(_features(next_g[0]), knowns, min_known=5)["score"])
    assert np.mean(genuine) > np.mean(forged)
    assert np.mean(genuine) > np.mean(other)
    assert np.mean(genuine) > -0.5     # about as close as the knowns are to each other


# ---------------------------------------------------------------- validation task

@pytest.fixture(scope="module")
def writer_set(tmp_path_factory):
    folder = tmp_path_factory.mktemp("writers")
    synth.generate_dataset(folder, writers=3, genuine=4, forgeries=1, seed=7)
    return folder / "manifest.json"


@pytest.fixture(scope="module")
def writer_dossier(writer_set):
    cfg = {**DEFAULTS, "score_min_known": 3}
    return run_validation([writer_set], purpose="benchmark", config=cfg, blur_samples=1, jpeg_samples=1)


def test_the_validation_measures_the_writer_score_per_stratum(writer_dossier):
    task = writer_dossier["tasks"]["writer-score"]
    assert task["feature_version"] == writer.FEATURE_VERSION and task["min_known"] == 3
    assert set(task["strata"]) == set(synth.STRATA)
    clean = task["strata"]["clean"]
    # 3 writers x 4 genuine; 3 x 1 forgery; 3 x 4 genuine of another writer.
    assert clean["positives"]["n"] == 12
    assert clean["negatives"]["skilled-forgery"]["n"] == 3
    assert clean["negatives"]["other-writer"]["n"] == 12
    for t in ("skilled-forgery", "other-writer"):
        assert 0.0 <= clean["negatives"][t]["auc"] <= 1.0
    assert task["all"]["positives"]["n"] == 12 * len(synth.STRATA)


def test_the_writer_score_is_skipped_with_a_reason_when_writers_have_too_few_signatures(tmp_path):
    synth.generate_dataset(tmp_path, writers=2, genuine=3, forgeries=1, seed=5)
    dossier = run_validation([tmp_path / "manifest.json"], purpose="benchmark", blur_samples=1, jpeg_samples=1)
    task = dossier["tasks"]["writer-score"]
    assert "6 or more genuine" in task["skipped"]


def test_the_dossier_explains_that_the_writer_score_is_raw(writer_dossier):
    html = dossier_html(writer_dossier)
    assert "Writer score" in html and "not a likelihood ratio" in html


def test_the_validate_command_reports_the_writer_score(tmp_path, capsys, writer_set):
    out = tmp_path / "dossier"
    assert main(["validate", str(writer_set), "--out", str(out), "--blur-samples", "1", "--jpeg-samples", "1"]) == 0
    text = capsys.readouterr().out
    assert "Writer score" in text
