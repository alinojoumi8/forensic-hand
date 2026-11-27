"""Synthetic signatures (Sigma-Lognormal) and their degradations. Synthetic data proves logic only."""

from __future__ import annotations

import hashlib
import json
import math

import numpy as np
import pytest

from forensic_hand import synth
from forensic_hand.synth import Stroke


def test_one_stroke_travels_its_distance_in_its_direction():
    stroke = Stroke(t0=0.0, D=10.0, mu=-1.6, sigma=0.25, theta_s=0.3, theta_e=0.3)
    comps = synth.trajectory([[stroke]], rate=2000)
    x, y = comps[0][:, 0], comps[0][:, 1]
    assert math.hypot(x[-1] - x[0], y[-1] - y[0]) == pytest.approx(10.0, rel=0.01)
    assert math.atan2(y[-1] - y[0], x[-1] - x[0]) == pytest.approx(0.3, abs=0.01)


def test_the_speed_peaks_at_the_lognormal_mode():
    stroke = Stroke(t0=0.1, D=8.0, mu=-1.5, sigma=0.3, theta_s=0.0, theta_e=0.0)
    t = np.linspace(0.1001, 1.5, 20000)
    speed = synth.lognormal_speed(t, stroke)
    assert t[int(np.argmax(speed))] == pytest.approx(0.1 + math.exp(-1.5 - 0.09), abs=0.002)


def test_erf_matches_the_standard_library():
    xs = np.linspace(-4, 4, 81)
    assert np.allclose(synth.erf(xs), [math.erf(v) for v in xs], atol=2e-7)


def test_the_same_seed_gives_the_same_picture_and_another_seed_does_not():
    def png(seed):
        rng = np.random.default_rng(seed)
        writer = synth.new_writer(rng)
        return synth.png_bytes(synth.render(synth.genuine(writer, rng), dpi=300, rng=rng), 300)
    assert png(7) == png(7) and png(7) != png(8)


def test_a_forgery_is_slower_and_shakier_than_a_genuine_signature():
    rng = np.random.default_rng(3)
    writer = synth.new_writer(rng)
    gen = [synth.execution_stats(synth.genuine(writer, rng)) for _ in range(5)]
    fake = [synth.execution_stats(synth.skilled_forgery(writer, rng)) for _ in range(5)]
    assert max(f["mean_speed"] for f in fake) < min(g["mean_speed"] for g in gen)
    # Smoothness overlaps for single samples (as in real writing); on average the forgery is shakier.
    assert np.mean([f["jerk"] for f in fake]) > np.mean([g["jerk"] for g in gen]) + 0.5


def test_a_rendered_signature_has_ink_on_paper():
    rng = np.random.default_rng(1)
    img = synth.render(synth.genuine(synth.new_writer(rng), rng), dpi=300, rng=rng)
    gray = np.asarray(img)
    assert img.mode == "RGB" and 100 < img.width < 2500 and 50 < img.height < 1200
    assert gray.min() < 90 and np.median(gray) > 230


@pytest.mark.parametrize("name", synth.STRATA)
def test_each_degradation_is_recorded_and_deterministic(name):
    rng = np.random.default_rng(5)
    img = synth.render(synth.genuine(synth.new_writer(rng), rng), dpi=300, rng=rng)
    a, dpi_a, params_a = synth.degrade(img, 300, name, np.random.default_rng(9))
    b, dpi_b, params_b = synth.degrade(img, 300, name, np.random.default_rng(9))
    assert params_a["name"] == name and params_a == params_b and dpi_a == dpi_b
    assert np.array_equal(np.asarray(a), np.asarray(b))
    if name == "dpi150":
        assert dpi_a == 150 and a.width < img.width
    if name != "clean":
        assert not np.array_equal(np.asarray(a.resize(img.size)), np.asarray(img))


def test_a_digital_copy_records_how_it_was_made():
    rng = np.random.default_rng(2)
    img = synth.render(synth.genuine(synth.new_writer(rng), rng), dpi=300, rng=rng)
    _copy, dpi, params = synth.make_copy(img, 300, np.random.default_rng(4))
    assert params["kind"] == "digital-copy" and 0.6 <= params["resize"] <= 1.25
    assert 60 <= params["jpeg_quality"] <= 90 and abs(params["rotation_deg"]) <= 2.5 and dpi == 300


def test_a_generated_dataset_is_complete_and_the_same_each_time(tmp_path):
    a = synth.generate_dataset(tmp_path / "a", writers=2, genuine=3, forgeries=1, seed=11)
    b = synth.generate_dataset(tmp_path / "b", writers=2, genuine=3, forgeries=1, seed=11)
    items = a["items"]
    assert a["synthetic"] is True and a["license"]["class"] == "own"
    kinds = {(i["kind"], i["stratum"]) for i in items}
    for stratum in synth.STRATA:
        assert ("copy", stratum) in kinds and ("genuine", stratum) in kinds and ("forgery-skilled", stratum) in kinds
    assert len([i for i in items if i["kind"] == "genuine" and i["stratum"] == "clean"]) == 6
    for item in items:
        data = (tmp_path / "a" / item["file"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item["sha256"]
    assert [i["sha256"] for i in items] == [i["sha256"] for i in b["items"]]
    saved = json.loads((tmp_path / "a" / "manifest.json").read_text(encoding="utf-8"))
    assert saved["generator"]["seed"] == 11 and saved["generator"]["version"] == synth.GENERATOR_VERSION
