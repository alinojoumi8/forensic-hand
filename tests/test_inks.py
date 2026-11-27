"""Colour: pens and stamps in the synthetic data, and ink separation in the copy check."""

from __future__ import annotations

import numpy as np
import pytest

from forensic_hand import clones, synth
from forensic_hand.config import DEFAULTS as C


def _sig(seed=3, pen="black"):
    rng = np.random.default_rng(seed)
    return synth.render(synth.genuine(synth.new_writer(rng), rng), dpi=300, rng=rng, pen=pen)


def _prep(img, separate=True):
    return clones.prepare(img, C["clone_radius_px"], C["clone_min_ink_fraction"], C["clone_blur_px"],
                          separate=separate)


def test_rgb_to_lab_matches_known_values():
    lab = clones.rgb_to_lab(np.array([[[255, 255, 255], [0, 0, 0], [255, 0, 0]]], dtype=np.uint8))
    assert lab[0, 0] == pytest.approx([100, 0, 0], abs=0.5)
    assert lab[0, 1] == pytest.approx([0, 0, 0], abs=0.5)
    assert lab[0, 2] == pytest.approx([53.24, 80.09, 67.20], abs=0.5)


def test_a_blue_pen_is_drawn_blue_and_a_black_pen_is_neutral():
    blue = np.asarray(_sig(pen="blue")).astype(int)
    black = np.asarray(_sig(pen="black")).astype(int)
    ink_b = blue[blue.sum(axis=2) < 300]
    ink_k = black[black.sum(axis=2) < 300]
    assert blue.ndim == 3 and (ink_b[:, 2] - ink_b[:, 0]).mean() > 40
    assert abs((ink_k[:, 2] - ink_k[:, 0]).mean()) < 10


@pytest.mark.parametrize("pen", ["black", "blue"])
def test_a_stamp_has_a_colour_that_differs_from_the_pen(pen):
    img = _sig(pen=pen)
    _stamped, _, params = synth.degrade(img, 300, "stamp", np.random.default_rng(1), pen=pen)
    assert params["color"] in synth.STAMP_COLORS and params["color"] != pen
    _same, _, same_params = synth.degrade(img, 300, "stamp-same", np.random.default_rng(1), pen=pen)
    assert same_params["color"] == pen


@pytest.mark.parametrize("pen, seed", [("black", 1), ("black", 2), ("blue", 1), ("blue", 3)])
def test_a_coloured_stamp_is_separated_and_the_copy_check_sees_the_signature(pen, seed):
    img = _sig(seed=seed + 10, pen=pen)
    stamped, _, params = synth.degrade(img, 300, "stamp", np.random.default_rng(seed), pen=pen)
    clean = _prep(img)
    with_stamp = _prep(stamped)
    assert with_stamp["ink_separation"]["inks"] == 2, params
    score = clones.compare(clean, with_stamp, C["clone_rotations_deg"], C["clone_max_aspect_diff"])["score"]
    without = _prep(stamped, separate=False)
    old = clones.compare(clean, without, C["clone_rotations_deg"], C["clone_max_aspect_diff"])["score"]
    assert score is not None and score >= 0.9, (params, score)
    assert old is None or score > old


def test_a_grey_picture_is_prepared_exactly_as_before():
    gray = _sig().convert("L")
    a, b = _prep(gray, separate=True), _prep(gray, separate=False)
    assert np.array_equal(a["ink"], b["ink"]) and a["ink_separation"]["inks"] == 1


def test_a_stamp_in_the_pen_colour_cannot_be_separated_and_says_so():
    img = _sig(pen="black")
    stamped, _, _ = synth.degrade(img, 300, "stamp-same", np.random.default_rng(2), pen="black")
    assert _prep(stamped)["ink_separation"]["inks"] == 1


def test_the_copy_check_records_which_ink_it_kept(tmp_path):
    from forensic_hand.case import Case
    from forensic_hand.work import add_crop, run_clone_check

    img = _sig(seed=12, pen="blue")
    stamped, _, _ = synth.degrade(img, 300, "stamp", np.random.default_rng(1), pen="blue")
    case = Case.create(tmp_path / "c", title="t")
    for name, picture in (("k.png", img), ("q.png", stamped)):
        picture.save(tmp_path / name, dpi=(300, 300))
        rec = case.add_evidence(tmp_path / name, role="known" if name == "k.png" else "questioned")
        add_crop(case, rec["id"], page=1, box=[0, 0, picture.width, picture.height])
    result = run_clone_check(case)
    sep = result["ink_separation"]["C2"]
    assert sep["inks"] == 2 and len(sep["kept_rgb"]) == 3 and len(sep["removed_rgb"]) == 3
    assert "C1" not in result["ink_separation"]
