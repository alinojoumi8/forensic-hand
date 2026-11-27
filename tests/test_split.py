"""Splitting a collection into a fit group and a test group of writers (Stage 4, Phase 5).

The pictures here are tiny blank stand-ins. They prove the logic of the split, not anything about real data.
"""

from __future__ import annotations

import hashlib

import pytest
from PIL import Image

from forensic_hand import calibrate as cal
from forensic_hand import datasets as ds
from forensic_hand import synth
from forensic_hand.cli import main
from forensic_hand.config import DEFAULTS
from forensic_hand.datasets import DatasetError
from forensic_hand.validation import run_validation

BOTH = ["benchmark", "calibrate", "publish"]


def _people(tmp_path, writers=20, genuine=3, forgeries=2, forgers=("f1", "f2"), scopes=None):
    """A collection: each writer has genuine signatures and skilled forgeries of them by the forgers.

    With scopes (a dict writer -> consent scopes), the collection needs consent; writers not in the dict and
    all forgers agree to everything.
    """
    folder = tmp_path / "set"
    folder.mkdir(parents=True)
    blank = Image.new("L", (24, 12), 255)
    items, people = [], set()
    for w in range(1, writers + 1):
        wid = f"w{w:02d}"
        people.add(wid)
        for g in range(genuine):
            blank.save(folder / f"{wid}-g{g}.png")
            item = {"item_id": f"{wid}-g{g}", "file": f"{wid}-g{g}.png", "writer_id": wid, "kind": "genuine"}
            if scopes is not None:
                item["consent_id"] = f"c-{wid}"
            items.append(item)
        for f in range(forgeries):
            forger = forgers[(w + f) % len(forgers)]
            people.add(forger)
            blank.save(folder / f"{wid}-f{f}.png")
            item = {"item_id": f"{wid}-f{f}", "file": f"{wid}-f{f}.png", "writer_id": wid,
                    "kind": "forgery-skilled", "forger_id": forger}
            if scopes is not None:
                item["forger_consent_id"] = f"c-{forger}"
            items.append(item)
    consent = None
    if scopes is not None:
        consent = [{"consent_id": f"c-{p}", "scopes": scopes.get(p, BOTH)} for p in sorted(people)]
    manifest = ds.new_manifest("People", "own", "own collection", items, folder, consent=consent)
    path = folder / "manifest.json"
    ds.save_manifest(manifest, path)
    return path


def _writers(manifest) -> set:
    return {i["writer_id"] for i in manifest.items}


# ---------------------------------------------------------------- the split

def test_no_writer_is_in_both_groups_and_each_item_goes_with_its_writer(tmp_path):
    path = _people(tmp_path)
    done = ds.split_manifest(path, seed=7)
    fit, test = ds.load_manifest(done["fit"]["path"]), ds.load_manifest(done["test"]["path"])
    assert _writers(fit) and _writers(test) and not _writers(fit) & _writers(test)
    assert len(_writers(fit) | _writers(test)) == 20 and len(fit.items) + len(test.items) == 20 * 5
    assert ds.verify(fit) == [] and ds.verify(test) == []
    source = ds.load_manifest(path).manifest_sha256
    for manifest, group, purpose in ((fit, "fit", "calibrate"), (test, "test", "publish")):
        split = manifest.data["split"]
        assert (split["group"], split["purpose"], split["seed"]) == (group, purpose, 7)
        assert split["source_manifest_sha256"] == source
        assert split["writers"] == sorted(_writers(manifest))


def test_the_seed_sets_the_split_and_anyone_can_recompute_it(tmp_path):
    path = _people(tmp_path)
    a, b, c = (ds.split_manifest(path, seed=s, dry_run=True) for s in (7, 7, 8))
    assert a["test"]["writers"] == b["test"]["writers"] != c["test"]["writers"]
    order = sorted((f"w{n:02d}" for n in range(1, 21)), key=lambda w: hashlib.sha256(f"7:{w}".encode()).hexdigest())
    assert a["test"]["writers"] == sorted(order[:10]) and a["fit"]["writers"] == sorted(order[10:])
    assert not (path.parent / "manifest-fit.json").exists()          # a dry run writes nothing


def test_the_test_share_sets_the_group_sizes(tmp_path):
    done = ds.split_manifest(_people(tmp_path), seed=1, test_share=0.25, dry_run=True)
    assert (len(done["test"]["writers"]), len(done["fit"]["writers"])) == (5, 15)


def test_the_fit_group_is_never_the_smaller_one_at_half(tmp_path):
    # The protocol: the calibration group should be at least as large as the test group.
    done = ds.split_manifest(_people(tmp_path, writers=23), seed=1, dry_run=True)
    assert (len(done["test"]["writers"]), len(done["fit"]["writers"])) == (11, 12)


def test_consent_decides_the_group_a_writer_may_join(tmp_path):
    scopes = {"w01": ["calibrate"], "w02": ["publish"], "w03": ["benchmark"]}
    done = ds.split_manifest(_people(tmp_path, scopes=scopes), seed=7)
    assert "w01" in done["fit"]["writers"] and "w02" in done["test"]["writers"]
    assert done["left_out"] == ["w03"] and done["forced"] == {"fit": ["w01"], "test": ["w02"]}
    test = ds.load_manifest(done["test"]["path"])
    assert "w03" not in _writers(test) | _writers(ds.load_manifest(done["fit"]["path"]))
    assert {r["consent_id"] for r in test.data["consent"]["records"]} >= {"c-w02", "c-f1", "c-f2"}


def test_a_split_before_the_forgeries_gives_the_same_groups_later(tmp_path):
    # The protocol tells collectors to split before the forgery sessions; the groups must not move afterwards.
    before = ds.split_manifest(_people(tmp_path / "a", forgeries=0), seed=11, dry_run=True)
    after = ds.split_manifest(_people(tmp_path / "b", forgeries=2), seed=11, dry_run=True)
    assert before["test"]["writers"] == after["test"]["writers"] and before["fit"]["writers"] == after["fit"]["writers"]


def test_a_person_in_both_groups_is_reported(tmp_path):
    one_forger = ds.split_manifest(_people(tmp_path / "a", forgers=("f1",)), seed=7, dry_run=True)
    assert one_forger["people_in_both_groups"] == ["f1"]
    apart = ds.split_manifest(_people(tmp_path / "b", forgeries=0), seed=7, dry_run=True)
    assert apart["people_in_both_groups"] == []


# ---------------------------------------------------------------- refusals

@pytest.mark.parametrize("share", [0, 1, -0.5, 1.5, float("nan")])
def test_a_test_share_outside_0_and_1_is_refused(tmp_path, share):
    with pytest.raises(DatasetError, match="share"):
        ds.split_manifest(_people(tmp_path), seed=7, test_share=share)


def test_a_split_never_overwrites_a_file(tmp_path):
    path = _people(tmp_path)
    ds.split_manifest(path, seed=7)
    with pytest.raises(DatasetError, match="exists"):
        ds.split_manifest(path, seed=8)


def test_the_new_manifests_must_be_beside_the_source(tmp_path):
    path = _people(tmp_path)
    with pytest.raises(DatasetError, match="folder"):
        ds.split_manifest(path, seed=7, fit_out=tmp_path / "fit.json")
    assert not (tmp_path / "fit.json").exists()


def test_a_split_needs_writers_for_both_groups(tmp_path):
    with pytest.raises(DatasetError, match="both groups"):
        ds.split_manifest(_people(tmp_path, writers=1), seed=7)


# ---------------------------------------------------------------- the command and the gate

def test_the_split_command(tmp_path, capsys):
    path = _people(tmp_path)
    args = ["dataset", "split", str(path), "--seed", "7"]
    assert main([*args, "--dry-run"]) == 0 and not (path.parent / "manifest-fit.json").exists()
    assert main(args) == 0
    out = capsys.readouterr().out
    assert "Fit group" in out and "Test group" in out and "10 writer(s)" in out
    assert (path.parent / "manifest-fit.json").is_file() and (path.parent / "manifest-test.json").is_file()
    assert main(args) == 2                                            # never overwrites
    assert "exists" in capsys.readouterr().err


def test_a_calibration_on_the_fit_group_shares_no_writer_with_the_test_group(tmp_path):
    cfg = {**DEFAULTS, "score_min_known": 3}
    synth.generate_dataset(tmp_path / "s", writers=8, genuine=4, forgeries=2, seed=5, strata=("clean",))
    done = ds.split_manifest(tmp_path / "s" / "manifest.json", seed=3)
    calibration = cal.calibrate([done["fit"]["path"]], "skilled-forgery", config=cfg)
    lr = run_validation([done["test"]["path"]], config=cfg, calibration=calibration, tasks=["writer-score"])["tasks"]["lr"]
    assert lr["writers_overlap"] == [] and lr["writers"] == len(done["test"]["writers"])
