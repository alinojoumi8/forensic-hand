"""Dataset manifests: hashes, license gate, consent filter, building from a CSV file."""

from __future__ import annotations

import csv
import json

import pytest
from conftest import save_image
from test_workbench import signature_image

from forensic_hand import datasets as ds
from forensic_hand.datasets import DatasetError


def _manifest(tmp_path, license_class="own", consent=None, items=None):
    folder = tmp_path / "set"
    folder.mkdir(exist_ok=True)
    save_image(folder / "a.png", signature_image(1), dpi=(300, 300))
    save_image(folder / "b.png", signature_image(2), dpi=(300, 300))
    base = [
        {"item_id": "w1-g1", "file": "a.png", "writer_id": "w1", "kind": "genuine", "stratum": "clean", "consent_id": "c1"},
        {"item_id": "w1-g2", "file": "b.png", "writer_id": "w1", "kind": "genuine", "stratum": "clean", "consent_id": "c2"},
    ]
    manifest = ds.new_manifest(title="Test set", license_class=license_class, license_name="test",
                               items=items or base, folder=folder, consent=consent)
    path = folder / "manifest.json"
    ds.save_manifest(manifest, path)
    return path


def test_a_saved_manifest_loads_and_verifies(tmp_path):
    loaded = ds.load_manifest(_manifest(tmp_path))
    assert ds.verify(loaded) == []
    assert len(loaded.items) == 2 and loaded.manifest_sha256


def test_a_changed_file_is_found(tmp_path):
    path = _manifest(tmp_path)
    (path.parent / "a.png").write_bytes(b"changed")
    problems = ds.verify(ds.load_manifest(path))
    assert problems and "w1-g1" in problems[0]


@pytest.mark.parametrize("bad_file", ["../outside.png", "C:/Windows/win.ini", "/etc/passwd", "sub/../../x.png"])
def test_a_file_path_outside_the_dataset_folder_is_refused(tmp_path, bad_file):
    path = _manifest(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["items"][0]["file"] = bad_file
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(DatasetError):
        ds.load_manifest(path)


@pytest.mark.parametrize("license_class, purpose, allowed", [
    ("own", "publish", True), ("commercial", "calibrate", True),
    ("research-only", "benchmark", True), ("research-only", "calibrate", False),
    ("research-only", "publish", False), ("research-only", "train", False),
    ("unknown", "benchmark", False),
])
def test_the_license_gate(tmp_path, license_class, purpose, allowed):
    manifest = ds.load_manifest(_manifest(tmp_path, license_class=license_class))
    if allowed:
        ds.require_use(manifest, purpose)
    else:
        with pytest.raises(DatasetError):
            ds.require_use(manifest, purpose)


def test_an_unknown_purpose_is_refused(tmp_path):
    with pytest.raises(DatasetError):
        ds.require_use(ds.load_manifest(_manifest(tmp_path)), "sell")


def test_consent_filters_items_by_scope_and_withdrawal(tmp_path):
    consent = [
        {"consent_id": "c1", "scopes": ["benchmark", "calibrate"], "withdrawn": False},
        {"consent_id": "c2", "scopes": ["benchmark"], "withdrawn": True},
    ]
    manifest = ds.load_manifest(_manifest(tmp_path, consent=consent))
    used, excluded = ds.usable_items(manifest, "benchmark")
    assert [i["item_id"] for i in used] == ["w1-g1"] and excluded == {"consent withdrawn": 1}
    used, excluded = ds.usable_items(manifest, "train")
    assert used == [] and excluded == {"consent does not cover train": 1, "consent withdrawn": 1}


def test_an_item_with_no_consent_record_is_excluded_when_consent_is_required(tmp_path):
    consent = [{"consent_id": "c1", "scopes": ["benchmark"], "withdrawn": False}]
    manifest = ds.load_manifest(_manifest(tmp_path, consent=consent))
    used, excluded = ds.usable_items(manifest, "benchmark")
    assert [i["item_id"] for i in used] == ["w1-g1"] and excluded == {"no consent record": 1}


def test_a_dataset_with_no_consent_section_uses_all_items(tmp_path):
    used, excluded = ds.usable_items(ds.load_manifest(_manifest(tmp_path)), "publish")
    assert len(used) == 2 and excluded == {}


@pytest.mark.parametrize("change", [
    lambda d: d.pop("items"), lambda d: d["license"].pop("class"),
    lambda d: d["items"][0].update(kind="opinion"), lambda d: d["items"].append(dict(d["items"][0])),
    lambda d: d["items"][0].pop("sha256"),
])
def test_a_broken_manifest_is_refused(tmp_path, change):
    path = _manifest(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(DatasetError):
        ds.load_manifest(path)


def test_build_from_csv_hashes_files_and_reads_consent(tmp_path):
    folder = tmp_path / "scans"
    folder.mkdir()
    save_image(folder / "s1.png", signature_image(1), dpi=(600, 600))
    save_image(folder / "s2.png", signature_image(2), dpi=(600, 600))
    items_csv, consent_csv = tmp_path / "items.csv", tmp_path / "consent.csv"
    with open(items_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["file", "writer_id", "kind", "stratum", "consent_id", "capture", "source_item"])
        w.writerow(["s1.png", "p01", "genuine", "clean", "k1", "scan", ""])
        w.writerow(["s2.png", "p01", "forgery-skilled", "clean", "k2", "scan", ""])
    with open(consent_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["consent_id", "scopes", "date", "withdrawn"])
        w.writerow(["k1", "benchmark;calibrate", "2026-11-20", "no"])
        w.writerow(["k2", "benchmark", "2026-11-21", "yes"])
    out = folder / "manifest.json"
    manifest = ds.build_from_csv(folder, items_csv, title="Pilot", license_class="own", license_name="Own collection",
                                 consent_csv=consent_csv, out=out)
    assert manifest["synthetic"] is False and manifest["items"][0]["dpi"] == [600, 600]
    loaded = ds.load_manifest(out)
    assert ds.verify(loaded) == []
    used, excluded = ds.usable_items(loaded, "benchmark")
    assert [i["file"] for i in used] == ["s1.png"] and excluded == {"consent withdrawn": 1}


def test_build_from_csv_refuses_a_missing_file(tmp_path):
    folder = tmp_path / "scans"
    folder.mkdir()
    items_csv = tmp_path / "items.csv"
    items_csv.write_text("file,writer_id,kind\nnope.png,p01,genuine\n", encoding="utf-8")
    with pytest.raises(DatasetError):
        ds.build_from_csv(folder, items_csv, title="T", license_class="own", license_name="x", out=folder / "m.json")


# ================================================ CodeRabbit review 7 (Stage 3)

def test_r7_a_consent_id_used_twice_is_refused(tmp_path):
    consent = [{"consent_id": "c1", "scopes": ["benchmark"], "withdrawn": True},
               {"consent_id": "c1", "scopes": ["benchmark"], "withdrawn": False}]
    with pytest.raises(DatasetError):
        _manifest(tmp_path, consent=consent)


def test_r7_csv_sample_links_let_degraded_real_scans_pair_with_their_originals(tmp_path):
    from forensic_hand.validation import _copy_pairs

    folder = tmp_path / "scans"
    folder.mkdir()
    for name, seed in (("a1.png", 1), ("a2.png", 2), ("a2-150.png", 2), ("b1.png", 3), ("b1-150.png", 3)):
        save_image(folder / name, signature_image(seed), dpi=(300, 300))
    items_csv = tmp_path / "items.csv"
    items_csv.write_text(
        "item_id,file,writer_id,kind,stratum,sample\n"
        "a1,a1.png,p1,genuine,clean,\na2,a2.png,p1,genuine,clean,\na2-150,a2-150.png,p1,genuine,dpi150,a2\n"
        "b1,b1.png,p2,genuine,clean,\nb1-150,b1-150.png,p2,genuine,dpi150,b1\n", encoding="utf-8")
    manifest = ds.build_from_csv(folder, items_csv, title="T", license_class="own", license_name="x",
                                 out=folder / "m.json")
    pairs = _copy_pairs(manifest["items"])
    assert ("a1", "a2-150") in pairs["dpi150"]["same-writer"]
    assert pairs["dpi150"]["other-writer"]


def test_r7_synth_refuses_a_folder_that_is_not_empty(tmp_path):
    from forensic_hand import synth

    (tmp_path / "images").mkdir()
    (tmp_path / "images" / "w001-g1.png").write_bytes(b"keep me")
    with pytest.raises(DatasetError):
        synth.generate_dataset(tmp_path, writers=1, genuine=2, forgeries=0, seed=1)
    assert (tmp_path / "images" / "w001-g1.png").read_bytes() == b"keep me"


def test_r7_a_mixed_report_does_not_say_synthetic_only():
    from forensic_hand.validation import dossier_html

    base = {"tool": {"name": "t", "version": "0"}, "purpose": "benchmark", "generated_claimed": "x",
            "results_sha256": "0" * 64, "limits": [],
            "environment": {"python": "3", "platform": "p", "packages": {}, "config_sha256": "0"},
            "tasks": {"copy-check": {"settings": {"clone_warning_at": 0.95, "clone_notice_at": 0.9}, "pairs": {},
                                     "strata": {}, "all": _EMPTY_ROW},
                      "blur-screen": {"method": "m", "samples": 0, "rows": []},
                      "jpeg-estimate": {"samples": 0, "rows": []}}}
    real = {"title": "Real", "synthetic": False, "license": {"class": "own", "name": "x"}, "items_used": 1,
            "items_total": 1, "items_excluded": {}, "writers": 1, "manifest_sha256": "0"}
    mixed = dossier_html({**base, "datasets": [real, {**real, "title": "Synth", "synthetic": True}]})
    only_real = dossier_html({**base, "datasets": [real]})
    assert "Synthetic data only" not in mixed and "mixes real and synthetic" in mixed
    assert "Synthetic data only" not in only_real and "mixes" not in only_real


_RATE = {"k": 0, "n": 0, "rate": None, "ci95": [None, None]}
_EMPTY_ROW = {"positives": {"n": 0, "warning": _RATE, "notice": _RATE, "not_compared": 0},
              "negatives": {t: {"n": 0, "warning": _RATE, "notice": _RATE, "max_score": None}
                            for t in ("same-writer", "skilled-forgery", "other-writer")},
              "auc": None, "eer": {"eer": None, "threshold": None}}
