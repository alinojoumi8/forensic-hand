"""Import of a public signature set by its file names, and validation of chosen tasks only.

The pictures here are small synthetic stand-ins with the names that public sets use. They prove the
logic of the importer, not anything about the real sets.
"""

from __future__ import annotations

import json

import numpy as np
import pytest
from PIL import Image

from forensic_hand import calibrate as cal
from forensic_hand import synth, writer
from forensic_hand.cli import main
from forensic_hand.config import DEFAULTS
from forensic_hand.datasets import PRESETS, DatasetError, build_from_names, load_manifest
from forensic_hand.imaging import on_white
from forensic_hand.validation import dossier_html, run_validation


def _png(path, seed=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng([seed, 1, 0])
    synth.render(synth.genuine(synth.new_writer(rng), rng), 300, rng).save(path, dpi=(300, 300))
    return path


def _cedar(root, writers=2, genuine=3, forged=2):
    for w in range(1, writers + 1):
        for n in range(1, genuine + 1):
            _png(root / "full_org" / f"original_{w}_{n}.png", seed=w)
        for n in range(1, forged + 1):
            _png(root / "full_forg" / f"forgeries_{w}_{n}.png", seed=100 + w)
    return root


# ---------------------------------------------------------------- the importer

def test_a_cedar_style_folder_is_read_by_its_file_names(tmp_path):
    _cedar(tmp_path)
    (tmp_path / "readme.txt").write_text("not a picture", encoding="utf-8")
    manifest = build_from_names(tmp_path, preset="cedar", title="CEDAR copy", license_class="research-only",
                                license_name="CEDAR: non-commercial research only")
    items = manifest["items"]
    assert len(items) == 10 and manifest["synthetic"] is False
    assert manifest["license"]["class"] == "research-only" and manifest["consent"]["required"] is False
    assert {i["writer_id"] for i in items} == {"1", "2"}
    assert sum(i["kind"] == "genuine" for i in items) == 6
    assert sum(i["kind"] == "forgery-skilled" for i in items) == 4
    assert all(i["stratum"] == "clean" and i["dpi"] == [300, 300] for i in items)
    assert len({i["item_id"] for i in items}) == 10
    assert manifest["import"]["preset"] == "cedar" and manifest["import"]["skipped"] == 0


def test_writer_numbers_with_and_without_leading_zeros_are_one_writer(tmp_path):
    _png(tmp_path / "original_1_1.png")
    _png(tmp_path / "forgeries_001_1.png")
    manifest = build_from_names(tmp_path, preset="cedar", title="t", license_class="research-only",
                                license_name="x")
    assert {i["writer_id"] for i in manifest["items"]} == {"1"}


def test_a_bhsig_style_folder_keeps_the_two_scripts_apart(tmp_path):
    _png(tmp_path / "Bengali" / "001" / "B-S-1-G-01.tif".replace(".tif", ".png"))
    for name in ("Bengali/001/B-S-1-G-01.tif", "Bengali/001/B-S-1-F-01.tif", "Hindi/001/H-S-1-G-01.tif"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        Image.open(tmp_path / "Bengali" / "001" / "B-S-1-G-01.png").save(tmp_path / name)
    (tmp_path / "Bengali" / "001" / "B-S-1-G-01.png").unlink()
    items = build_from_names(tmp_path, preset="bhsig260", title="t", license_class="research-only",
                             license_name="x")["items"]
    assert {(i["writer_id"], i["kind"]) for i in items} == {("B-1", "genuine"), ("B-1", "forgery-skilled"),
                                                           ("H-1", "genuine")}


def test_any_naming_works_with_a_pattern_and_its_kind_words(tmp_path):
    _png(tmp_path / "w7_real_1.png")
    _png(tmp_path / "w7_fake_by_f2_1.png")
    _png(tmp_path / "w7_disguise_1.png")
    manifest = build_from_names(tmp_path, pattern=r"w(?P<writer>\d+)_(?P<kind>real|fake|disguise)(?:_by_(?P<forger>\w+?))?_\d+\.png",
                                genuine=["real"], forgery=["fake"], title="t", license_class="own", license_name="x")
    items = {i["kind"]: i for i in manifest["items"]}
    assert set(items) == {"genuine", "forgery-skilled"} and items["forgery-skilled"]["forger_id"] == "f2"
    assert manifest["import"]["skipped"] == 1 and manifest["import"]["skipped_examples"] == ["w7_disguise_1.png"]


def test_a_pattern_without_writer_and_kind_groups_is_refused(tmp_path):
    _png(tmp_path / "a.png")
    with pytest.raises(DatasetError, match="writer"):
        build_from_names(tmp_path, pattern=r"(?P<kind>a)\.png", genuine=["a"], forgery=[], title="t",
                         license_class="own", license_name="x")


def test_a_folder_where_nothing_matches_is_refused(tmp_path):
    _png(tmp_path / "scan.png")
    with pytest.raises(DatasetError, match="no picture"):
        build_from_names(tmp_path, preset="cedar", title="t", license_class="research-only", license_name="x")


def test_the_presets_name_their_kind_words():
    assert PRESETS["cedar"]["genuine"] == ["original"] and PRESETS["cedar"]["forgery"] == ["forgeries"]
    assert PRESETS["bhsig260"]["genuine"] == ["G"] and PRESETS["bhsig260"]["forgery"] == ["F"]


def test_sixteen_bit_and_one_bit_scans_keep_their_ink():
    img = synth.render(synth.genuine(synth.new_writer(np.random.default_rng(5)), np.random.default_rng(6)), 300)
    gray = np.asarray(img.convert("L"), dtype=np.uint16)
    sixteen = Image.fromarray((gray * 257).astype(np.uint16))         # Pillow opens this as a 16-bit grey picture
    assert sixteen.mode.startswith("I")
    one_bit = img.convert("L").point(lambda v: 255 if v > 160 else 0).convert("1")
    assert np.asarray(on_white(sixteen).convert("L")).min() < 100     # the ink did not turn white
    for picture in (sixteen, one_bit):
        assert writer.features(picture, DEFAULTS) is not None


# ---------------------------------------------------------------- research-only data in use

@pytest.fixture(scope="module")
def cedar_set(tmp_path_factory):
    root = _cedar(tmp_path_factory.mktemp("cedar"), writers=2, genuine=6, forged=2)
    manifest = build_from_names(root, preset="cedar", title="CEDAR-like", license_class="research-only",
                                license_name="research only", out=root / "manifest.json")
    assert load_manifest(root / "manifest.json").data == manifest
    return root / "manifest.json"


def test_validate_can_run_the_writer_score_alone(cedar_set):
    dossier = run_validation([cedar_set], purpose="benchmark", tasks=["writer-score"])
    assert set(dossier["tasks"]) == {"writer-score"} and dossier["tasks_run"] == ["writer-score"]
    assert dossier["tasks"]["writer-score"]["strata"]["clean"]["positives"]["n"] == 12
    html = dossier_html(dossier)
    assert "Writer score" in html and "Copy check" not in html


def test_an_unknown_task_is_refused(cedar_set):
    with pytest.raises(DatasetError, match="task"):
        run_validation([cedar_set], purpose="benchmark", tasks=["handwriting-ai"])


def test_research_only_data_can_benchmark_but_never_calibrate(cedar_set):
    with pytest.raises(DatasetError, match="calibrate"):
        cal.calibrate([cedar_set], "skilled-forgery")


def test_the_import_and_validate_commands(tmp_path, capsys):
    root = _cedar(tmp_path / "set", writers=2, genuine=6, forged=1)
    args = ["dataset", "import", str(root), "--preset", "cedar", "--title", "CEDAR-like",
            "--license-class", "research-only", "--license-name", "research only"]
    assert main([*args, "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "14 picture(s) match" in out and "2 writer(s)" in out and not (root / "manifest.json").exists()
    assert main(args) == 0 and (root / "manifest.json").is_file()
    assert main(args) == 2                                            # never overwrites a manifest
    capsys.readouterr()
    assert main(["validate", str(root / "manifest.json"), "--out", str(tmp_path / "v"), "--tasks", "writer-score"]) == 0
    out = capsys.readouterr().out
    assert "Writer score (raw" in out and "Copy check" not in out
    assert json.loads((tmp_path / "v" / "dossier.json").read_text(encoding="utf-8"))["tasks_run"] == ["writer-score"]
