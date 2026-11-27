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
from forensic_hand.datasets import PRESETS, DatasetError, build_from_names, load_manifest, verify
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


def test_a_transparent_value_in_a_16_bit_picture_becomes_paper():
    # CodeRabbit review 15: the transparency key of a 16-bit picture was lost.
    values = np.full((8, 8), 30000, np.uint16)
    values[:, :4] = 0
    img = Image.fromarray(values)
    img.info["transparency"] = 0
    out = np.asarray(on_white(img).convert("L"))
    assert out[:, :4].min() == 255 and out[:, 4:].max() < 200


def test_two_paths_that_clean_to_the_same_id_get_valid_ids(tmp_path):
    # CodeRabbit review 15: the "~2" suffix was not a valid item id, so the import failed.
    _png(tmp_path / "a+b" / "original_1_1.png")
    _png(tmp_path / "a-b" / "original_1_1.png")
    dry = build_from_names(tmp_path, preset="cedar", title="t", license_class="research-only", license_name="x",
                           dry_run=True)
    manifest = build_from_names(tmp_path, preset="cedar", title="t", license_class="research-only", license_name="x")
    for items in (dry["items"], manifest["items"]):
        ids = [i["item_id"] for i in items]
        assert len(set(ids)) == 2 and all("~" not in i for i in ids)


def test_the_blur_and_jpeg_tasks_see_the_ink_of_16_bit_scans(tmp_path):
    # CodeRabbit review 15: those tasks turned 16-bit scans white before they measured them.
    for w in (1, 2):
        for n in (1, 2):
            gray = np.asarray(Image.open(_png(tmp_path / "tmp.png", seed=10 * w + n)).convert("L"), dtype=np.uint16)
            Image.fromarray(gray * 257).save(tmp_path / f"original_{w}_{n}.png")
    (tmp_path / "tmp.png").unlink()
    build_from_names(tmp_path, preset="cedar", title="16-bit", license_class="research-only", license_name="x",
                     out=tmp_path / "manifest.json")
    tasks = run_validation([tmp_path / "manifest.json"], purpose="benchmark", tasks=["blur-screen", "jpeg-estimate"],
                           blur_samples=2, jpeg_samples=2)["tasks"]
    clean = tasks["blur-screen"]["rows"][0]
    assert clean["sigma_px"] == 0 and clean["mean_sharpness"] is not None and clean["warning"]["rate"] == 0
    assert all(row["mean_abs_error"] is not None for row in tasks["jpeg-estimate"]["rows"])


# ---------------------------------------------------------------- where the manifest is saved

def test_a_manifest_saved_above_the_picture_folder_finds_its_files(tmp_path):
    # Found on the SOHI import: with --out above the folder, every file was "missing".
    root = _cedar(tmp_path / "set" / "raw", writers=1, genuine=2, forged=1)
    out = tmp_path / "set" / "manifest.json"
    manifest = build_from_names(root, preset="cedar", title="t", license_class="research-only", license_name="x",
                                out=out)
    assert all(i["file"].startswith("raw/full_") for i in manifest["items"])
    assert verify(load_manifest(out)) == []
    assert manifest["import"]["folder"] == "raw"


def test_a_manifest_saved_in_the_picture_folder_keeps_short_paths(tmp_path):
    root = _cedar(tmp_path, writers=1, genuine=1, forged=1)
    manifest = build_from_names(root, preset="cedar", title="t", license_class="research-only", license_name="x",
                                out=root / "manifest.json")
    assert {i["file"] for i in manifest["items"]} == {"full_org/original_1_1.png", "full_forg/forgeries_1_1.png"}
    assert manifest["import"]["folder"] == "."
    assert verify(load_manifest(root / "manifest.json")) == []


@pytest.mark.parametrize("where", ["beside", "below"])
def test_a_manifest_that_cannot_see_the_pictures_is_refused(tmp_path, where):
    root = _cedar(tmp_path / "set", writers=1, genuine=1, forged=1)
    out = tmp_path / "other" / "m.json" if where == "beside" else root / "full_org" / "m.json"
    out.parent.mkdir(exist_ok=True)
    with pytest.raises(DatasetError, match="above"):
        build_from_names(root, preset="cedar", title="t", license_class="research-only", license_name="x", out=out)
    assert not out.exists()


def test_the_import_command_writes_a_manifest_above_the_folder(tmp_path, capsys):
    root = _cedar(tmp_path / "set" / "raw", writers=2, genuine=1, forged=1)
    base = ["dataset", "import", str(root), "--preset", "cedar", "--title", "t",
            "--license-class", "research-only", "--license-name", "x"]
    assert main([*base, "--out", str(tmp_path / "set" / "m.json")]) == 0
    assert main(["dataset", "verify", str(tmp_path / "set" / "m.json")]) == 0
    capsys.readouterr()
    assert main([*base, "--out", str(tmp_path / "elsewhere.json")]) == 2
    assert "above" in capsys.readouterr().err and not (tmp_path / "elsewhere.json").exists()


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
