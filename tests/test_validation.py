"""Error-rate math, the validation harness and the dossier."""

from __future__ import annotations

import json

import pytest

from forensic_hand import datasets as ds
from forensic_hand import metrics, synth
from forensic_hand.cli import main
from forensic_hand.datasets import DatasetError
from forensic_hand.validation import run_validation, write_dossier

# ---------------------------------------------------------------- metrics

@pytest.mark.parametrize("k, n, low, high", [(0, 10, 0.0, 0.2775), (5, 10, 0.2366, 0.7634), (10, 10, 0.7225, 1.0)])
def test_wilson_interval(k, n, low, high):
    lo, hi = metrics.wilson(k, n)
    assert lo == pytest.approx(low, abs=1e-4) and hi == pytest.approx(high, abs=1e-4)


def test_wilson_with_no_trials_is_unknown():
    assert metrics.wilson(0, 0) == (None, None)


@pytest.mark.parametrize("pos, neg, auc", [
    ([0.9, 0.8], [0.1, 0.2], 1.0), ([0.1, 0.2], [0.9, 0.8], 0.0), ([0.5, 0.5], [0.5, 0.5], 0.5),
    ([0.9, 0.4], [0.5, 0.1], 0.75),
])
def test_auc(pos, neg, auc):
    assert metrics.auc(pos, neg) == pytest.approx(auc)


def test_eer_of_perfect_and_overlapping_scores():
    assert metrics.eer([0.9, 0.8], [0.1, 0.2])["eer"] == pytest.approx(0.0)
    result = metrics.eer([0.9, 0.6, 0.4, 0.3], [0.5, 0.35, 0.2, 0.1])
    assert result["eer"] == pytest.approx(0.25)


def test_rate_at_threshold_counts_missing_scores_as_not_flagged():
    r = metrics.rate([0.96, 0.5, None, 0.99], 0.95)
    assert (r["k"], r["n"], r["rate"]) == (2, 4, 0.5)


# ---------------------------------------------------------------- harness

@pytest.fixture(scope="module")
def small_set(tmp_path_factory):
    folder = tmp_path_factory.mktemp("synth")
    synth.generate_dataset(folder, writers=2, genuine=3, forgeries=1, seed=5)
    return folder / "manifest.json"


@pytest.fixture(scope="module")
def dossier(small_set):
    return run_validation([small_set], purpose="benchmark", blur_samples=2, jpeg_samples=2)


def test_a_run_reports_each_task_and_stratum(dossier):
    copy = dossier["tasks"]["copy-check"]
    assert set(copy["strata"]) == set(synth.STRATA) and "all" in copy
    row = copy["strata"]["clean"]
    assert row["positives"]["n"] == 6 and row["negatives"]["same-writer"]["n"] == 12
    for value in (row["positives"]["warning"]["rate"], row["auc"]):
        assert 0.0 <= value <= 1.0
    assert set(dossier["tasks"]) == {"copy-check", "blur-screen", "jpeg-estimate", "writer-score"}
    assert dossier["datasets"][0]["synthetic"] is True
    assert dossier["environment"]["config_sha256"]


def test_the_results_are_the_same_on_a_second_run(small_set, dossier):
    again = run_validation([small_set], purpose="benchmark", blur_samples=2, jpeg_samples=2)
    assert again["results_sha256"] == dossier["results_sha256"]


def test_a_changed_dataset_file_stops_the_run(tmp_path):
    synth.generate_dataset(tmp_path, writers=2, genuine=2, forgeries=1, seed=2)
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    (tmp_path / manifest["items"][0]["file"]).write_bytes(b"x")
    with pytest.raises(DatasetError):
        run_validation([tmp_path / "manifest.json"], purpose="benchmark")


def test_a_research_only_dataset_cannot_be_published(tmp_path):
    synth.generate_dataset(tmp_path, writers=2, genuine=2, forgeries=1, seed=2)
    path = tmp_path / "manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["license"]["class"] = "research-only"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(DatasetError):
        run_validation([path], purpose="publish")
    with pytest.raises(DatasetError):
        run_validation([path], purpose="calibrate")


def test_the_dossier_html_says_synthetic_and_escapes_text(tmp_path, dossier):
    dossier = json.loads(json.dumps(dossier))
    dossier["datasets"][0]["title"] = "<script>alert(1)</script>"
    html_path = write_dossier(dossier, tmp_path / "out")
    html = html_path.read_text(encoding="utf-8")
    assert "Synthetic data only" in html and "<script" not in html.lower()
    saved = json.loads((tmp_path / "out" / "dossier.json").read_text(encoding="utf-8"))
    assert saved["results_sha256"] == dossier["results_sha256"]


# ---------------------------------------------------------------- commands

def test_the_commands_work_end_to_end(tmp_path, capsys):
    data = tmp_path / "set"
    assert main(["synth", str(data), "--writers", "2", "--genuine", "2", "--forgeries", "0", "--seed", "3"]) == 0
    assert main(["dataset", "verify", str(data / "manifest.json")]) == 0
    assert main(["validate", str(data / "manifest.json"), "--out", str(tmp_path / "v"), "--blur-samples", "1",
                 "--jpeg-samples", "1"]) == 0
    out = capsys.readouterr().out
    assert "dossier.html" in out and (tmp_path / "v" / "dossier.json").is_file()
    assert "Writer score: not measured" in out     # 2 genuine signatures per writer are too few
    (data / ds.load_manifest(data / "manifest.json").items[0]["file"]).write_bytes(b"x")
    assert main(["dataset", "verify", str(data / "manifest.json")]) == 1
