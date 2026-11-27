"""Calibration: turn the raw writer score into a likelihood ratio (Stage 4, phase 2).

A likelihood ratio (LR) compares two propositions:
    Hp: the known writer wrote the questioned signature.
    Hd: someone else wrote it (which "someone else" is part of the propositions, see PROPOSITIONS).
LR = P(score | Hp) / P(score | Hd). An LR of 100 means: the score is 100 times more likely if Hp
is true than if Hd is true. It is not the probability that Hp is true.

Method
1. Scores of labelled pairs (validation.score_comparisons): same-writer pairs and pairs for Hd.
2. Fit: log10 LR = a x score + b, by logistic regression with each class weighted to half, so
   the number of pairs in each class does not change the LR. A small penalty (RIDGE) keeps the
   fit finite when the classes do not overlap.
3. Bounds: the LR is kept between a lower and an upper bound that the amount of data supports,
   in the manner of the ELUB method (Vergeer and others, 2016): one misleading result is added to
   each side, and the LR may only go as far as the system still does better than "always LR 1" at
   the prior odds where that LR would decide. Check this against the paper before quoting it.

The status of a calibration
- "demo": any data was synthetic. A case can never use it.
- "candidate": real data. A case cannot use it until a release (phase 3) checks it against
  pass marks that were time stamped before the test.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import numpy as np

from . import TOOL_NAME, __version__, metrics, writer
from .config import DEFAULTS
from .datasets import load_manifest, require_use, usable_items, verify
from .ledger import utc_now

FORMAT = 1
RIDGE = 1e-3
MIN_PAIRS = 5
MIN_WRITERS = 2
PROPOSITIONS = {
    "skilled-forgery": {
        "hp": "The known writer wrote the questioned signature.",
        "hd": "Another person wrote it, imitating the known writer's signature (a skilled forgery).",
    },
    "other-writer": {
        "hp": "The known writer wrote the questioned signature.",
        "hd": "Another person wrote it in their own way, with no attempt to imitate (a random other writer).",
    },
}
SCORE_SETTINGS = ("clone_min_ink_fraction", "clone_ink_separation", "clone_ink_hue_deg")


class CalibrationError(Exception):
    """The calibration cannot be made or used. The message is plain language."""


# ---------------------------------------------------------------- fit and bounds

def fit(same_scores, diff_scores, ridge: float = RIDGE) -> tuple[float, float]:
    """Natural-log LR = a x score + b. Newton steps on the class-weighted logistic loss."""
    s = np.asarray(same_scores, dtype=np.float64)
    d = np.asarray(diff_scores, dtype=np.float64)
    x = np.concatenate([s, d])
    y = np.concatenate([np.ones(s.size), np.zeros(d.size)])
    w = np.concatenate([np.full(s.size, 0.5 / s.size), np.full(d.size, 0.5 / d.size)])
    a, b = 0.0, 0.0
    for _ in range(100):
        z = a * x + b
        p = 1.0 / (1.0 + np.exp(-np.clip(z, -500, 500)))
        r = w * (p - y)
        grad = np.array([float((r * x).sum()) + ridge * a, float(r.sum())])
        h = w * p * (1 - p)
        hess = np.array([[float((h * x * x).sum()) + ridge, float((h * x).sum())],
                         [float((h * x).sum()), float(h.sum()) + 1e-12]])
        step = np.linalg.solve(hess, grad)
        a, b = a - float(step[0]), b - float(step[1])
        if float(np.abs(step).max()) < 1e-10:
            break
    if not a > 0:
        raise CalibrationError("the score does not separate the two classes in this data (a higher score must "
                               "mean more support for the known writer)")
    return a, b


def _upper(same_log10, diff_log10) -> float:
    """Largest log10 LR (0 or more) that the data supports. See the module notes."""
    s = np.asarray(same_log10, dtype=np.float64)
    d = np.asarray(diff_log10, dtype=np.float64)
    ns, nd = s.size + 1, d.size + 1             # one misleading result added to each side
    breaks = sorted({float(v) for v in np.concatenate([s, d]) if v > 0})
    lo = 0.0
    for hi in [*breaks, math.inf]:
        hit = float((s > lo).sum()) / ns
        false_alarm = (float((d > lo).sum()) + 1) / nd
        allowed = math.log10(hit / false_alarm) if hit > 0 else -math.inf
        if allowed < lo:
            return lo
        if allowed < hi:
            return allowed
        lo = hi
    return lo


def bounds(same_log10, diff_log10) -> tuple[float, float]:
    """(lower, upper) log10 LR bounds. The lower bound is the upper bound of the mirrored data."""
    upper = _upper(same_log10, diff_log10)
    lower = -_upper([-v for v in diff_log10], [-v for v in same_log10])
    return round(lower + 0.0, 6), round(upper + 0.0, 6)


# ---------------------------------------------------------------- the calibration file

def score_settings(cfg: dict) -> dict:
    return {"feature_version": writer.FEATURE_VERSION, **{k: cfg[k] for k in SCORE_SETTINGS}}


def _hash(body: dict) -> str:
    core = {k: v for k, v in body.items() if k not in ("created_claimed", "results_sha256")}
    return hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _load_sets(manifest_paths, purpose: str):
    sets, described, excluded_total = [], [], {}
    for path in manifest_paths:
        manifest = load_manifest(path)
        require_use(manifest, purpose)
        problems = verify(manifest)
        if problems:
            raise CalibrationError(f"'{manifest.data['title']}' does not match its manifest: {problems[0]}")
        items, excluded = usable_items(manifest, purpose)
        for reason, count in excluded.items():
            excluded_total[reason] = excluded_total.get(reason, 0) + count
        sets.append((manifest, items))
        described.append({"title": manifest.data["title"], "manifest_sha256": manifest.manifest_sha256,
                          "synthetic": bool(manifest.data["synthetic"]), "license": manifest.data["license"],
                          "items_used": len(items), "items_excluded": excluded})
    return sets, described, excluded_total


def labelled_scores(sets, cfg: dict, propositions: str, strata=None) -> dict:
    """Same-writer and Hd scores, each as (score, writer_id, source), inside the chosen strata."""
    from .validation import score_comparisons

    comparisons = score_comparisons(sets, cfg)
    chosen = sorted(comparisons) if strata is None else sorted(s for s in comparisons if s in set(strata))
    same = [c for s in chosen for c in comparisons[s]["positives"] if c[0] is not None]
    diff = [c for s in chosen for c in comparisons[s][propositions] if c[0] is not None]
    return {"strata": chosen, "outside": sorted(s for s in comparisons if s not in chosen),
            "same": same, "diff": diff}


def calibrate(manifest_paths, propositions: str, config: dict | None = None, strata=None) -> dict:
    """Fit a calibration on labelled data whose licence and consent allow the use "calibrate"."""
    cfg = dict(config or DEFAULTS)
    if propositions not in PROPOSITIONS:
        raise CalibrationError(f"the propositions must be one of: {', '.join(PROPOSITIONS)}")
    sets, described, excluded = _load_sets(manifest_paths, "calibrate")
    scores = labelled_scores(sets, cfg, propositions, strata)
    same, diff = scores["same"], scores["diff"]
    writers = sorted({c[1] for c in same} | {c[1] for c in diff})
    if len(same) < MIN_PAIRS or len(diff) < MIN_PAIRS or len(writers) < MIN_WRITERS:
        left = "; ".join(f"{k}: {v}" for k, v in sorted(excluded.items())) or "none"
        raise CalibrationError(
            f"too few comparisons to calibrate: {len(same)} same-writer and {len(diff)} {propositions} pairs "
            f"from {len(writers)} writer(s); at least {MIN_PAIRS} of each and {MIN_WRITERS} writers are needed "
            f"(items left out: {left}). Each writer needs {cfg['score_min_known'] + 1} or more clean genuine "
            "signatures.")
    same_x, diff_x = [c[0] for c in same], [c[0] for c in diff]
    a_ln, b_ln = fit(same_x, diff_x)
    a, b = a_ln / math.log(10), b_ln / math.log(10)
    raw_same = [a * x + b for x in same_x]
    raw_diff = [a * x + b for x in diff_x]
    lower, upper = bounds(raw_same, raw_diff)
    fitted_same = [min(upper, max(lower, v)) for v in raw_same]
    fitted_diff = [min(upper, max(lower, v)) for v in raw_diff]
    items = [i for _, its in sets for i in its]
    dpis = sorted({int(v) for i in items for v in (i.get("dpi") or [])})
    body = {
        "kind": "forensic-hand calibration", "format": FORMAT,
        "status": "demo" if any(d["synthetic"] for d in described) else "candidate",
        "tool": {"name": TOOL_NAME, "version": __version__},
        "propositions": {"id": propositions, **PROPOSITIONS[propositions]},
        "feature_version": writer.FEATURE_VERSION,
        "score_settings": score_settings(cfg),
        "model": {"formula": "log10 LR = a x score + b, kept between lower and upper",
                  "a": round(a, 6), "b": round(b, 6), "lower": lower, "upper": upper, "ridge": RIDGE},
        "conditions": {"strata": scores["strata"], "known_count": int(cfg["score_min_known"]),
                       "known_stratum": "clean", "dpi": [dpis[0], dpis[-1]] if dpis else None,
                       "captures": sorted({str(i.get("capture")) for i in items if i.get("capture")})},
        "data": {"datasets": described, "writers": writers,
                 "pairs": {"same": len(same), "different": len(diff)}},
        "fit": {"note": "measured on the calibration data itself; a validation on other writers is needed",
                "cllr": round(metrics.cllr(fitted_same, fitted_diff), 6),
                "cllr_min": round(metrics.cllr_min(same_x, diff_x), 6)},
        "created_claimed": utc_now(),
    }
    body["results_sha256"] = _hash(body)
    return body


def write_new(path, data: bytes, error) -> None:
    """Write a new file. Never replace one: two runs that pick the same name cannot overwrite each other."""
    try:
        with open(path, "xb") as handle:
            handle.write(data)
    except FileExistsError as exc:
        raise error(f"the file exists already; choose a new name: {path}") from exc


def save_calibration(body: dict, path) -> None:
    data = (json.dumps(body, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    write_new(path, data, CalibrationError)


def load_calibration(path) -> dict:
    try:
        body = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CalibrationError(f"the calibration file cannot be read: {exc}") from exc
    check(body)
    return body


def check(body) -> None:
    """The calibration must be complete and unchanged since it was made."""
    if not isinstance(body, dict) or body.get("kind") != "forensic-hand calibration" or body.get("format") != FORMAT:
        raise CalibrationError("this is not a forensic-hand calibration (format 1)")
    try:
        if _hash(body) != body["results_sha256"]:
            raise CalibrationError("the calibration file was changed after it was made (its hash does not match)")
        model = body["model"]
        float(model["a"]), float(model["b"]), float(model["lower"]), float(model["upper"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CalibrationError(f"the calibration file is not complete: {exc}") from exc


def check_settings(body: dict, cfg: dict) -> None:
    if body.get("score_settings") != score_settings(cfg):
        raise CalibrationError("the calibration was made with other score settings or another feature version; "
                               "make a new calibration with the present settings")


# Verbal equivalents after the ENFSI Guideline for Evaluative Reporting (2015): upper log10 LR of each band.
# Check them against the scale your laboratory uses before you quote one.
VERBAL = ((1, "weak support"), (2, "moderate support"), (3, "moderately strong support"), (4, "strong support"),
          (6, "very strong support"), (math.inf, "extremely strong support"))
VERBAL_SOURCE = ("after the ENFSI Guideline for Evaluative Reporting (2015): LR 1 to 10 weak, 10 to 100 moderate, "
                 "100 to 1,000 moderately strong, 1,000 to 10,000 strong, 10,000 to 1,000,000 very strong, above "
                 "1,000,000 extremely strong support")


def verbal(log10_lr: float) -> str:
    size = abs(float(log10_lr))
    if size < 1e-9:
        return "no support for either proposition"
    word = next(text for upper, text in VERBAL if size <= upper)
    return f"{word} for {'Hp' if log10_lr > 0 else 'Hd'}"


def lr_text(log10_lr: float) -> str:
    """The LR as people read it: 100, 2.0, 1/10."""
    size = abs(float(log10_lr))
    value = 10 ** size
    text = f"{value:,.0f}" if value >= 10 else f"{value:.1f}"
    return text if log10_lr >= 0 else f"1/{text}"


def apply(body: dict, score: float, config: dict | None = None) -> dict:
    """log10 LR for a raw score, kept inside the bounds of the calibration."""
    check_settings(body, config or DEFAULTS)
    model = body["model"]
    raw = model["a"] * float(score) + model["b"]
    value = min(model["upper"], max(model["lower"], raw))
    return {"log10_lr": round(value, 6), "unbounded": round(raw, 6), "bounded": value != raw}
