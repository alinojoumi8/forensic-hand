"""Validation harness: run the tool's own screens on labelled data and report measured error rates.

Tasks
- copy-check: does the copy check flag digital copies, and how often does it raise a false
  alarm on genuine signatures of the same writer, on skilled forgeries and on other writers?
- blur-screen: how the blur screen responds to a known amount of blur.
- jpeg-estimate: how close the JPEG quality estimate is to the true setting.
- writer-score: how well the raw writer score (writer.py) separates genuine signatures from skilled
  forgeries and from other writers. A raw score only: not a likelihood ratio, not used in cases.

The harness calls the same functions that the workbench calls, with the same settings. The
results are deterministic: the same data and settings give the same results hash.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
from html import escape
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter

from . import TOOL_NAME, __version__, clones, metrics, writer
from .checks import environment
from .config import DEFAULTS
from .datasets import DatasetError, load_manifest, require_use, usable_items, verify
from .ledger import utc_now
from .quality import analyse_image

BLUR_SIGMAS = (0.0, 0.75, 1.5, 2.25, 3.0, 4.5)
JPEG_QUALITIES = (30, 50, 70, 90)
NEGATIVE_TYPES = ("same-writer", "skilled-forgery", "other-writer")

LIMITS = [
    "Synthetic signatures show how a method behaves. They do not show its error rates on real documents.",
    ("The copy check compares whole crops. A copy that was edited after pasting, or traced by hand, is a "
     "different problem and is not measured here."),
    ("The results hold for the data and settings listed in this file only. Other scanners, pens, papers "
     "and crop habits can give other numbers."),
    ("A stamp over the signature is removed only when its colour differs in hue from the pen (or one of them "
     "is black). A stamp in the pen's own colour, or a near hue such as violet over blue, still defeats the "
     "copy check. The hue rule (15 degrees) comes from synthetic inks; real scanners may need another value."),
    ("The writer score is a raw research score. It is not a likelihood ratio, it does not say who wrote a "
     "signature, and a case cannot use it. Its known signatures here are clean scans."),
]
SCORE_NEGATIVES = ("skilled-forgery", "other-writer")


def _r(value):
    return None if value is None else round(float(value), 4)


def _rate(scores, threshold) -> dict:
    out = metrics.rate(scores, threshold)
    return {**out, "rate": _r(out["rate"]), "ci95": [_r(v) for v in out["ci95"]]}


def _open(manifest, item) -> Image.Image:
    with Image.open(manifest.folder / item["file"]) as img:
        img.load()
        return img.copy()


# ---------------------------------------------------------------- copy check

def _copy_pairs(items: list[dict]) -> dict[str, dict[str, list[tuple[str, str]]]]:
    """Pairs per stratum: positives (original, copy) and three kinds of negatives."""
    originals = sorted((i for i in items if i["stratum"] == "clean" and i["kind"] in ("genuine", "forgery-skilled")),
                       key=lambda i: i["item_id"])
    questioned = {(i.get("sample") or i["item_id"], i["stratum"]): i["item_id"]
                  for i in items if i["kind"] in ("genuine", "forgery-skilled")}
    by_id = {i["item_id"]: i for i in items}
    writers = sorted({i["writer_id"] for i in originals})
    genuine = {w: [i["item_id"] for i in originals if i["writer_id"] == w and i["kind"] == "genuine"] for w in writers}
    forged = {w: [i["item_id"] for i in originals if i["writer_id"] == w and i["kind"] == "forgery-skilled"]
              for w in writers}
    strata = sorted({i["stratum"] for i in items})
    out = {}
    for s in strata:
        pairs = {"positives": [], **{t: [] for t in NEGATIVE_TYPES}}
        for copy in sorted((i for i in items if i["kind"] == "copy" and i["stratum"] == s), key=lambda i: i["item_id"]):
            if copy.get("source_item") in by_id:
                pairs["positives"].append((copy["source_item"], copy["item_id"]))
        for wi, w in enumerate(writers):
            for a in genuine[w]:
                for b in genuine[w]:
                    if a != b and (b, s) in questioned:
                        pairs["same-writer"].append((a, questioned[(b, s)]))
                for f in forged[w]:
                    if (f, s) in questioned:
                        pairs["skilled-forgery"].append((a, questioned[(f, s)]))
            if len(writers) > 1:
                other = genuine[writers[(wi + 1) % len(writers)]]
                for n, a in enumerate(genuine[w]):
                    if other and (other[n % len(other)], s) in questioned:
                        pairs["other-writer"].append((a, questioned[(other[n % len(other)], s)]))
        if pairs["positives"] or any(pairs[t] for t in NEGATIVE_TYPES):
            out[s] = pairs
    return out


def _copy_rows(scores: dict, cfg: dict) -> dict:
    pos = scores["positives"]
    neg_all = [x for t in NEGATIVE_TYPES for x in scores[t]]
    row = {
        "positives": {"n": len(pos), "warning": _rate(pos, cfg["clone_warning_at"]),
                      "notice": _rate(pos, cfg["clone_notice_at"]),
                      "not_compared": sum(1 for x in pos if x is None)},
        "negatives": {t: {"n": len(scores[t]), "warning": _rate(scores[t], cfg["clone_warning_at"]),
                          "notice": _rate(scores[t], cfg["clone_notice_at"]),
                          "max_score": _r(max((x for x in scores[t] if x is not None), default=None))}
                      for t in NEGATIVE_TYPES},
        "auc": _r(metrics.auc(pos, neg_all)),
    }
    e = metrics.eer(pos, neg_all)
    row["eer"] = {"eer": _r(e["eer"]), "threshold": _r(e["threshold"])}
    return row


def copy_check_task(sets, cfg: dict) -> dict:
    features: dict[str, dict | None] = {}

    def feature(manifest, item):
        key = item["sha256"]
        if key not in features:
            features[key] = clones.prepare(_open(manifest, item), cfg["clone_radius_px"],
                                           cfg["clone_min_ink_fraction"], cfg["clone_blur_px"],
                                           separate=cfg["clone_ink_separation"], hue_deg=cfg["clone_ink_hue_deg"])
        return features[key]

    per_stratum: dict[str, dict] = {}
    for manifest, items in sets:
        by_id = {i["item_id"]: i for i in items}
        for stratum, pairs in _copy_pairs(items).items():
            bucket = per_stratum.setdefault(stratum, {"positives": [], **{t: [] for t in NEGATIVE_TYPES}})
            for kind, plist in pairs.items():
                for a, b in plist:
                    fa, fb = feature(manifest, by_id[a]), feature(manifest, by_id[b])
                    score = None if fa is None or fb is None else clones.compare(
                        fa, fb, cfg["clone_rotations_deg"], cfg["clone_max_aspect_diff"])["score"]
                    bucket[kind].append(score)
    pooled = {k: [x for s in per_stratum.values() for x in s[k]] for k in ("positives", *NEGATIVE_TYPES)}
    return {
        "settings": {k: cfg[k] for k in sorted(cfg) if k.startswith("clone_")},
        "pairs": {"positives": "an original genuine signature and a digital copy of it (resized, JPEG, turned, "
                               "pasted), with the stratum's degradation on the copy",
                  "same-writer": "two different genuine signatures of one writer; the second one degraded",
                  "skilled-forgery": "a genuine signature and a skilled forgery of it; the forgery degraded",
                  "other-writer": "genuine signatures of two different writers; the second one degraded"},
        "strata": {s: _copy_rows(per_stratum[s], cfg) for s in sorted(per_stratum)},
        "all": _copy_rows(pooled, cfg),
    }


# ---------------------------------------------------------------- writer score

def _summary(values: list) -> dict:
    valid = [v for v in values if v is not None]
    return {"n": len(values), "not_scored": len(values) - len(valid),
            "median": _r(np.median(valid)) if valid else None,
            "min": _r(min(valid)) if valid else None, "max": _r(max(valid)) if valid else None}


def _score_rows(scores: dict) -> dict:
    pos = [x for x in scores["positives"] if x is not None]
    row = {"positives": _summary(scores["positives"]), "negatives": {}}
    for t in SCORE_NEGATIVES:
        neg = [x for x in scores[t] if x is not None]
        row["negatives"][t] = {**_summary(scores[t]), "auc": _r(metrics.auc(pos, neg)),
                               "eer": _r(metrics.eer(pos, neg)["eer"])}
    return row


def score_comparisons(sets, cfg: dict) -> dict[str, dict[str, list]]:
    """Raw writer scores per stratum: genuine (positives), skilled forgeries and other writers.

    Each writer with min_known + 1 or more clean genuine signatures takes part. Known set: min_known
    clean genuine signatures of the writer. A genuine signature is scored against min_known of the
    writer's other genuine signatures; forgeries and the next writer's genuine signatures are scored
    against the first min_known. The questioned item carries the stratum's degradation; the knowns are clean.
    Each comparison is (score, writer_id) so that later steps can resample by writer.
    """
    k = int(cfg["score_min_known"])
    cache: dict[str, dict | None] = {}

    def feat(manifest, item):
        if item["sha256"] not in cache:
            cache[item["sha256"]] = writer.features(_open(manifest, item), cfg)
        return cache[item["sha256"]]

    def score(q, knowns) -> float | None:
        valid = [f for f in knowns if f is not None]
        if q is None or len(valid) < k:
            return None
        return writer.compare(q, valid, k)["score"]

    out: dict[str, dict[str, list]] = {}
    for manifest, items in sets:
        clean = sorted((i for i in items if i["stratum"] == "clean"), key=lambda i: i["item_id"])
        genuine: dict[str, list[dict]] = {}
        forged: dict[str, list[dict]] = {}
        for item in clean:
            if item["kind"] == "genuine":
                genuine.setdefault(item["writer_id"], []).append(item)
            elif item["kind"] == "forgery-skilled":
                forged.setdefault(item["writer_id"], []).append(item)
        questioned = {(i.get("sample") or i["item_id"], i["stratum"]): i
                      for i in items if i["kind"] in ("genuine", "forgery-skilled")}
        strata = sorted({i["stratum"] for i in items})
        writers = sorted(w for w, g in genuine.items() if len(g) >= k + 1)
        for wi, w in enumerate(writers):
            gen = genuine[w]
            base = [feat(manifest, g) for g in gen[:k]]

            def add(kind, source, knowns, w=w):
                for s in strata:
                    q = questioned.get((source["item_id"], s))
                    if q is not None:
                        bucket = out.setdefault(s, {"positives": [], **{t: [] for t in SCORE_NEGATIVES}})
                        bucket[kind].append((score(feat(manifest, q), knowns), w))

            for g in gen:
                add("positives", g, [feat(manifest, x) for x in gen if x is not g][:k])
            for f in forged.get(w, []):
                add("skilled-forgery", f, base)
            if len(writers) > 1:
                for g in genuine[writers[(wi + 1) % len(writers)]]:
                    add("other-writer", g, base)
    return out


def writer_score_task(sets, cfg: dict) -> dict:
    k = int(cfg["score_min_known"])
    head = {"feature_version": writer.FEATURE_VERSION, "min_known": k,
            "groups": {name: text for name, (_, text) in writer.GROUPS.items()}}
    per_stratum = score_comparisons(sets, cfg)
    if not per_stratum:
        return {**head, "skipped": f"needs {k + 1} or more genuine signatures per writer (clean scans): "
                                   f"{k} as known signatures and 1 as the questioned one"}
    plain = {s: {kind: [x for x, _ in v] for kind, v in b.items()} for s, b in per_stratum.items()}
    pooled = {kind: [x for b in plain.values() for x in b[kind]] for kind in ("positives", *SCORE_NEGATIVES)}
    return {
        **head,
        "method": ("minus the mean over the measures of ln((distance to the knowns + floor) / (distance "
                   "between the knowns + floor)); 0 = as close as the knowns are to each other"),
        "pairs": {"positives": "a genuine signature against other genuine signatures of the same writer",
                  "skilled-forgery": "a skilled forgery against the genuine signatures it imitates",
                  "other-writer": "a genuine signature of another writer against the known writer"},
        "strata": {s: _score_rows(plain[s]) for s in sorted(plain)},
        "all": _score_rows(pooled),
    }


# ---------------------------------------------------------------- likelihood ratio

def lr_task(sets, cfg: dict, calibration: dict) -> dict:
    """Apply a calibration to new data and measure how good its LRs are."""
    from . import calibrate as cal

    cal.check(calibration)
    cal.check_settings(calibration, cfg)
    prop = calibration["propositions"]["id"]
    k = int(calibration["conditions"]["known_count"])
    scores = cal.labelled_scores(sets, {**cfg, "score_min_known": k}, prop, calibration["conditions"]["strata"])
    head = {"calibration_sha256": calibration["results_sha256"], "status": calibration["status"],
            "propositions": prop, "hp": calibration["propositions"]["hp"], "hd": calibration["propositions"]["hd"],
            "model": calibration["model"], "strata": scores["strata"], "outside_conditions": scores["outside"]}
    if not scores["same"] or not scores["diff"]:
        return {**head, "skipped": "no comparisons of both kinds inside the conditions of the calibration"}
    rows = ([(w, 1, cal.apply(calibration, x, cfg)["log10_lr"], x) for x, w in scores["same"]]
            + [(w, 0, cal.apply(calibration, x, cfg)["log10_lr"], x) for x, w in scores["diff"]])
    same = [v for _, y, v, _ in rows if y == 1]
    diff = [v for _, y, v, _ in rows if y == 0]

    def both(rs):
        s = [v for _, y, v, _ in rs if y == 1]
        d = [v for _, y, v, _ in rs if y == 0]
        return (s, d) if s and d else None

    def boot_cllr(rs):
        pair = both(rs)
        return None if pair is None else metrics.cllr(*pair)

    def boot_rate(side):
        def stat(rs):
            pair = both(rs)
            return None if pair is None else metrics.misleading(*pair)[side]["rate"]
        return stat

    mis = metrics.misleading(same, diff)
    misleading = {}
    for side in ("hp", "hd"):
        m = mis[side]
        misleading[side] = {"k": m["k"], "n": m["n"], "rate": _r(m["rate"]), "ci95": [_r(v) for v in m["ci95"]],
                            "ci95_writers": [_r(v) for v in metrics.bootstrap(rows, boot_rate(side))]}
    value = metrics.cllr(same, diff)
    minimum = metrics.cllr_min([x for _, y, _, x in rows if y == 1], [x for _, y, _, x in rows if y == 0])
    writers = sorted({w for w, *_ in rows})
    return {
        **head,
        "pairs": {"same": len(same), "different": len(diff)},
        "writers": len(writers),
        "writers_overlap": sorted(set(writers) & set(calibration["data"]["writers"])),
        "cllr": _r(value), "cllr_min": _r(minimum), "cllr_cal": _r(value - minimum),
        "cllr_ci95": [_r(v) for v in metrics.bootstrap(rows, boot_cllr)],
        "misleading": misleading,
        "bounded_share": _r(sum(1 for _, _, v, _ in rows if v in (calibration["model"]["lower"],
                                                                    calibration["model"]["upper"])) / len(rows)),
        "tippett": {"same": sorted(round(v, 4) for v in same), "different": sorted(round(v, 4) for v in diff)},
    }


# ---------------------------------------------------------------- quality screens

def _originals(sets, limit: int):
    picked = []
    for manifest, items in sets:
        for item in sorted(items, key=lambda i: i["item_id"]):
            if item["kind"] == "genuine" and item["stratum"] == "clean" and len(picked) < limit:
                picked.append((manifest, item))
    return picked


def blur_task(sets, cfg: dict, samples: int) -> dict:
    rows = []
    picked = _originals(sets, samples)
    for sigma in BLUR_SIGMAS:
        warn, soft, scores = [], [], []
        for manifest, item in picked:
            img = _open(manifest, item).convert("L")
            if sigma:
                img = img.filter(ImageFilter.GaussianBlur(sigma))
            dpi = (item.get("dpi") or [300, 300])
            img.info["dpi"] = tuple(dpi)
            result = analyse_image(img, cfg)
            codes = {f["code"] for f in result["findings"]}
            warn.append(1.0 if "IMG-BLUR" in codes else 0.0)
            soft.append(1.0 if codes & {"IMG-BLUR", "IMG-SOFT"} else 0.0)
            scores.append(result["metrics"].get("sharpness"))
        valid = [s for s in scores if s is not None]
        rows.append({"sigma_px": sigma, "n": len(picked), "warning": _rate(warn, 0.5),
                     "note_or_warning": _rate(soft, 0.5),
                     "mean_sharpness": _r(sum(valid) / len(valid)) if valid else None})
    return {"samples": len(picked), "rows": rows,
            "method": "Gaussian blur of the given size (pixels) added to clean genuine signatures"}


def jpeg_task(sets, cfg: dict, samples: int) -> dict:
    rows = []
    picked = _originals(sets, samples)
    for quality in JPEG_QUALITIES:
        errors, agree = [], []
        expected = ("warning" if quality < cfg["jpeg_quality_warning_below"]
                    else "notice" if quality < cfg["jpeg_quality_notice_below"] else "none")
        for manifest, item in picked:
            buf = io.BytesIO()
            _open(manifest, item).convert("L").save(buf, "JPEG", quality=quality)
            buf.seek(0)
            with Image.open(buf) as img:
                img.load()
                result = analyse_image(img, cfg)
            estimate = result["metrics"].get("jpeg_quality_estimate")
            errors.append(abs(estimate - quality) if estimate is not None else None)
            found = next((f["level"] for f in result["findings"] if f["code"] == "IMG-JPEG-QUALITY"), "none")
            agree.append(1.0 if found == expected else 0.0)
        valid = [e for e in errors if e is not None]
        rows.append({"quality": quality, "n": len(picked), "expected_level": expected,
                     "mean_abs_error": _r(sum(valid) / len(valid)) if valid else None,
                     "max_abs_error": _r(max(valid)) if valid else None,
                     "level_agrees": _rate(agree, 0.5)})
    return {"samples": len(picked), "rows": rows}


# ---------------------------------------------------------------- the run

def _results_hash(dossier: dict) -> str:
    core = {k: v for k, v in dossier.items() if k not in ("generated_claimed", "results_sha256")}
    return hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def run_validation(manifest_paths, purpose: str = "benchmark", config: dict | None = None,
                   blur_samples: int = 12, jpeg_samples: int = 12, calibration: dict | None = None) -> dict:
    cfg = dict(config or DEFAULTS)
    sets, described = [], []
    for path in manifest_paths:
        manifest = load_manifest(path)
        require_use(manifest, purpose)
        problems = verify(manifest)
        if problems:
            more = f" (and {len(problems) - 3} more)" if len(problems) > 3 else ""
            raise DatasetError(f"'{manifest.data['title']}' does not match its manifest: "
                               + "; ".join(problems[:3]) + more)
        items, excluded = usable_items(manifest, purpose)
        sets.append((manifest, items))
        described.append({"title": manifest.data["title"], "manifest_sha256": manifest.manifest_sha256,
                          "license": manifest.data["license"], "synthetic": manifest.data["synthetic"],
                          "generator": manifest.data.get("generator"), "items_total": len(manifest.items),
                          "items_used": len(items), "items_excluded": excluded,
                          "writers": len({i["writer_id"] for i in items})})
    dossier = {
        "kind": "forensic-hand validation dossier", "format": 1,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "purpose": purpose,
        "environment": environment(cfg),
        "datasets": described,
        "tasks": {"copy-check": copy_check_task(sets, cfg), "blur-screen": blur_task(sets, cfg, blur_samples),
                  "jpeg-estimate": jpeg_task(sets, cfg, jpeg_samples),
                  "writer-score": writer_score_task(sets, cfg)},
        "limits": LIMITS,
        "generated_claimed": utc_now(),
    }
    if calibration is not None:
        dossier["tasks"]["lr"] = lr_task(sets, cfg, calibration)
    dossier["results_sha256"] = _results_hash(dossier)
    return dossier


# ---------------------------------------------------------------- the dossier file

_CSS = """body{margin:0;background:#fbfbfa;color:#1c1c1a;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 20px 64px}h1{font-size:26px;margin:0 0 4px}
h2{font-size:18px;margin:34px 0 10px;padding-top:14px;border-top:1px solid #d9d8d2}h3{font-size:15px;margin:20px 0 6px}
.muted{color:#5d5d58}.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;overflow-wrap:anywhere}
.banner{border:1px solid #d9d8d2;border-left:5px solid #b3541e;background:#fff;padding:12px 16px;margin:18px 0;border-radius:4px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;background:#fff;margin:6px 0}
th,td{text-align:left;vertical-align:top;padding:6px 9px;border:1px solid #d9d8d2}th{font-weight:600}
td.n{font-variant-numeric:tabular-nums;white-space:nowrap}ul{padding-left:22px}
@media (prefers-color-scheme:dark){body{background:#161615;color:#ecebe6}.muted{color:#a3a29b}
table,.banner{background:#1f1f1d}th,td,.banner{border-color:#3a3a36}}"""


def _e(value) -> str:
    return escape("" if value is None else str(value), quote=True)


def _pct(r: dict) -> str:
    if r.get("rate") is None:
        return "-"
    lo, hi = r["ci95"]
    return f"{r['rate'] * 100:.1f}% ({r['k']}/{r['n']}; 95% CI {lo * 100:.1f} to {hi * 100:.1f})"


def _writer_html(task: dict) -> str:
    parts = ["<h2>Writer score (raw)</h2><p class='muted'>A raw research score: it is <strong>not a likelihood "
             "ratio</strong> and a case cannot use it. 0 means: as close to the known signatures as they are to "
             f"each other; below 0: farther away. Feature version {_e(task['feature_version'])}, "
             f"{_e(task['min_known'])} known signatures per comparison.</p>"]
    if task.get("skipped"):
        parts.append(f"<p>Not measured: {_e(task['skipped'])}.</p>")
        return "".join(parts)
    parts.append("<ul>" + "".join(f"<li><strong>{_e(k)}</strong>: {_e(v)}</li>" for k, v in task["pairs"].items())
                 + "</ul><div class='scroll'><table><tr><th>Stratum</th><th>Genuine (n, median)</th>"
                   "<th>Skilled forgery (n, median)</th><th>AUC</th><th>EER</th>"
                   "<th>Other writer (n, median)</th><th>AUC</th><th>EER</th></tr>")
    for name, row in [*task["strata"].items(), ("all strata", task["all"])]:
        pos, neg = row["positives"], row["negatives"]
        cells = "".join(f"<td class='n'>{_e(neg[t]['n'])}, {_e(neg[t]['median'])}</td><td class='n'>"
                        f"{_e(neg[t]['auc'])}</td><td class='n'>{_e(neg[t]['eer'])}</td>" for t in SCORE_NEGATIVES)
        parts.append(f"<tr><td>{_e(name)}</td><td class='n'>{_e(pos['n'])}, {_e(pos['median'])}</td>{cells}</tr>")
    parts.append("</table></div><h3>The measures</h3><ul>"
                 + "".join(f"<li><strong>{_e(k)}</strong>: {_e(v)}</li>" for k, v in task["groups"].items()) + "</ul>")
    return "".join(parts)


def tippett_svg(same: list, different: list, width: int = 640, height: int = 300) -> str:
    """Tippett plot: the share of LRs at or above each value, for each kind of pair. Plain SVG, no script."""
    lo = min(-1.0, *same, *different)
    hi = max(1.0, *same, *different)
    left, right, top, bottom = 52, 16, 14, 40
    w, h = width - left - right, height - top - bottom

    def x(v):
        return left + (v - lo) / (hi - lo) * w

    def y(share):
        return top + (1 - share) * h

    def line(values, colour, dash):
        values = sorted(values)
        n = len(values)
        points = [(x(lo), y(1.0))]
        for i, v in enumerate(values):
            above = (n - i) / n
            points += [(x(v), y(above)), (x(v), y((n - i - 1) / n))]
        points.append((x(hi), y(0.0)))
        path = " ".join(f"{px:.1f},{py:.1f}" for px, py in points)
        return (f"<polyline fill='none' stroke='{colour}' stroke-width='2' stroke-dasharray='{dash}' "
                f"points='{path}'/>")

    ticks = "".join(f"<line x1='{x(t):.1f}' y1='{top}' x2='{x(t):.1f}' y2='{top + h}' stroke='#8884'/>"
                    f"<text x='{x(t):.1f}' y='{top + h + 16}' text-anchor='middle' font-size='11'>{t:g}</text>"
                    for t in range(math.ceil(lo), math.floor(hi) + 1))
    shares = "".join(f"<text x='{left - 6}' y='{y(s) + 4:.1f}' text-anchor='end' font-size='11'>{s:.0%}</text>"
                     for s in (0, 0.5, 1))
    return (f"<svg role='img' aria-label='Tippett plot' viewBox='0 0 {width} {height}' width='100%' "
            f"style='max-width:{width}px' font-family='system-ui,sans-serif' fill='currentColor'>"
            f"<rect x='{left}' y='{top}' width='{w}' height='{h}' fill='none' stroke='#8888'/>{ticks}{shares}"
            f"{line(same, '#1f7a4d', '0')}{line(different, '#b3541e', '6 4')}"
            f"<text x='{left + w / 2:.0f}' y='{height - 4}' text-anchor='middle' font-size='12'>log10 LR "
            "(0 is LR 1; 2 is LR 100; -2 is LR 1/100)</text></svg>")


def _lr_html(task: dict) -> str:
    parts = ["<h2>Likelihood ratio</h2>"]
    if task["status"] == "demo":
        parts.append("<div class='banner'><strong>This is a demo calibration.</strong> It was fitted on synthetic "
                     "data. These numbers show how the method behaves. A case can never use a demo calibration.</div>")
    elif task["status"] != "released":
        parts.append("<div class='banner'><strong>This calibration is not released.</strong> A case cannot use it "
                     "until a release checks it against pass marks that were time stamped before the test.</div>")
    parts.append(f"<p><strong>Hp</strong>: {_e(task['hp'])}<br><strong>Hd</strong>: {_e(task['hd'])}</p>"
                 f"<p class='muted'>Calibration SHA-256 <span class='mono'>{_e(task['calibration_sha256'])}</span>. "
                 f"Strata: {_e(', '.join(task['strata']) or 'none')}"
                 + (f"; outside the calibration, not measured: {_e(', '.join(task['outside_conditions']))}"
                    if task["outside_conditions"] else "") + ".</p>")
    if task.get("skipped"):
        parts.append(f"<p>Not measured: {_e(task['skipped'])}.</p>")
        return "".join(parts)
    if task["writers_overlap"]:
        parts.append("<div class='banner'><strong>Writers were used to calibrate and are tested again:</strong> "
                     f"{_e(', '.join(task['writers_overlap']))}. This is not a fair test. A release refuses it.</div>")
    mis = task["misleading"]

    def rate(m):
        lo, hi = m["ci95_writers"]
        by_writers = f"; by writers {lo * 100:.1f} to {hi * 100:.1f}" if lo is not None else ""
        return f"{_pct(m)}{by_writers}"

    lo, hi = task["cllr_ci95"]
    parts.append(
        "<div class='scroll'><table><tr><th>Measure</th><th>Value</th><th>Meaning</th></tr>"
        f"<tr><td>Pairs</td><td class='n'>{_e(task['pairs']['same'])} same writer, "
        f"{_e(task['pairs']['different'])} for Hd, {_e(task['writers'])} writer(s)</td><td></td></tr>"
        f"<tr><td>Cllr</td><td class='n'>{_e(task['cllr'])} (95% by writers {_e(lo)} to {_e(hi)})</td>"
        "<td>Cost of the LRs. 0 is perfect; 1 is no better than always saying LR 1.</td></tr>"
        f"<tr><td>Cllr-min</td><td class='n'>{_e(task['cllr_min'])}</td><td>The best cost these scores allow "
        "(discrimination).</td></tr>"
        f"<tr><td>Cllr-cal</td><td class='n'>{_e(task['cllr_cal'])}</td><td>Cost of the calibration "
        "(Cllr minus Cllr-min).</td></tr>"
        f"<tr><td>Misleading for Hp</td><td class='n'>{_e(rate(mis['hp']))}</td><td>Same-writer pairs with an LR "
        "below 1.</td></tr>"
        f"<tr><td>Misleading for Hd</td><td class='n'>{_e(rate(mis['hd']))}</td><td>Pairs for Hd with an LR above 1."
        "</td></tr>"
        f"<tr><td>At a bound</td><td class='n'>{_e(round(task['bounded_share'] * 100, 1))}%</td><td>LRs held at the "
        f"lower ({_e(task['model']['lower'])}) or upper ({_e(task['model']['upper'])}) log10 bound.</td></tr>"
        "</table></div>")
    parts.append("<h3>Tippett plot</h3><p class='muted'>Share of LRs at or above each value. Solid green: same-writer "
                 "pairs (should lie to the right). Dashed orange: pairs for Hd (should lie to the left).</p>"
                 + tippett_svg(task["tippett"]["same"], task["tippett"]["different"]))
    return "".join(parts)


def dossier_html(d: dict) -> str:
    parts = []
    add = parts.append
    add(f"<h1>Validation dossier</h1><p class='muted'>{_e(d['tool']['name'])} {_e(d['tool']['version'])} &middot; "
        f"purpose: {_e(d['purpose'])} &middot; made {_e(d['generated_claimed'])} (clock of this computer)</p>")
    flags = [ds["synthetic"] for ds in d["datasets"]]
    if flags and all(flags):
        add("<div class='banner'><strong>Synthetic data only.</strong> These numbers show how the method behaves on "
            "generated signatures. They are not error rates on real casework, and they must not be quoted as such.</div>")
    elif any(flags):
        add("<div class='banner'><strong>This report mixes real and synthetic data.</strong> The pooled numbers are "
            "not error rates on real casework. Run the real datasets alone to report real error rates.</div>")
    add(f"<p>Results hash (SHA-256): <span class='mono'>{_e(d['results_sha256'])}</span>. The same data and "
        "settings give the same hash.</p>")

    add("<h2>Data</h2><div class='scroll'><table><tr><th>Dataset</th><th>Licence</th><th>Items used</th>"
        "<th>Left out</th><th>Writers</th><th>Manifest SHA-256</th></tr>")
    for ds in d["datasets"]:
        left = ", ".join(f"{k}: {v}" for k, v in ds["items_excluded"].items()) or "none"
        add(f"<tr><td>{_e(ds['title'])}{' (synthetic)' if ds['synthetic'] else ''}</td>"
            f"<td>{_e(ds['license']['class'])}: {_e(ds['license']['name'])}</td><td class='n'>{_e(ds['items_used'])} of "
            f"{_e(ds['items_total'])}</td><td>{_e(left)}</td><td class='n'>{_e(ds['writers'])}</td>"
            f"<td class='mono'>{_e(ds['manifest_sha256'])}</td></tr>")
    add("</table></div>")

    copy = d["tasks"]["copy-check"]
    s = copy["settings"]
    add("<h2>Copy check (digital cut and paste)</h2>")
    add(f"<p class='muted'>Warning at a score of {_e(s['clone_warning_at'])}, note at {_e(s['clone_notice_at'])}. "
        "A good result: copies flagged near 100%, false alarms near 0%.</p><ul>")
    for name, text in copy["pairs"].items():
        add(f"<li><strong>{_e(name)}</strong>: {_e(text)}</li>")
    add("</ul><div class='scroll'><table><tr><th>Stratum</th><th>Copies flagged (warning)</th>"
        "<th>False alarms: same writer</th><th>False alarms: skilled forgery</th><th>False alarms: other writer</th>"
        "<th>AUC</th><th>EER</th></tr>")
    for name, row in [*copy["strata"].items(), ("all strata", copy["all"])]:
        neg = row["negatives"]
        add(f"<tr><td>{_e(name)}</td><td class='n'>{_e(_pct(row['positives']['warning']))}</td>"
            + "".join(f"<td class='n'>{_e(_pct(neg[t]['warning']))}</td>" for t in NEGATIVE_TYPES)
            + f"<td class='n'>{_e(row['auc'])}</td><td class='n'>{_e(row['eer']['eer'])}</td></tr>")
    add("</table></div><h3>At the note level</h3><div class='scroll'><table><tr><th>Stratum</th>"
        "<th>Copies flagged (note)</th><th>False alarms: same writer</th><th>Highest same-writer score</th></tr>")
    for name, row in [*copy["strata"].items(), ("all strata", copy["all"])]:
        sw = row["negatives"]["same-writer"]
        add(f"<tr><td>{_e(name)}</td><td class='n'>{_e(_pct(row['positives']['notice']))}</td>"
            f"<td class='n'>{_e(_pct(sw['notice']))}</td><td class='n'>{_e(sw['max_score'])}</td></tr>")
    add("</table></div>")

    if "writer-score" in d["tasks"]:     # dossiers made before Stage 4 have no writer score
        add(_writer_html(d["tasks"]["writer-score"]))
    if "lr" in d["tasks"]:
        add(_lr_html(d["tasks"]["lr"]))

    blur = d["tasks"]["blur-screen"]
    add(f"<h2>Blur screen</h2><p class='muted'>{_e(blur['method'])}; {_e(blur['samples'])} signature(s).</p>"
        "<div class='scroll'><table><tr><th>Blur added (px)</th><th>Warning given</th><th>Note or warning given</th>"
        "<th>Mean sharpness score</th></tr>")
    for row in blur["rows"]:
        add(f"<tr><td class='n'>{_e(row['sigma_px'])}</td><td class='n'>{_e(_pct(row['warning']))}</td>"
            f"<td class='n'>{_e(_pct(row['note_or_warning']))}</td><td class='n'>{_e(row['mean_sharpness'])}</td></tr>")
    add("</table></div>")

    jpg = d["tasks"]["jpeg-estimate"]
    add(f"<h2>JPEG quality estimate</h2><p class='muted'>{_e(jpg['samples'])} signature(s).</p><div class='scroll'>"
        "<table><tr><th>True quality</th><th>Mean error</th><th>Largest error</th><th>Expected level</th>"
        "<th>Level given as expected</th></tr>")
    for row in jpg["rows"]:
        add(f"<tr><td class='n'>{_e(row['quality'])}</td><td class='n'>{_e(row['mean_abs_error'])}</td>"
            f"<td class='n'>{_e(row['max_abs_error'])}</td><td>{_e(row['expected_level'])}</td>"
            f"<td class='n'>{_e(_pct(row['level_agrees']))}</td></tr>")
    add("</table></div>")

    add("<h2>What this does not show</h2><ul>" + "".join(f"<li>{_e(x)}</li>" for x in d["limits"]) + "</ul>")
    env = d["environment"]
    packages = ", ".join(f"{k} {v}" for k, v in sorted(env["packages"].items()))
    add(f"<h2>Method and settings</h2><p>Python {_e(env['python'])} on {_e(env['platform'])}; {_e(packages)}.</p>"
        f"<p>Settings SHA-256: <span class='mono'>{_e(env['config_sha256'])}</span>. Every setting is in "
        "dossier.json.</p>")
    return ("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' "
            "content='width=device-width, initial-scale=1'><title>Validation dossier</title>"
            f"<style>{_CSS}</style></head><body><main>{''.join(parts)}</main></body></html>\n")


def write_dossier(dossier: dict, out_dir) -> Path:
    out = Path(out_dir)
    if (out / "dossier.json").exists():
        raise DatasetError(f"a dossier exists already in {out}; choose a new folder")
    out.mkdir(parents=True, exist_ok=True)
    (out / "dossier.json").write_text(json.dumps(dossier, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                                      encoding="utf-8")
    path = out / "dossier.html"
    path.write_text(dossier_html(dossier), encoding="utf-8")
    return path
