"""Examiner work in the workbench: crops, notes, measurements, copy check, charts, the locked score.

Every action is one ledger event. A file that an action makes (a crop, a chart) is stored by
its SHA-256 and set to read-only before the event is written. If the event cannot be written,
a new file is removed again, so the case never holds a file that the ledger does not know.
"""

from __future__ import annotations

import hashlib
import io
import json
import math

from PIL import Image

from . import calibrate, clones, exhibit, pages, release, writer
from .case import CaseError, _clean, clean_text
from .config import DEFAULTS
from .findings import finding
from .store import StoreError, store_bytes

MAX_PANELS = 12
_ID_LIMIT = 40


def _record(case, kind: str, data: dict, stored: dict) -> dict:
    try:
        case.ledger.append(kind, data)
    except BaseException:
        if stored.get("created"):
            path = case.path / stored["file"]
            if path.exists():
                import os
                import stat

                os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
                path.unlink()
        raise
    return data


def _store_png(case, img: Image.Image, folder: str, dpi=None) -> dict:
    buf = io.BytesIO()
    options = {"dpi": tuple(dpi)} if dpi else {}
    img.save(buf, "PNG", optimize=False, **options)
    try:
        return store_bytes(buf.getvalue(), case.path / folder, ".png")
    except (StoreError, OSError) as exc:
        raise CaseError(f"the picture could not be stored: {exc}") from exc


def _evidence(state, evidence_id) -> dict:
    for rec in state["evidence"]:
        if rec["id"] == evidence_id:
            return rec
    raise CaseError(f"no item with the id {str(evidence_id)[:_ID_LIMIT]}")


def _crop(state, crop_id) -> dict:
    for crop in state["crops"]:
        if crop["crop_id"] == crop_id:
            return crop
    raise CaseError(f"no crop with the id {str(crop_id)[:_ID_LIMIT]}")


def _number(value, name: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise CaseError(f"{name} must be a number")
    if not low <= value <= high:
        raise CaseError(f"{name} must be between {low} and {high}")
    return float(value)


# ---------------------------------------------------------------- crops

def add_crop(case, evidence_id, page, box, label=None, dpi=None) -> dict:
    with case.ledger.lock():
        state = case.state()
        record = _evidence(state, evidence_id)
        img, meta = pages.region(case, record, page, box, dpi)
        stored = _store_png(case, img, "derived", meta["dpi"])
        data = {
            "crop_id": f"C{len(state['crops']) + 1}",
            "evidence_id": record["id"],
            "source_sha256": record["sha256"],
            "page": page,
            "box": meta["box"],
            "units": meta["units"],
            "label": _clean(label, 200),
            "width": img.width,
            "height": img.height,
            "mode": img.mode,
            "dpi": meta["dpi"],
            "render_dpi": meta["render_dpi"],
            "pixel_box": meta.get("pixel_box"),
            "method": meta["method"],
            "renderer": meta["renderer"],
            "converted": meta["converted"],
            "file": stored["file"],
            "sha256": stored["sha256"],
            "size": stored["size"],
        }
        return _record(case, "crop.created", data, stored)


def crop_image(case, crop: dict) -> Image.Image:
    """The picture of a crop, only if its file still has the hash that the ledger recorded."""
    try:
        data = (case.path / crop["file"]).read_bytes()
    except OSError as exc:
        raise CaseError(f"crop {crop['crop_id']}: its file cannot be read: {exc}") from exc
    if hashlib.sha256(data).hexdigest() != crop["sha256"]:
        raise CaseError(f"crop {crop['crop_id']}: its file was changed (its hash does not match the ledger). "
                        "Run: fhand verify <case>")
    with Image.open(io.BytesIO(data)) as img:
        img.load()
        return img.copy()


# ---------------------------------------------------------------- notes

def add_note(case, target, text, supersedes=None) -> dict:
    text = clean_text(text)
    if not text:
        raise CaseError("a note needs text")
    with case.ledger.lock():
        state = case.state()
        targets = ({"case"} | {r["id"] for r in state["evidence"]} | {c["crop_id"] for c in state["crops"]}
                   | {x["exhibit_id"] for x in state["exhibits"]})
        if target not in targets:
            raise CaseError(f"a note must be about the case, an item, a crop or a chart, not {str(target)[:_ID_LIMIT]}")
        if supersedes is not None and supersedes not in {n["note_id"] for n in state["notes"]}:
            raise CaseError(f"no note with the id {str(supersedes)[:_ID_LIMIT]}")
        data = {"note_id": f"N{len(state['notes']) + 1}", "target": target, "text": text, "supersedes": supersedes}
        case.ledger.append("note.added", data)
        return data


# ---------------------------------------------------------------- measurements

def _points(points, count: int, crop: dict) -> list[list[float]]:
    if not isinstance(points, list) or len(points) != count:
        raise CaseError(f"this measurement needs {count} points")
    out = []
    for point in points:
        if not isinstance(point, list | tuple) or len(point) != 2:
            raise CaseError("each point must be two numbers: x and y")
        x = _number(point[0], "x", 0, crop["width"])
        y = _number(point[1], "y", 0, crop["height"])
        out.append([round(x, 2), round(y, 2)])
    return out


def _line(p, q, dpi) -> dict:
    dx, dy = q[0] - p[0], q[1] - p[1]
    length_px = math.hypot(dx, dy)
    if length_px == 0:
        raise CaseError("the two points of a line must differ")
    if dpi:
        dx_in, dy_in = dx / dpi[0], dy / dpi[1]
        length_mm = round(math.hypot(dx_in, dy_in) * 25.4, 3)
    else:
        dx_in, dy_in, length_mm = dx, dy, None
    # Screen y grows downward; the angle is counter-clockwise from the horizontal, 0 to 180 degrees.
    angle = math.degrees(math.atan2(-dy_in, dx_in)) % 180.0
    return {"length_px": round(length_px, 2), "length_mm": length_mm, "angle_deg": round(angle, 2)}


def add_measurement(case, crop_id, kind, points, note=None) -> dict:
    if kind not in ("line", "angle"):
        raise CaseError("the kind of measurement must be: line or angle")
    with case.ledger.lock():
        state = case.state()
        crop = _crop(state, crop_id)
        pts = _points(points, 2 if kind == "line" else 4, crop)
        dpi = crop["dpi"]
        data = {"measure_id": f"M{len(state['measurements']) + 1}", "crop_id": crop["crop_id"], "kind": kind,
                "points": pts, "note": clean_text(note, 1000)}
        first = _line(pts[0], pts[1], dpi)
        if kind == "line":
            data.update(first)
        else:
            second = _line(pts[2], pts[3], dpi)
            data["angles_deg"] = [first["angle_deg"], second["angle_deg"]]
            data["angle_between_deg"] = round((second["angle_deg"] - first["angle_deg"]) % 180.0, 2)
        data["physical"] = bool(dpi)
        case.ledger.append("measure.added", data)
        return data


# ---------------------------------------------------------------- copy check

def _clone_settings(cfg: dict) -> dict:
    return {"radius_px": cfg["clone_radius_px"], "blur_px": cfg["clone_blur_px"],
            "ink_separation": cfg["clone_ink_separation"], "ink_hue_deg": cfg["clone_ink_hue_deg"],
            "rotations_deg": cfg["clone_rotations_deg"],
            "notice_at": cfg["clone_notice_at"], "warning_at": cfg["clone_warning_at"],
            "max_aspect_diff": cfg["clone_max_aspect_diff"], "min_ink_fraction": cfg["clone_min_ink_fraction"],
            "method": "second ink of another hue removed (Lab 2-means), Otsu ink, long straight lines removed, farthest 2% of ink dropped, scale by ink spread, "
                      "small blur, cross-correlation shift, Pearson score",
            "status": cfg["status"]}


def _overlap(a: dict, b: dict) -> bool:
    if a["source_sha256"] != b["source_sha256"] or a["page"] != b["page"]:
        return False
    if a["units"] != b["units"]:
        return False
    ax0, ay0, ax1, ay1 = a["box"]
    bx0, by0, bx1, by1 = b["box"]
    return ax0 < bx1 and bx0 < ax1 and ay0 < by1 and by0 < ay1


_CLONE_LIMITS = ("Two genuine signatures are never identical point for point. A score this high fits a digital "
                 "copy (cut and paste), but it also fits two scans or copies of the same piece of paper. "
                 "The score is a screening value and is not validated on real casework.")


def run_clone_check(case, config: dict | None = None) -> dict:
    cfg = config or DEFAULTS
    settings = _clone_settings(cfg)
    with case.ledger.lock():
        state = case.state()
        crops = state["crops"]
        prepared, skipped, separated = {}, [], {}
        for crop in crops:
            features = clones.prepare(crop_image(case, crop), cfg["clone_radius_px"], cfg["clone_min_ink_fraction"],
                                      cfg["clone_blur_px"], separate=cfg["clone_ink_separation"],
                                      hue_deg=cfg["clone_ink_hue_deg"])
            if features is None:
                skipped.append(crop["crop_id"])
            else:
                prepared[crop["crop_id"]] = features
                if features["ink_separation"].get("inks") == 2:
                    separated[crop["crop_id"]] = features["ink_separation"]
        pairs, found = [], []
        for i, a in enumerate(crops):
            for b in crops[i + 1:]:
                ida, idb = a["crop_id"], b["crop_id"]
                if ida not in prepared or idb not in prepared:
                    continue
                if _overlap(a, b):
                    pairs.append({"a": ida, "b": idb, "score": None, "reason": "the two crops share the same area"})
                    continue
                result = clones.compare(prepared[ida], prepared[idb], cfg["clone_rotations_deg"],
                                        cfg["clone_max_aspect_diff"])
                pairs.append({"a": ida, "b": idb, **result})
                score = result["score"]
                if score is not None and score >= cfg["clone_notice_at"]:
                    level = "warning" if score >= cfg["clone_warning_at"] else "notice"
                    code = "CLONE-NEAR-IDENTICAL" if level == "warning" else "CLONE-VERY-SIMILAR"
                    title = (f"{ida} and {idb} match almost point for point." if level == "warning"
                             else f"{ida} and {idb} are very similar in shape and position.")
                    found.append(finding(code, level, title,
                                         detail=f"Match score {score} (note from {cfg['clone_notice_at']}, "
                                                f"warning from {cfg['clone_warning_at']}).",
                                         limits=_CLONE_LIMITS, crops=[ida, idb], score=score))
        data = {"crops": [c["crop_id"] for c in crops], "pairs": pairs, "skipped": skipped,
                "findings": found, "settings": settings, "ink_separation": separated}
        case.ledger.append("clone.checked", data)
        return data


# ---------------------------------------------------------------- charts

def _item(case, state, crop_id, label=None) -> dict:
    crop = _crop(state, crop_id)
    source = _evidence(state, crop["evidence_id"])
    label = _clean(label, 120) or crop.get("label") or f"{crop['crop_id']} ({source['role']})"
    return {"crop": crop, "image": crop_image(case, crop), "label": label, "source": source}


def make_exhibit(case, title, panels=None, kind="panels", overlay=None) -> dict:
    title = _clean(title, 200)
    if not title:
        raise CaseError("a chart needs a title")
    if kind not in ("panels", "overlay"):
        raise CaseError("the kind of chart must be: panels or overlay")
    with case.ledger.lock():
        state = case.state()
        subtitle = f"Case: {state['title']}"
        head = state["ledger_head"]
        if kind == "panels":
            if not isinstance(panels, list) or not 1 <= len(panels) <= MAX_PANELS:
                raise CaseError(f"a chart needs 1 to {MAX_PANELS} crops")
            items = []
            for panel in panels:
                if not isinstance(panel, dict):
                    raise CaseError("each panel must name a crop")
                items.append(_item(case, state, panel.get("crop_id"), panel.get("label")))
            png, meta = exhibit.draw_panels(title, subtitle, items, state["case_id"])
            spec = {"panels": [{"crop_id": it["crop"]["crop_id"], "label": it["label"]} for it in items]}
        else:
            if not isinstance(overlay, dict):
                raise CaseError("an overlay chart needs two crops and an alignment")
            params = {"dx": _number(overlay.get("dx", 0), "dx", -5000, 5000),
                      "dy": _number(overlay.get("dy", 0), "dy", -5000, 5000),
                      "rotation": _number(overlay.get("rotation", 0), "rotation", -30, 30),
                      "scale": _number(overlay.get("scale", 1), "scale", 0.25, 4)}
            params = {k: round(v, 3) for k, v in params.items()}
            if overlay.get("a") == overlay.get("b"):
                raise CaseError("an overlay needs two different crops")
            a = _item(case, state, overlay.get("a"))
            b = _item(case, state, overlay.get("b"))
            png, meta = exhibit.draw_overlay(title, subtitle, a, b, params, state["case_id"])
            spec = {"overlay": {"a": a["crop"]["crop_id"], "b": b["crop"]["crop_id"], **params}}
        try:
            stored = store_bytes(png, case.path / "exhibits", ".png")
        except (StoreError, OSError) as exc:
            raise CaseError(f"the chart could not be stored: {exc}") from exc
        data = {"exhibit_id": f"E{len(state['exhibits']) + 1}", "title": title, "kind": kind, **spec, **meta,
                "ledger_head_at_creation": head, "file": stored["file"], "sha256": stored["sha256"],
                "size": stored["size"]}
        return _record(case, "exhibit.created", data, stored)


# ---------------------------------------------------------------- the locked score (Stage 4)

SCORE_LIMITS = [
    ("The likelihood ratio is one input for the examiner. It is not a verdict, and it is not the chance "
     "that the known writer wrote the signature."),
    ("It measures the pictures of the crops only: not pen pressure, line quality under magnification, the ink, "
     "or indentations in the paper. It does not replace an examination of the original document."),
    ("It holds only for its two propositions and inside the conditions that its test covered. A case outside "
     "them gets no score."),
]
# Quality warnings, and the test condition (stratum) in which a calibration must have been tested to allow them.
WARNING_STRATA = {"IMG-BLUR": "blur", "IMG-SOFT": "blur", "IMG-JPEG-QUALITY": "jpeg", "IMG-DPI-LOW": "dpi150"}
ALWAYS_REFUSE = {"IMG-SMALL"}
LOCKED = ("no released calibration is in this case. A score needs a calibration that passed pass marks, "
          "written and time stamped before its test, on real and consented signatures (fhand release). "
          "Add one with: fhand score <case> --release <file> --questioned <crop> --known <crops>")


def _checked_release(raw: bytes) -> tuple[dict, dict]:
    """Parse a release file and run every release check again (release.check_release)."""
    try:
        bundle = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        bundle = None
    if not isinstance(bundle, dict) or bundle.get("kind") != "forensic-hand released calibration":
        raise CaseError("this file is not a released calibration. A case can use only a release (fhand release); "
                        "a calibration file alone is never enough")
    try:
        facts = release.check_release(bundle)
    except release.ReleaseError as exc:
        raise CaseError(str(exc)) from exc
    return bundle, facts


def _checker_checks_scores(case) -> bool:
    """Does the checker in the case folder (copied when the case was made) know how to check scores?"""
    try:
        text = (case.path / "verify_case.py").read_text(encoding="utf-8")
    except OSError:
        return False
    return "\nCHECKS_SCORES = True\n" in text


def add_release(case, raw: bytes) -> dict:
    """Check a release file and keep it in the case (models/, read-only, in the ledger and the next seal)."""
    if not _checker_checks_scores(case):
        raise CaseError("this case was made with an older checker (verify_case.py) that cannot check scores, so the "
                        "other side could not check one. Make a new case with this version to use a score")
    bundle, facts = _checked_release(raw)
    sha = hashlib.sha256(raw).hexdigest()
    with case.ledger.lock():
        state = case.state()
        for rel in state["releases"]:
            if rel["sha256"] == sha:
                return rel
        try:
            stored = store_bytes(raw, case.path / "models", ".json")
        except (StoreError, OSError) as exc:
            raise CaseError(f"the release file could not be stored: {exc}") from exc
        calibration = bundle["calibration"]
        data = {"release_id": f"R{len(state['releases']) + 1}", "file": stored["file"], "sha256": stored["sha256"],
                "size": stored["size"], "calibration_sha256": calibration["results_sha256"],
                "propositions": calibration["propositions"]["id"], "conditions": calibration["conditions"],
                "criteria_stamp": facts["criteria_stamp"]["gen_time"],
                "dossier_stamp": facts["dossier_stamp"]["gen_time"], "summary": facts["summary"]}
        return _record(case, "release.added", data, stored)


def score_status(case) -> dict:
    state = case.state()
    if not state["releases"]:
        return {"locked": True, "reason": LOCKED, "release_id": None, "known_count": None, "conditions": None}
    rel = state["releases"][-1]
    return {"locked": False, "reason": None, "release_id": rel["release_id"],
            "known_count": rel["conditions"]["known_count"], "conditions": rel["conditions"],
            "propositions": rel["propositions"]}


def _condition_problems(state, crops: dict, cond: dict) -> list[str]:
    problems = []
    strata = set(cond["strata"])
    for eid in sorted({c["evidence_id"] for c in crops.values()}):
        check = state["files"].get(eid)
        if check is None:
            problems.append(f"{eid} has not been screened. Run the screens first (fhand check <case>), so that the "
                            "score can test its conditions")
            continue
        for f in check["findings"]:
            if f["level"] != "warning" or f["code"] not in ALWAYS_REFUSE | set(WARNING_STRATA):
                continue
            stratum = WARNING_STRATA.get(f["code"])
            if f["code"] in ALWAYS_REFUSE or stratum not in strata:
                problems.append(f"{eid} has the warning {f['code']}" + (f" ({stratum})" if stratum else "")
                                + f"; the calibration was tested on: {', '.join(sorted(strata))}")
    low, high = cond["dpi"] if cond.get("dpi") else (None, None)
    for cid, crop in crops.items():
        dpi = crop.get("dpi")
        if not dpi:
            problems.append(f"{cid}: its resolution is not known, so it cannot be held to the tested resolution")
        elif low is None:
            problems.append("the calibration does not record the resolution of its data")
        elif not all(low * 0.99 <= v <= high * 1.01 for v in dpi[:2]):
            problems.append(f"{cid}: its resolution ({dpi[0]:g} DPI) is outside the tested range ({low} to {high} DPI)")
    return problems


def run_score(case, questioned, known, release_id=None, config: dict | None = None) -> dict:
    """The LR of a questioned crop against known crops, with a release that is checked again now."""
    cfg = config or DEFAULTS
    state = case.state()
    if not state["releases"]:
        raise CaseError(f"the score is locked: {LOCKED}")
    wanted = release_id or state["releases"][-1]["release_id"]
    rel = next((r for r in state["releases"] if r["release_id"] == wanted), None)
    if rel is None:
        raise CaseError(f"no released calibration with the id {str(wanted)[:_ID_LIMIT]}")
    raw = (case.path / rel["file"]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != rel["sha256"]:
        raise CaseError(f"the release file of {rel['release_id']} was changed in the case folder")
    if not _checker_checks_scores(case):
        raise CaseError("the checker in this case (verify_case.py) cannot check scores; make a new case to use one")
    _, facts = _checked_release(raw)
    calibration = facts["calibration"]          # the calibration checked from the files inside the release
    try:
        calibrate.check_settings(calibration, cfg)
    except calibrate.CalibrationError as exc:
        raise CaseError(str(exc)) from exc
    cond = calibration["conditions"]
    k = int(cond["known_count"])
    if not isinstance(known, list) or len(known) != k:
        raise CaseError(f"this calibration was tested with exactly {k} known signatures; choose exactly {k} known crops")
    ids = [questioned, *known]
    if len(set(map(str, ids))) != len(ids):
        raise CaseError("each crop may be used only once in a score")
    crops = {cid: _crop(state, cid) for cid in ids}
    for cid in known:
        source = _evidence(state, crops[cid]["evidence_id"])
        if source["role"] != "known":
            raise CaseError(f"{cid} must come from a known item; it comes from {source['id']} ({source['role']})")
    source = _evidence(state, crops[questioned]["evidence_id"])
    if source["role"] != "questioned":
        raise CaseError(f"{questioned} must come from a questioned item; it comes from {source['id']} "
                        f"({source['role']})")
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            if _overlap(crops[a], crops[b]):
                raise CaseError(f"{a} and {b} share the same area of a page")
    problems = _condition_problems(state, crops, cond)
    feats = {}
    for cid, crop in crops.items():
        feats[cid] = writer.features(crop_image(case, crop), cfg)
        if feats[cid] is None:
            problems.append(f"{cid} has no clear ink")
        elif feats[cid]["ink_separation"].get("inks") == 2 and not {"stamp", "stamp-same"} & set(cond["strata"]):
            problems.append(f"{cid} holds a second ink (a stamp); the calibration was not tested with stamps")
    if problems:
        raise CaseError("no score: the case is outside what the test of this calibration covered:\n- "
                        + "\n- ".join(problems))
    result = writer.compare(feats[questioned], [feats[c] for c in known], k)
    lr = calibrate.apply(calibration, result["score"], cfg)
    model = calibration["model"]
    with case.ledger.lock():
        state = case.state()
        data = {
            "score_id": f"S{len(state['scores']) + 1}", "questioned": questioned, "known": list(known),
            "release_id": rel["release_id"], "release_sha256": rel["sha256"],
            "calibration_sha256": calibration["results_sha256"], "propositions": calibration["propositions"],
            "feature_version": writer.FEATURE_VERSION, "score_settings": calibration["score_settings"],
            "features": feats, "score": result["score"], "groups": result["groups"],
            "model": {name: model[name] for name in ("a", "b", "lower", "upper")},
            "log10_lr": lr["log10_lr"], "unbounded": lr["unbounded"], "bounded": lr["bounded"],
            "lr_text": calibrate.lr_text(lr["log10_lr"]), "verbal": calibrate.verbal(lr["log10_lr"]),
            "verbal_source": calibrate.VERBAL_SOURCE, "conditions": cond,
            "release_facts": {"criteria_stamp": facts["criteria_stamp"]["gen_time"],
                              "dossier_stamp": facts["dossier_stamp"]["gen_time"], "summary": facts["summary"]},
            "limits": SCORE_LIMITS,
        }
        case.ledger.append("score.computed", data)
        return data
