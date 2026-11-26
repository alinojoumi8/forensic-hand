"""Examiner work in the workbench: crops, notes, measurements, copy check, charts.

Every action is one ledger event. A file that an action makes (a crop, a chart) is stored by
its SHA-256 and set to read-only before the event is written. If the event cannot be written,
a new file is removed again, so the case never holds a file that the ledger does not know.
"""

from __future__ import annotations

import io
import math

from PIL import Image

from . import clones, exhibit, pages
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
    with Image.open(case.path / crop["file"]) as img:
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
            "rotations_deg": cfg["clone_rotations_deg"],
            "notice_at": cfg["clone_notice_at"], "warning_at": cfg["clone_warning_at"],
            "max_aspect_diff": cfg["clone_max_aspect_diff"], "min_ink_fraction": cfg["clone_min_ink_fraction"],
            "method": "Otsu ink, long straight lines removed, middle 96% of ink mass, scale by ink spread, "
                      "small blur, phase correlation shift, Pearson score",
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
        prepared, skipped = {}, []
        for crop in crops:
            features = clones.prepare(crop_image(case, crop), cfg["clone_radius_px"], cfg["clone_min_ink_fraction"],
                                      cfg["clone_blur_px"])
            if features is None:
                skipped.append(crop["crop_id"])
            else:
                prepared[crop["crop_id"]] = features
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
                "findings": found, "settings": settings}
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
