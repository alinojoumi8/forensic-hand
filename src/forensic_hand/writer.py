"""Writer score: is a questioned signature as close to the known signatures as they are to each other?

Stage 4, phase 1. Fixed, explainable measures of the ink. No trained model. The raw score is
NOT a likelihood ratio and it is NOT used in a case: a later step calibrates it on real data.

Method
1. Ink: the same preparation as the copy check (clones.ink_weight). A stamp of another colour,
   long straight lines and stray far ink are removed first.
2. Measures (GROUPS). None of them depends on the scan resolution: sizes are taken relative to
   the spread of the ink (its radius of gyration), and shares are taken of the whole ink.
3. For each group: d = mean distance from the questioned signature to each known signature;
   s = mean distance between the known signatures; ratio = (d + floor) / (s + floor).
   The floor is about the smallest difference that matters for that measure.
4. Score = minus the mean of ln(ratio) over the groups. Each ln(ratio) is limited to
   +/- LOG_RATIO_LIMIT, so that one measure cannot decide the score alone.
   0 means: as close to the knowns as they are to each other. Below 0: farther away.
"""

from __future__ import annotations

import math

import numpy as np
from PIL import Image

from . import clones

# Raise the version whenever a change can alter any measure: a calibration then refuses the new scores.
# 2: ruled lines are removed by relative lengths only (CodeRabbit review 10).
FEATURE_VERSION = 2
NORM_RADIUS_PX = 64       # the ink is resized to this spread before the shape measures
LOG_RATIO_LIMIT = 2.5     # a ratio of about 12 at most, for each group

GROUPS = {
    "proportion": ("scalar", "ln of the length-to-height ratio of the ink (principal axes)"),
    "layout": ("histogram", "share of the ink in each cell of a 3 x 6 grid over the signature"),
    "columns": ("histogram", "ink along the writing line, in 16 steps"),
    "rows": ("histogram", "ink from top to bottom, in 8 steps"),
    "directions": ("histogram", "directions of the pen lines, in 12 steps of 15 degrees"),
    "slant": ("scalar", "mean direction of the up and down strokes, in degrees from vertical (right is +)"),
    "stroke_width": ("scalar", "ln of the typical line width, relative to the size of the signature"),
    "width_spread": ("scalar", "variation of the line width (standard deviation / mean)"),
    "pressure": ("scalar", "variation of the ink darkness along the line (standard deviation / mean)"),
    "roughness": ("scalar", "share of ink that a light smoothing of the edges changes (tremor raises it)"),
    "parts": ("scalar", "ln(1 + number of separate ink parts)"),
    "loops": ("scalar", "ln(1 + number of closed loops)"),
}
FLOORS = {
    "proportion": 0.03, "layout": 0.02, "columns": 0.02, "rows": 0.02, "directions": 0.02,
    "slant": 1.0, "stroke_width": 0.03, "width_spread": 0.02, "pressure": 0.02, "roughness": 0.005,
    "parts": 0.15, "loops": 0.15,
}


class ScoreError(Exception):
    """The score cannot be made. The message is plain language."""


# ---------------------------------------------------------------- small tools

def _r(value: float) -> float:
    return round(float(value), 6)


def _share(values: np.ndarray) -> list[float]:
    total = float(values.sum())
    if total <= 0:
        return [_r(1.0 / values.size)] * values.size
    return [_r(v) for v in (values.ravel() / total)]


def _cells(weight: np.ndarray, ny: int, nx: int) -> np.ndarray:
    h, w = weight.shape
    ys = np.minimum((np.arange(h) * ny) // h, ny - 1)
    xs = np.minimum((np.arange(w) * nx) // w, nx - 1)
    out = np.zeros((ny, nx))
    np.add.at(out, (ys[:, None], xs[None, :]), weight)
    return out


def _moments(weight: np.ndarray) -> tuple[float, float]:
    """Radius of gyration (pixels) and elongation (principal axes) of the ink."""
    mass = weight.sum()
    yy, xx = np.mgrid[0:weight.shape[0], 0:weight.shape[1]]
    cy, cx = (weight * yy).sum() / mass, (weight * xx).sum() / mass
    var_y = float((weight * (yy - cy) ** 2).sum() / mass)
    var_x = float((weight * (xx - cx) ** 2).sum() / mass)
    cov = float((weight * (xx - cx) * (yy - cy)).sum() / mass)
    half_trace, spread = (var_x + var_y) / 2, math.sqrt(max(((var_x - var_y) / 2) ** 2 + cov ** 2, 0.0))
    return math.sqrt(var_x + var_y), math.sqrt((half_trace + spread) / max(half_trace - spread, 1e-9))


def _depth(mask: np.ndarray, limit: int = 200) -> np.ndarray:
    """Chessboard distance of each ink pixel to the paper (1 at the edge of a line)."""
    depth = np.zeros(mask.shape, dtype=np.int32)
    current = mask.copy()
    step = 0
    while current.any() and step < limit:
        step += 1
        depth[current] = step
        p = np.pad(current, 1)
        current = (p[1:-1, 1:-1] & p[:-2, 1:-1] & p[2:, 1:-1] & p[1:-1, :-2] & p[1:-1, 2:]
                   & p[:-2, :-2] & p[:-2, 2:] & p[2:, :-2] & p[2:, 2:])
    return depth


def _ridge(depth: np.ndarray) -> np.ndarray:
    """Ink pixels at the middle of a line: no neighbour lies deeper in the ink."""
    p = np.pad(depth, 1)
    deepest = np.max(np.stack([p[1 + dy:p.shape[0] - 1 + dy, 1 + dx:p.shape[1] - 1 + dx]
                               for dy in (-1, 0, 1) for dx in (-1, 0, 1) if dy or dx]), axis=0)
    return (depth > 0) & (depth >= deepest)


def components(mask: np.ndarray, eight: bool = True) -> list[tuple[int, bool]]:
    """Connected parts of a mask: (area in pixels, touches the edge of the picture), from runs per row."""
    h, w = mask.shape
    padded = np.pad(mask.astype(np.int8), ((0, 0), (1, 1)))
    d = np.diff(padded, axis=1)
    rows, starts = np.nonzero(d == 1)
    _, ends = np.nonzero(d == -1)
    n = rows.size
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    reach = 1 if eight else 0
    first = np.searchsorted(rows, np.arange(h + 1))
    for y in range(1, h):
        i, i_end = int(first[y - 1]), int(first[y])
        j, j_end = int(first[y]), int(first[y + 1])
        while i < i_end and j < j_end:
            if ends[i] + reach <= starts[j]:
                i += 1
            elif ends[j] + reach <= starts[i]:
                j += 1
            else:
                a, b = find(i), find(j)
                if a != b:
                    parent[b] = a
                if ends[i] < ends[j]:
                    i += 1
                else:
                    j += 1
    area: dict[int, int] = {}
    edge: dict[int, bool] = {}
    for k in range(n):
        root = find(k)
        area[root] = area.get(root, 0) + int(ends[k] - starts[k])
        touches = rows[k] == 0 or rows[k] == h - 1 or starts[k] == 0 or ends[k] == w
        edge[root] = edge.get(root, False) or bool(touches)
    return [(area[r], edge[r]) for r in sorted(area)]


# ---------------------------------------------------------------- features

def features(img: Image.Image, cfg: dict) -> dict | None:
    """The measures of one signature crop. None when the crop has no clear ink."""
    cut = clones.ink_weight(img, cfg["clone_min_ink_fraction"], separate=cfg["clone_ink_separation"],
                            hue_deg=cfg["clone_ink_hue_deg"], fixed_minimum=False)
    if cut is None:
        return None
    dark, separation = cut
    mask = dark > 0
    radius, elongation = _moments(dark)
    if radius < 4 or mask.sum() < 50:
        return None

    # Shape measures on the ink resized to a fixed spread.
    factor = NORM_RADIUS_PX / radius
    size = (max(8, round(dark.shape[1] * factor)), max(8, round(dark.shape[0] * factor)))
    norm = np.asarray(Image.fromarray(dark.astype(np.float32), mode="F").resize(size, Image.BILINEAR),
                      dtype=np.float64).clip(0, None)
    smooth = clones._blur(norm, 1.0)
    gy, gx = np.gradient(smooth)
    magnitude = np.hypot(gx, gy)
    # Picture rows grow downward: turn the y axis up. The pen line runs across its own edge direction.
    line_deg = (np.degrees(np.arctan2(-gy, gx)) + 90.0) % 180.0
    strong = magnitude > 0.02 * float(magnitude.max(initial=0.0))
    weights, angles = magnitude[strong], line_deg[strong]
    bins = np.minimum((angles // 15).astype(int), 11)
    directions = np.bincount(bins, weights=weights, minlength=12)
    steep = (angles >= 30) & (angles <= 150)
    if weights[steep].sum() > 0:
        doubled = np.radians(2 * angles[steep])
        mean_deg = math.degrees(math.atan2(float((weights[steep] * np.sin(doubled)).sum()),
                                           float((weights[steep] * np.cos(doubled)).sum()))) / 2 % 180.0
        slant = 90.0 - mean_deg
    else:
        slant = 0.0

    # Line measures at the resolution of the scan.
    depth = _depth(mask)
    ridge = _ridge(depth)
    widths = (2 * depth[ridge] - 1).astype(np.float64)
    width_px = float(widths.mean())
    darkness = dark[ridge]
    sigma = max(1.0, 0.5 * width_px)
    smoothed = clones._blur(mask.astype(np.float64), sigma) > 0.5
    roughness = float((mask ^ smoothed).sum() / mask.sum())
    min_part = max(3.0, 0.5 * width_px ** 2)
    parts = sum(1 for area, _ in components(mask, eight=True) if area >= min_part)
    min_loop = max(4.0, 2.0 * width_px ** 2)
    loops = sum(1 for area, edge in components(~mask, eight=False) if not edge and area >= min_loop)

    groups = {
        "proportion": _r(math.log(elongation)),
        "layout": _share(_cells(norm, 3, 6)),
        "columns": _share(_cells(norm, 1, 16)),
        "rows": _share(_cells(norm, 8, 1)),
        "directions": _share(directions),
        "slant": _r(slant),
        "stroke_width": _r(math.log(width_px / radius)),
        "width_spread": _r(float(widths.std() / width_px)),
        "pressure": _r(float(darkness.std() / max(float(darkness.mean()), 1e-9))),
        "roughness": _r(roughness),
        "parts": _r(math.log1p(parts)),
        "loops": _r(math.log1p(loops)),
    }
    return {"version": FEATURE_VERSION, "groups": groups,
            "facts": {"radius_px": _r(radius), "line_width_px": _r(width_px), "ink_pixels": int(mask.sum()),
                      "parts": parts, "loops": loops},
            "ink_separation": separation}


# ---------------------------------------------------------------- score

def distance(kind: str, a, b) -> float:
    if kind == "histogram":
        return 0.5 * float(np.abs(np.asarray(a, dtype=np.float64) - np.asarray(b, dtype=np.float64)).sum())
    return abs(float(a) - float(b))


def compare(questioned: dict, knowns: list[dict], min_known: int) -> dict:
    """Raw score of a questioned signature against the known signatures of one writer."""
    if len(knowns) < min_known:
        raise ScoreError(f"the score needs {min_known} or more known signatures with clear ink; "
                         f"it has {len(knowns)}")
    for record in (questioned, *knowns):
        if record.get("version") != FEATURE_VERSION:
            raise ScoreError(f"the measures were made by feature version {record.get('version')}; "
                             f"this tool uses version {FEATURE_VERSION}")
    groups, logs = {}, []
    for name, (kind, _) in GROUPS.items():
        q = questioned["groups"][name]
        values = [k["groups"][name] for k in knowns]
        d = float(np.mean([distance(kind, q, v) for v in values]))
        pairs = [distance(kind, values[i], values[j]) for i in range(len(values)) for j in range(i + 1, len(values))]
        s = float(np.mean(pairs))
        ratio = (d + FLOORS[name]) / (s + FLOORS[name])
        log_ratio = max(-LOG_RATIO_LIMIT, min(LOG_RATIO_LIMIT, math.log(ratio)))
        logs.append(log_ratio)
        groups[name] = {"distance": _r(d), "spread": _r(s), "ratio": round(ratio, 4), "log_ratio": round(log_ratio, 4)}
    return {"score": round(-float(np.mean(logs)), 6), "groups": groups, "known_count": len(knowns),
            "feature_version": FEATURE_VERSION}
