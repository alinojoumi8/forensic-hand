"""Copy check: are two crops the same ink, point for point?

No hand repeats a signature exactly. Two crops that match almost perfectly, after the size is
made equal and small turns and shifts are allowed, fit a digital copy (cut and paste).
They also fit two scans or copies of the same piece of paper. This is a screen, not proof.

Method (fixed rules, no model):
1. Ink: pixels darker than an Otsu threshold. Darkness is kept, not only black and white.
2. Cut to the ink, and resize so that the spread of the ink is a fixed size; blur a little.
3. For each small turn: find the best shift by cross-correlation, then score the match by
   Pearson correlation. The best score over the turns is the result.
"""

from __future__ import annotations

import numpy as np
from PIL import Image

from .imaging import on_white


def otsu_threshold(gray: np.ndarray) -> float:
    hist, _ = np.histogram(gray, bins=256, range=(0, 256))
    hist = hist.astype(np.float64)
    total = hist.sum()
    if total == 0:
        return 128.0
    levels = np.arange(256, dtype=np.float64)
    weight_low = np.cumsum(hist)
    mean_low_sum = np.cumsum(hist * levels)
    weight_high = total - weight_low
    mean_total = mean_low_sum[-1]
    with np.errstate(divide="ignore", invalid="ignore"):
        between = (mean_total * weight_low / total - mean_low_sum) ** 2 / (weight_low * weight_high / total)
    between[~np.isfinite(between)] = 0
    return float(np.argmax(between)) + 0.5


def _blur(arr: np.ndarray, sigma: float) -> np.ndarray:
    if sigma <= 0:
        return arr
    radius = int(3 * sigma)
    kernel = np.exp(-0.5 * (np.arange(-radius, radius + 1) / sigma) ** 2)
    kernel /= kernel.sum()
    padded = np.pad(arr, radius)
    rows = np.apply_along_axis(lambda m: np.convolve(m, kernel, mode="valid"), 1, padded)
    return np.apply_along_axis(lambda m: np.convolve(m, kernel, mode="valid"), 0, rows)


def long_runs(mask: np.ndarray, length: int, axis: int) -> np.ndarray:
    """Pixels that belong to a straight run of ink at least `length` long, along rows (1) or columns (0)."""
    m = mask if axis == 1 else mask.T
    width = m.shape[1]
    if length < 2 or length > width:
        return np.zeros_like(mask)
    total = np.cumsum(np.pad(m.astype(np.int32), ((0, 0), (1, 0))), axis=1)
    full = (total[:, length:] - total[:, :-length]) == length          # window that starts at j is all ink
    starts = np.cumsum(np.pad(full.astype(np.int32), ((0, 0), (1, 0))), axis=1)
    j = np.arange(width)
    lo = np.clip(j - length + 1, 0, full.shape[1])
    hi = np.clip(j + 1, 0, full.shape[1])
    covered = (starts[:, hi] - starts[:, lo]) > 0
    return covered if axis == 1 else covered.T


def _edge_runs(ink: np.ndarray, length: int) -> np.ndarray:
    """Straight ink that starts at the left or right edge of the crop and is at least `length` long."""
    from_left = np.cumprod(ink, axis=1).astype(bool)
    from_right = np.cumprod(ink[:, ::-1], axis=1)[:, ::-1].astype(bool)
    keep_left = from_left.sum(axis=1) >= length
    keep_right = from_right.sum(axis=1) >= length
    return (from_left & keep_left[:, None]) | (from_right & keep_right[:, None])


def remove_ruling_lines(ink: np.ndarray, share: float) -> np.ndarray:
    """Drop long straight horizontal and vertical ink: printed signature lines, form borders, table rules.

    Also drops shorter straight pieces that run into the edge of the crop: what is left of a line
    when a pasted picture covers its middle. A straight part of a signature that is as long gets
    dropped too; that happens to both crops of a copy in the same way, so a copy still matches.
    """
    h, w = ink.shape
    lines = long_runs(ink, max(40, round(share * w)), axis=1) | long_runs(ink, max(40, round(share * h)), axis=0)
    lines |= _edge_runs(ink, max(20, round(0.04 * w)))
    lines |= _edge_runs(ink.T, max(20, round(0.04 * h))).T
    return ink & ~lines


def _drop_far_ink(weight: np.ndarray, share: float) -> np.ndarray:
    """Drop the `share` of ink mass that lies farthest from the centre of the ink.

    Small stray marks at the far ends (bits of a line, a dot) then do not change the size or
    the proportions. The cut is round, not along the page axes, so it stays the same when the
    ink is turned.
    """
    mass = weight.sum()
    if mass <= 0:
        return weight
    yy, xx = np.mgrid[0:weight.shape[0], 0:weight.shape[1]]
    cy, cx = (weight * yy).sum() / mass, (weight * xx).sum() / mass
    dist = np.hypot(yy - cy, xx - cx)
    inked = weight > 0
    order = np.argsort(dist[inked])
    cumulative = np.cumsum(weight[inked][order])
    cut = dist[inked][order][min(int(np.searchsorted(cumulative, (1 - share) * mass)), order.size - 1)]
    return np.where(dist <= cut, weight, 0.0)


def prepare(img: Image.Image, radius_px: float, min_ink: float, blur_sigma: float = 1.5,
            line_share: float = 0.30) -> dict | None:
    """Ink of a crop, ready to compare. None when there is no clear ink.

    Long straight lines are removed first. The size is made equal by the spread of the ink (its
    radius of gyration), not by the edges of the ink: noise moves an edge, but it barely moves
    the spread of all the ink.
    """
    gray = np.asarray(on_white(img).convert("L"), dtype=np.float32)
    threshold = otsu_threshold(gray)
    ink = remove_ruling_lines(gray < threshold, line_share)
    fraction = float(ink.mean())
    if fraction < min_ink or fraction > 0.6 or gray.max() - gray.min() < 40:
        return None
    # Darkness of the ink only; removed lines carry no weight.
    weight = np.clip((threshold - gray) / max(threshold, 1.0), 0, 1).astype(np.float64) * ink
    weight = _drop_far_ink(weight, 0.02)
    rows, cols = np.nonzero(weight)
    if rows.size == 0:
        return None
    dark = weight[rows.min():rows.max() + 1, cols.min():cols.max() + 1]
    mass = dark.sum()
    yy, xx = np.mgrid[0:dark.shape[0], 0:dark.shape[1]]
    cy, cx = (dark * yy).sum() / mass, (dark * xx).sum() / mass
    var_y = float((dark * (yy - cy) ** 2).sum() / mass)
    var_x = float((dark * (xx - cx) ** 2).sum() / mass)
    cov = float((dark * (xx - cx) * (yy - cy)).sum() / mass)
    radius = float(np.sqrt(var_x + var_y))
    if radius < 2:
        return None
    # Elongation from the principal axes of the ink: the same when the ink is turned.
    half_trace, spread = (var_x + var_y) / 2, np.sqrt(max(((var_x - var_y) / 2) ** 2 + cov ** 2, 0.0))
    elongation = float(np.sqrt((half_trace + spread) / max(half_trace - spread, 1e-9)))
    factor = radius_px / radius
    size = (max(8, round(dark.shape[1] * factor)), max(8, round(dark.shape[0] * factor)))
    resized = Image.fromarray(dark.astype(np.float32), mode="F").resize(size, Image.BILINEAR)
    return {"ink": _blur(np.asarray(resized, dtype=np.float64), blur_sigma), "elongation": elongation}


def _place(arr: np.ndarray, shape: tuple[int, int]) -> np.ndarray:
    out = np.zeros(shape, dtype=np.float64)
    h, w = arr.shape
    H, W = shape
    top, left = (H - h) // 2, (W - w) // 2
    src = arr[max(0, -top):max(0, -top) + min(h, H), max(0, -left):max(0, -left) + min(w, W)]
    out[max(0, top):max(0, top) + src.shape[0], max(0, left):max(0, left) + src.shape[1]] = src
    return out


def _turned(prep: dict, degrees: float) -> np.ndarray:
    """The ink turned by a small angle. Kept in the prepared item, because each item is compared many times."""
    cache = prep.setdefault("_turned", {})
    if degrees not in cache:
        cache[degrees] = prep["ink"] if degrees == 0 else np.asarray(
            Image.fromarray(prep["ink"].astype(np.float32), mode="F").rotate(degrees, resample=Image.BILINEAR,
                                                                           expand=True), dtype=np.float64)
    return cache[degrees]


def compare(prep_a: dict, prep_b: dict, rotations, max_aspect_diff: float) -> dict:
    """Best match of b onto a. Score 1.0 means the same ink, point for point.

    For each small turn of b: the best shift by plain cross-correlation (computed with FFT), then the
    Pearson correlation at that shift. Phase-only correlation was tried first: it locks onto wrong
    shifts when thin pen lines are turned even one degree, so it is not used.
    """
    # Symmetric (the order of the crops does not matter) and rotation-safe (principal axes).
    low, high = sorted((prep_a["elongation"], prep_b["elongation"]))
    if high / low - 1 > max_aspect_diff:
        return {"score": None, "reason": "the shapes have different proportions"}
    a, b = prep_a["ink"], prep_b["ink"]
    pad = max(a.shape[0], b.shape[0]) // 4
    shape = (max(a.shape[0], b.shape[0]) + 2 * pad, max(a.shape[1], b.shape[1]) + 2 * pad)
    H, W = shape
    base = _place(a, shape)
    base_c = base - base.mean()
    base_norm = float((base_c * base_c).sum())
    base_fft = np.fft.rfft2(base_c)
    best = {"score": -1.0}
    for degrees in rotations:
        moving = _place(_turned(prep_b, degrees), shape)
        moving_c = moving - moving.mean()
        peak = np.fft.irfft2(base_fft * np.conj(np.fft.rfft2(moving_c)), s=shape)
        dy, dx = np.unravel_index(int(np.argmax(peak)), shape)
        dy, dx = (dy - H if dy > H // 2 else dy), (dx - W if dx > W // 2 else dx)
        denom = np.sqrt(base_norm * float((moving_c * moving_c).sum()))
        score = float((base_c * np.roll(moving_c, (dy, dx), axis=(0, 1))).sum() / denom) if denom > 0 else 0.0
        if score > best["score"]:
            best = {"score": score, "rotation_deg": degrees, "shift_px": [int(dx), int(dy)]}
    best["score"] = round(best["score"], 4)
    return best
