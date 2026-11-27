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

import math

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


def remove_ruling_lines(ink: np.ndarray, share: float, fixed_minimum: bool = True) -> np.ndarray:
    """Drop long straight horizontal and vertical ink: printed signature lines, form borders, table rules.

    Also drops shorter straight pieces that run into the edge of the crop: what is left of a line
    when a pasted picture covers its middle. A straight part of a signature that is as long gets
    dropped too; that happens to both crops of a copy in the same way, so a copy still matches.

    The lengths are shares of the crop size. The copy check also keeps fixed minimums (40 and 20
    pixels). With fixed_minimum=False the rule is relative only, so a crop and the same crop at twice
    the resolution lose the same ink (the writer score needs that).
    """
    h, w = ink.shape
    run_min, edge_min = (40, 20) if fixed_minimum else (2, 2)
    lines = (long_runs(ink, max(run_min, round(share * w)), axis=1)
             | long_runs(ink, max(run_min, round(share * h)), axis=0))
    lines |= _edge_runs(ink, max(edge_min, round(0.04 * w)))
    lines |= _edge_runs(ink.T, max(edge_min, round(0.04 * h))).T
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


def rgb_to_lab(rgb: np.ndarray) -> np.ndarray:
    """sRGB (0 to 255) to CIE Lab (D65): lightness L (0 to 100) and the colour axes a (green-red), b (blue-yellow)."""
    c = np.asarray(rgb, dtype=np.float64) / 255.0
    lin = np.where(c <= 0.04045, c / 12.92, ((c + 0.055) / 1.055) ** 2.4)
    m = np.array([[0.4124564, 0.3575761, 0.1804375], [0.2126729, 0.7151522, 0.0721750],
                  [0.0193339, 0.1191920, 0.9503041]])
    xyz = lin @ m.T / np.array([0.95047, 1.0, 1.08883])
    f = np.where(xyz > 0.008856, np.cbrt(xyz), 7.787 * xyz + 16 / 116)
    return np.stack([116 * f[..., 1] - 16, 500 * (f[..., 0] - f[..., 1]), 200 * (f[..., 1] - f[..., 2])], axis=-1)


NEUTRAL_CHROMA, CHROMATIC_CHROMA = 10.0, 20.0


def _two_inks(c1: np.ndarray, c2: np.ndarray, hue_deg: float) -> bool:
    """Do two ink colours (centres in the a,b plane) differ in hue, not only in strength?

    The faint edge of a blue line is a weaker blue: same hue, lower chroma. That is one ink.
    A neutral (black or grey) ink beside a coloured ink, or two clearly different hues, are two inks.
    """
    ch1, ch2 = float(np.hypot(*c1)), float(np.hypot(*c2))
    if min(ch1, ch2) < NEUTRAL_CHROMA:
        return max(ch1, ch2) > CHROMATIC_CHROMA
    diff = abs(math.degrees(math.atan2(c1[1], c1[0]) - math.atan2(c2[1], c2[0]))) % 360
    return min(diff, 360 - diff) >= hue_deg


def separate_inks(img: Image.Image, hue_deg: float = 15.0, min_share: float = 0.05) -> tuple[np.ndarray, dict]:
    """Grey picture of the pen ink only, when a second ink (a stamp) of another colour is present.

    1. Ink pixels: darker than an Otsu threshold on lightness.
    2. Two groups by colour (2-means in the a,b plane). Two inks only if the hues differ (see _two_inks)
       and the smaller group holds at least `min_share` of the ink.
    3. The pen is the group with the darker core (10th percentile of lightness): a pen line is usually
       darker than a stamp. A very dark stamp, or a crop with printed text, can break this rule: the
       record says which colour was kept, so the examiner can check.
    4. Pixels of the other ink's colour that are not darker than that ink (overlaps keep the pen) become paper.
    A grey picture, or one ink only, gives exactly the plain grey conversion.
    """
    rgb = np.asarray(img.convert("RGB"))
    gray = np.asarray(img.convert("L"), dtype=np.float32)
    spread = rgb.max(axis=2).astype(np.int16) - rgb.min(axis=2).astype(np.int16)
    if int(spread.max(initial=0)) < 12:
        return gray, {"inks": 1, "reason": "no colour"}
    lab = rgb_to_lab(rgb)
    light = lab[..., 0]
    ink = light < otsu_threshold(np.clip(light * 2.55, 0, 255)) / 2.55
    n = int(ink.sum())
    if n < 50:
        return gray, {"inks": 1, "reason": "too little ink"}
    ab = lab[..., 1:][ink]
    sample = ab[:: max(1, n // 20000)]
    chroma = np.hypot(sample[:, 0], sample[:, 1])
    centers = np.array([sample[np.argsort(chroma)[: max(1, len(sample) // 10)]].mean(axis=0), np.zeros(2)])
    centers[1] = sample[int(np.argmax(np.hypot(*(sample - centers[0]).T)))]
    for _ in range(15):
        labels = np.argmin(np.stack([np.hypot(*(sample - c).T) for c in centers]), axis=0)
        if labels.min() == labels.max():
            return gray, {"inks": 1, "reason": "one colour"}
        centers = np.array([sample[labels == k].mean(axis=0) for k in (0, 1)])
    full = np.argmin(np.stack([np.hypot(*(ab - c).T) for c in centers]), axis=0)
    share = float(min((full == 0).mean(), (full == 1).mean()))
    if share < min_share or not _two_inks(centers[0], centers[1], hue_deg):
        return gray, {"inks": 1, "reason": "one hue"}
    ink_light = light[ink]
    # Judge darkness only from pixels close to their own ink colour: where the pen crosses the stamp,
    # mixed pixels lie between the two colours and would make the stamp look darker than it is.
    gap = float(np.hypot(*(centers[0] - centers[1])))
    near = [np.hypot(*(ab - centers[k]).T) < 0.35 * gap for k in (0, 1)]
    cores = [float(np.percentile(ink_light[(full == k) & near[k]] if (near[k] & (full == k)).any()
                                 else ink_light[full == k], 10)) for k in (0, 1)]
    pen = int(np.argmin(cores))
    other = 1 - pen
    cp, co = centers[pen], centers[other]
    direction = co - cp
    t = ((lab[..., 1:] - cp) @ direction) / float(direction @ direction)
    other_light = float(np.median(ink_light[full == other]))
    remove = (t > 0.5) & (light >= other_light - 10)
    out = gray.copy()
    out[remove] = float(np.percentile(gray, 90))
    ink_rgb = rgb[ink]
    return out, {"inks": 2, "kept_rgb": [int(v) for v in ink_rgb[full == pen].mean(axis=0).round()],
                 "removed_rgb": [int(v) for v in ink_rgb[full == other].mean(axis=0).round()],
                 "removed_share": round(float(remove[ink].mean()), 4)}


def ink_weight(img: Image.Image, min_ink: float, line_share: float = 0.30, separate: bool = True,
               hue_deg: float = 15.0, fixed_minimum: bool = True) -> tuple[np.ndarray, dict] | None:
    """Darkness of the pen ink (0 to 1), cut to the ink. None when there is no clear ink.

    A second ink of another colour (a stamp) is removed first, then long straight lines, then the
    2% of ink farthest from the centre. The copy check and the writer score both start here; the
    writer score passes fixed_minimum=False (see remove_ruling_lines).
    """
    paper = on_white(img)
    if separate:
        gray, separation = separate_inks(paper, hue_deg)
    else:
        gray, separation = np.asarray(paper.convert("L"), dtype=np.float32), {"inks": None, "reason": "off"}
    threshold = otsu_threshold(gray)
    ink = remove_ruling_lines(gray < threshold, line_share, fixed_minimum)
    fraction = float(ink.mean())
    if fraction < min_ink or fraction > 0.6 or gray.max() - gray.min() < 40:
        return None
    # Darkness of the ink only; removed lines carry no weight.
    weight = np.clip((threshold - gray) / max(threshold, 1.0), 0, 1).astype(np.float64) * ink
    weight = _drop_far_ink(weight, 0.02)
    rows, cols = np.nonzero(weight)
    if rows.size == 0:
        return None
    return weight[rows.min():rows.max() + 1, cols.min():cols.max() + 1], separation


def prepare(img: Image.Image, radius_px: float, min_ink: float, blur_sigma: float = 1.5,
            line_share: float = 0.30, separate: bool = True, hue_deg: float = 15.0) -> dict | None:
    """Ink of a crop, ready to compare. None when there is no clear ink.

    A second ink of another colour (a stamp) is removed first, then long straight lines. The size
    is made equal by the spread of the ink (its radius of gyration), not by the edges of the ink:
    noise moves an edge, but it barely moves the spread of all the ink.
    """
    cut = ink_weight(img, min_ink, line_share, separate, hue_deg)
    if cut is None:
        return None
    dark, separation = cut
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
    return {"ink": _blur(np.asarray(resized, dtype=np.float64), blur_sigma), "elongation": elongation,
            "ink_separation": separation}


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
