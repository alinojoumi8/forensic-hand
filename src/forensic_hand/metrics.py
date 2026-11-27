"""Error-rate arithmetic for validation. Plain numpy; small enough to check by hand.

A missing score (None: the method could not compare the pair) counts as "not flagged" in rates,
and as the lowest possible score in AUC and EER.
"""

from __future__ import annotations

import math

import numpy as np

Z95 = 1.959963984540054


def wilson(k: int, n: int, z: float = Z95) -> tuple[float | None, float | None]:
    """95% Wilson score interval for k successes in n trials."""
    if n <= 0:
        return None, None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def _clean(scores) -> np.ndarray:
    return np.array([-1.0 if s is None else float(s) for s in scores], dtype=np.float64)


def rate(scores, threshold: float) -> dict:
    """Share of scores at or above the threshold, with its 95% interval."""
    n = len(scores)
    k = sum(1 for s in scores if s is not None and s >= threshold)
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else None, "ci95": [lo, hi]}


def auc(pos, neg) -> float | None:
    """Chance that a random positive scores above a random negative (ties count half)."""
    p, q = _clean(pos), _clean(neg)
    if p.size == 0 or q.size == 0:
        return None
    diff = p[:, None] - q[None, :]
    return float(((diff > 0).sum() + 0.5 * (diff == 0).sum()) / diff.size)


# ---------------------------------------------------------------- likelihood ratios (log10)

_LN10 = math.log(10)


def cllr(same_log10, diff_log10) -> float:
    """Log-likelihood-ratio cost (Brümmer and du Preez, 2006). 0 is perfect; 1 is a system that always says LR 1.

    Cllr = 1/2 [mean over same-source pairs of log2(1 + 1/LR) + mean over different-source pairs of log2(1 + LR)].
    """
    s = np.asarray(same_log10, dtype=np.float64)
    d = np.asarray(diff_log10, dtype=np.float64)
    if s.size == 0 or d.size == 0:
        raise ValueError("Cllr needs pairs of both kinds")
    # log2(1 + 10^x) = logaddexp(0, x ln 10) / ln 2, without overflow for large x.
    cost_s = np.logaddexp(0.0, -s * _LN10).mean() / math.log(2)
    cost_d = np.logaddexp(0.0, d * _LN10).mean() / math.log(2)
    return float(0.5 * (cost_s + cost_d))


def pav_log10(same_scores, diff_scores) -> tuple[np.ndarray, np.ndarray]:
    """Best monotone LRs for these scores (pool adjacent violators), each class weighted to half.

    Tied scores always share one LR. A block with only one class gets an LR of 0 or infinity.
    """
    s = np.asarray(same_scores, dtype=np.float64)
    d = np.asarray(diff_scores, dtype=np.float64)
    scores = np.concatenate([s, d])
    labels = np.concatenate([np.ones(s.size), np.zeros(d.size)])
    weights = np.concatenate([np.full(s.size, 0.5 / s.size), np.full(d.size, 0.5 / d.size)])
    _, inverse = np.unique(scores, return_inverse=True)
    w = np.bincount(inverse, weights=weights)
    hit = np.bincount(inverse, weights=weights * labels)
    blocks: list[list[float]] = []       # [weight, weighted hits, number of distinct scores]
    for wi, hi in zip(w, hit, strict=True):
        blocks.append([wi, hi, 1])
        while len(blocks) > 1 and blocks[-2][1] / blocks[-2][0] >= blocks[-1][1] / blocks[-1][0]:
            last = blocks.pop()
            blocks[-1] = [blocks[-1][0] + last[0], blocks[-1][1] + last[1], blocks[-1][2] + last[2]]
    per_value = np.concatenate([np.full(int(n), h / wt) for wt, h, n in blocks])
    with np.errstate(divide="ignore"):
        log10 = np.log10(per_value) - np.log10(1.0 - per_value)
    out = log10[inverse]
    return out[: s.size], out[s.size:]


def cllr_min(same_scores, diff_scores) -> float:
    """Cllr after the best monotone calibration: what the scores could give at most (discrimination only)."""
    return cllr(*pav_log10(same_scores, diff_scores))


def misleading(same_log10, diff_log10) -> dict:
    """Rates of misleading evidence: same-source pairs with LR below 1 (hp), different-source pairs above 1 (hd)."""
    s, d = list(same_log10), list(diff_log10)
    k_hp, k_hd = sum(1 for v in s if v < 0), sum(1 for v in d if v > 0)
    out = {}
    for side, k, n in (("hp", k_hp, len(s)), ("hd", k_hd, len(d))):
        lo, hi = wilson(k, n)
        out[side] = {"k": k, "n": n, "rate": (k / n) if n else None, "ci95": [lo, hi]}
    return out


def bootstrap(items, statistic, n: int = 1000, seed: int = 0) -> list:
    """95% interval of a statistic when whole writers are drawn again with replacement.

    items: rows whose first value is the writer. Pairs from one writer are not independent, so
    the interval comes from resampling writers, not single pairs. A resample where the statistic
    cannot be computed (it returns None) is left out. The same seed gives the same interval.
    """
    groups: dict = {}
    for row in items:
        groups.setdefault(row[0], []).append(row)
    writers = sorted(groups)
    if not writers:
        return [None, None]
    rng = np.random.default_rng(seed)
    values = []
    for _ in range(n):
        drawn = rng.integers(0, len(writers), len(writers))
        rows = [r for i in drawn for r in groups[writers[i]]]
        v = statistic(rows)
        if v is not None:
            values.append(v)
    if not values:
        return [None, None]
    return [float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5))]


def eer(pos, neg) -> dict:
    """Equal error rate: the threshold where missed positives and false alarms are about equal."""
    p, q = _clean(pos), _clean(neg)
    if p.size == 0 or q.size == 0:
        return {"eer": None, "threshold": None}
    best = None
    for t in np.unique(np.concatenate([p, q, [np.inf]])):
        miss = float((p < t).mean())
        false_alarm = float((q >= t).mean())
        gap = abs(miss - false_alarm)
        if best is None or gap < best[0] - 1e-12:
            best = (gap, (miss + false_alarm) / 2, float(t))
    return {"eer": best[1], "threshold": None if math.isinf(best[2]) else best[2]}
