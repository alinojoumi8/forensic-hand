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
