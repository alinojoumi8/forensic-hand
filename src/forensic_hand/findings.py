"""One shape for every screening result.

A finding is a fact plus its limits. It is never a verdict.
  info    : a fact for the record
  notice  : look at this
  warning : this can change what the examination is able to show
"""

from __future__ import annotations

LEVELS = ("info", "notice", "warning")


def finding(code: str, level: str, title: str, detail: str = "", limits: str = "", **data) -> dict:
    if level not in LEVELS:
        raise ValueError(f"unknown level: {level}")
    if not limits:
        raise ValueError(f"finding {code} must say what it does not prove")
    return {"code": code, "level": level, "title": title, "detail": detail, "limits": limits, "data": data}


def count_levels(findings: list[dict]) -> dict:
    counts = {level: 0 for level in LEVELS}
    for item in findings:
        counts[item["level"]] += 1
    return counts
