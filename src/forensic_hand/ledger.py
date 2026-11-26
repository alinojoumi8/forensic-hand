"""Append-only event log. Each line is chained to the line before it by a hash.

The format and the reader live in verify_case.py, so that the stand-alone checker and the app
can never disagree.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from .verify_case import ZERO_HASH, parse_ledger


class LedgerError(Exception):
    """The ledger on disk is damaged."""


def utc_now() -> str:
    """Time of this computer's clock, in UTC. This is a claim, not proof."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Ledger:
    def __init__(self, path) -> None:
        self.path = Path(path)

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        entries, errors = parse_ledger(self.path)
        if errors:
            raise LedgerError("; ".join(errors))
        return entries

    def head(self) -> tuple[int, str]:
        entries = self.entries()
        if not entries:
            return -1, ZERO_HASH
        return entries[-1]["seq"], entries[-1]["hash"]

    def append(self, type: str, data: dict, time: str | None = None) -> dict:
        """Add one event. Refuses to add to a damaged ledger. One writer at a time."""
        seq, prev = self.head()
        body = {"seq": seq + 1, "prev": prev, "time": time or utc_now(), "type": type, "data": data}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        with open(self.path, "ab") as handle:
            handle.write(digest.encode("ascii") + b" " + raw + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        return {**body, "hash": digest}
