"""Append-only event log. Each line is chained to the line before it by a hash.

The format and the reader live in verify_case.py, so that the stand-alone checker and the app
can never disagree.

One writer at a time: `Ledger.lock()` holds a lock for the threads of this program (the
workbench server) and an operating-system lock on `ledger.lock` for other programs (the CLI).
The same thread can take the lock again, so a step can hold it across read, store and append.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path

from .verify_case import ZERO_HASH, parse_ledger

LOCK_NAME = "ledger.lock"


class LedgerError(Exception):
    """The ledger on disk is damaged, or it is locked by another program for too long."""


def utc_now() -> str:
    """Time of this computer's clock, in UTC. This is a claim, not proof."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _os_lock(handle) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)   # retries for about 10 seconds
        except OSError as exc:
            raise LedgerError("the case is busy: another program is writing to it") from exc
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _os_unlock(handle) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class _PathLock:
    """A lock for one ledger file: re-entrant for a thread, exclusive across threads and programs."""

    def __init__(self, lock_path: Path) -> None:
        self.lock_path = lock_path
        self.rlock = threading.RLock()
        self.depth = 0
        self.handle = None

    def __enter__(self):
        self.rlock.acquire()
        try:
            if self.depth == 0:
                handle = open(self.lock_path, "a+b")
                try:
                    _os_lock(handle)
                except BaseException:
                    handle.close()
                    raise
                self.handle = handle
            self.depth += 1
        except BaseException:
            self.rlock.release()
            raise
        return self

    def __exit__(self, *exc) -> None:
        try:
            self.depth -= 1
            if self.depth == 0:
                handle, self.handle = self.handle, None
                try:
                    _os_unlock(handle)
                finally:
                    handle.close()
        finally:
            self.rlock.release()


_LOCKS: dict[str, _PathLock] = {}
_LOCKS_GUARD = threading.Lock()


class Ledger:
    def __init__(self, path) -> None:
        self.path = Path(path)
        key = os.path.normcase(str(self.path.resolve()))
        with _LOCKS_GUARD:
            self._lock = _LOCKS.setdefault(key, _PathLock(self.path.with_name(LOCK_NAME)))

    def lock(self) -> _PathLock:
        return self._lock

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
        """Add one event. Refuses to add to a damaged ledger."""
        with self._lock:
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
