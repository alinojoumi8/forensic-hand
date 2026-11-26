"""A case is a folder. Its state is rebuilt from the ledger each time: nothing else is trusted."""

from __future__ import annotations

import re
import shutil
import uuid
from datetime import date
from pathlib import Path

from . import CASE_FORMAT, TOOL_NAME, __version__
from .ledger import Ledger, LedgerError
from .store import StoreError, store_file
from .verify_case import LEDGER_NAME, ZERO_HASH, hash_file

ROLES = {"questioned": "Q", "known": "K", "other": "X"}
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class CaseError(Exception):
    """A problem that the user can fix. The message is plain language."""


def _clean(text: str | None, limit: int = 500) -> str | None:
    if text is None:
        return None
    text = _CONTROL.sub(" ", str(text)).encode("utf-8", "replace").decode("utf-8").strip()
    return text[:limit] or None


def _check_date(text: str | None) -> str | None:
    if text is None:
        return None
    if not _DATE.match(text):
        raise CaseError(f"date must look like 2021-05-03 (year-month-day), not: {text}")
    try:
        date.fromisoformat(text)
    except ValueError:
        raise CaseError(f"not a real date: {text}") from None
    return text


class Case:
    def __init__(self, path) -> None:
        self.path = Path(path)
        self.ledger = Ledger(self.path / LEDGER_NAME)

    # ------------------------------------------------------------ create / open

    @classmethod
    def create(cls, path, title: str) -> Case:
        path = Path(path)
        title = _clean(title, 200)
        if not title:
            raise CaseError("a case needs a title")
        if path.exists() and (not path.is_dir() or any(path.iterdir())):
            raise CaseError(f"the folder is not empty: {path}")
        path.mkdir(parents=True, exist_ok=True)
        for sub in ("evidence", "seals", "reports"):
            (path / sub).mkdir()
        checker = path / "verify_case.py"
        shutil.copyfile(Path(__file__).with_name("verify_case.py"), checker)
        case = cls(path)
        case.ledger.append("case.created", {
            "case_id": uuid.uuid4().hex,
            "title": title,
            "format": CASE_FORMAT,
            "tool": {"name": TOOL_NAME, "version": __version__},
            "checker_sha256": hash_file(checker)["sha256"],
        })
        return case

    @classmethod
    def open(cls, path) -> Case:
        case = cls(path)
        if not case.ledger.path.is_file():
            raise CaseError(f"not a case folder (no {LEDGER_NAME}): {path}")
        try:
            entries = case.ledger.entries()
        except LedgerError as exc:
            raise CaseError(f"the ledger is damaged: {exc}") from exc
        if not entries or entries[0]["type"] != "case.created":
            raise CaseError(f"not a case folder: {path}")
        return case

    # ------------------------------------------------------------ evidence

    def add_evidence(self, src, role: str, signer=None, doc_date=None, note=None) -> dict:
        src = Path(src)
        if role not in ROLES:
            raise CaseError(f"role must be one of: {', '.join(ROLES)}")
        doc_date = _check_date(doc_date)
        if not src.is_file():
            raise CaseError(f"file not found: {src}")
        number = 1 + sum(1 for rec in self.state()["evidence"] if rec["role"] == role)
        try:
            stored = store_file(src, self.path / "evidence")
        except StoreError as exc:
            raise CaseError(str(exc)) from exc
        except OSError as exc:
            raise CaseError(f"the file could not be copied: {exc}") from exc
        record = {
            "id": f"{ROLES[role]}{number}",
            "role": role,
            "name": _clean(src.name, 255),   # the name only: a folder path can hold private words
            **stored,
            "signer": _clean(signer),
            "doc_date": doc_date,
            "note": _clean(note),
        }
        self.ledger.append("evidence.added", record)
        return record

    def annotate(self, evidence_id: str, doc_date=None, signer=None, note=None) -> dict:
        """Correct the date, signer or note of an item. The old value stays in the ledger."""
        if evidence_id not in {rec["id"] for rec in self.state()["evidence"]}:
            raise CaseError(f"no item with the id {evidence_id}")
        changes = {}
        if doc_date is not None:
            changes["doc_date"] = _check_date(doc_date)
        if signer is not None:
            changes["signer"] = _clean(signer)
        if note is not None:
            changes["note"] = _clean(note)
        if not changes:
            raise CaseError("nothing to change")
        self.ledger.append("evidence.annotated", {"id": evidence_id, "changes": changes})
        return changes

    # ------------------------------------------------------------ state

    def state(self) -> dict:
        """Replay the ledger into the current picture of the case."""
        try:
            entries = self.ledger.entries()
        except LedgerError as exc:
            raise CaseError(f"the ledger is damaged: {exc}") from exc
        state = {
            "case_id": "", "title": "", "created": "", "tool": {},
            "evidence": [], "files": {}, "case_findings": None, "checked_at": None, "env": None,
            "seals": [],
            "ledger_count": len(entries),
            "ledger_head": entries[-1]["hash"] if entries else ZERO_HASH,
        }
        by_id: dict[str, dict] = {}
        for entry in entries:
            kind, data = entry["type"], entry["data"]
            if kind == "case.created":
                state.update(case_id=data["case_id"], title=data["title"], created=entry["time"],
                             tool=data.get("tool", {}))
            elif kind == "evidence.added":
                record = {**data, "added": entry["time"]}
                state["evidence"].append(record)
                by_id[record["id"]] = record
            elif kind == "evidence.annotated":
                if data["id"] in by_id:
                    by_id[data["id"]].update(data["changes"])
            elif kind == "env.recorded":
                state["env"] = data
            elif kind == "check.file":
                state["files"][data["evidence_id"]] = data
            elif kind == "check.case":
                state["case_findings"] = data["findings"]
                state["checked_at"] = entry["time"]
            elif kind == "seal.created":
                state["seals"].append({**data, "created": entry["time"], "timestamp": None})
            elif kind == "seal.timestamped":
                for seal in state["seals"]:
                    if seal["seal_no"] == data["seal_no"]:
                        seal["timestamp"] = data
        return state
