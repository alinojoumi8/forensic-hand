"""Pass marks, written down before the test (Stage 4, phase 3).

Pre-registration: you write the pass marks, and the calibration and test data that they are for,
before you run the test. A trusted time stamp on the marks file proves when it existed. A release
(release.py) then needs a test dossier that was made with these marks and stamped after them.

What the stamps cannot prove: that nobody ran the test before the marks were written. Keep the
test data unopened until the marks are stamped.

The proposed marks (DEFAULT_MARKS) come from the Stage 4 plan. Confirm them with practising
examiners before you rely on them.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from . import TOOL_NAME, __version__, tsa
from . import verify_case as vc
from .calibrate import write_new
from .datasets import load_manifest
from .ledger import utc_now

FORMAT = 1
DEFAULT_MARKS = {
    "cllr_max": 0.5,                    # target; Cllr below 1 is the bare minimum (better than no system)
    "cllr_upper95_max": 1.0,            # with 95% confidence (writer bootstrap), better than no system
    "misleading_hp_max": 0.10,          # genuine signatures with an LR below 1
    "misleading_hp_upper95_max": 0.20,
    "misleading_hd_max": 0.05,          # pairs for Hd (forgeries) with an LR above 1
    "misleading_hd_upper95_max": 0.10,
    "min_writers": 30,
    "min_hd_pairs_per_writer": 5,       # for example 5 skilled forgeries of each writer
    "min_forgers": 2,                   # skilled forgeries by 2 or more different people
}
MARK_TEXT = {
    "cllr_max": "Cllr at most",
    "cllr_upper95_max": "upper 95% bound of Cllr (by writers) at most",
    "misleading_hp_max": "misleading evidence for Hp at most",
    "misleading_hp_upper95_max": "upper 95% bound of misleading evidence for Hp (by writers) at most",
    "misleading_hd_max": "misleading evidence for Hd at most",
    "misleading_hd_upper95_max": "upper 95% bound of misleading evidence for Hd (by writers) at most",
    "min_writers": "writers in the test at least",
    "min_hd_pairs_per_writer": "pairs for Hd of each writer at least",
    "min_forgers": "different forgers at least",
}


class PreregError(Exception):
    """The pass marks cannot be made or used. The message is plain language."""


class Criteria(dict):
    """The pass marks as read from their file. `sha256` is the hash of the exact file bytes."""

    sha256: str = ""


def _check_signature(reply: bytes, digest_hex: str, info: dict) -> tuple[str, str]:
    return vc.openssl_verify_timestamp(reply, digest_hex, info)


# ---------------------------------------------------------------- the file

def write_criteria(calibration: dict, test_manifests, marks: dict | None = None, note: str | None = None) -> dict:
    marks = dict(DEFAULT_MARKS if marks is None else marks)
    unknown = sorted(set(marks) - set(DEFAULT_MARKS))
    if unknown:
        raise PreregError(f"unknown pass mark(s): {', '.join(unknown)}; the marks are: {', '.join(DEFAULT_MARKS)}")
    missing = sorted(set(DEFAULT_MARKS) - set(marks))
    if missing:
        raise PreregError(f"pass mark(s) missing: {', '.join(missing)}")
    _check_values(marks)
    test_data = []
    for path in test_manifests:
        manifest = load_manifest(path)
        test_data.append({"title": manifest.data["title"], "manifest_sha256": manifest.manifest_sha256,
                          "synthetic": bool(manifest.data["synthetic"])})
    if not test_data:
        raise PreregError("name the test data (one manifest or more)")
    return {
        "kind": "forensic-hand pass marks", "format": FORMAT,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "calibration_sha256": calibration["results_sha256"],
        "propositions": calibration["propositions"]["id"],
        "test_data": test_data,
        "marks": marks,
        "note": note,
        "created_claimed": utc_now(),
    }


def _check_values(marks: dict) -> None:
    for name, value in marks.items():
        if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value) or value < 0:
            raise PreregError(f"the pass mark {name} must be a finite number of 0 or more, not {value!r}")


def save_criteria(body: dict, path) -> None:
    data = (json.dumps(body, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    write_new(path, data, PreregError)


def parse_criteria(raw: bytes) -> Criteria:
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PreregError(f"the pass marks file cannot be read: {exc}") from exc
    if not isinstance(body, dict) or body.get("kind") != "forensic-hand pass marks" or body.get("format") != FORMAT:
        raise PreregError("this is not a forensic-hand pass marks file (format 1)")
    marks = body.get("marks")
    if not isinstance(marks, dict) or set(marks) != set(DEFAULT_MARKS):
        raise PreregError("the pass marks file does not hold every mark")
    _check_values(marks)
    out = Criteria(body)
    out.sha256 = hashlib.sha256(raw).hexdigest()
    return out


def load_criteria(path) -> Criteria:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise PreregError(f"the pass marks file cannot be read: {exc}") from exc
    return parse_criteria(raw)


# ---------------------------------------------------------------- evaluation

def evaluate(marks: dict, lr: dict) -> list[dict]:
    """Each mark against the LR task of a dossier: value, limit and pass or fail."""
    mis = lr["misleading"]
    values = {
        "cllr_max": lr["cllr"],
        "cllr_upper95_max": lr["cllr_ci95"][1],
        "misleading_hp_max": mis["hp"]["rate"],
        "misleading_hp_upper95_max": mis["hp"]["ci95_writers"][1],
        "misleading_hd_max": mis["hd"]["rate"],
        "misleading_hd_upper95_max": mis["hd"]["ci95_writers"][1],
        "min_writers": lr["writers"],
        "min_hd_pairs_per_writer": lr["hd_pairs_min_per_writer"],
        "min_forgers": lr["forgers"],
    }
    out = []
    for name in DEFAULT_MARKS:
        limit, value = marks[name], values[name]
        if name == "min_forgers" and lr["propositions"] != "skilled-forgery":
            out.append({"mark": name, "limit": limit, "value": None, "pass": True, "text": MARK_TEXT[name],
                        "note": "does not apply: Hd is not a skilled forgery"})
            continue
        if value is None:
            passed, note = False, ("unknown: the data has no forger ids" if name == "min_forgers" else "unknown")
        else:
            passed = value >= limit if name.startswith("min_") else value <= limit
            note = None
        out.append({"mark": name, "limit": limit, "value": value, "pass": bool(passed), "text": MARK_TEXT[name],
                    "note": note})
    return out


# ---------------------------------------------------------------- time stamp of any file

def stamp_file(path, url: str = tsa.DEFAULT_TSA_URL, timeout: float = 20) -> dict:
    """Get a trusted time stamp for a file (pass marks or a dossier). Only its SHA-256 is sent.

    The answer is written next to the file as <name>.tsr. A stamp whose signature check fails is refused.
    """
    path = Path(path)
    target = path.with_name(path.name + ".tsr")
    if target.exists():
        raise PreregError(f"a time stamp exists already: {target}")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PreregError(f"the file cannot be read: {exc}") from exc
    digest = hashlib.sha256(data)
    try:
        reply, nonce = tsa.request_timestamp(url, digest.digest(), timeout=timeout)
    except tsa.TimestampError as exc:
        raise PreregError(f"time stamp failed: {exc}") from exc
    try:
        info = vc.parse_timestamp_response(reply)
    except ValueError as exc:
        raise PreregError(f"time stamp failed: {exc}") from exc
    if not info["granted"]:
        raise PreregError(f"time stamp failed: the server refused the request (status {info['status']})")
    if info["hash_oid"] != vc.OID_SHA256 or info["imprint"] != digest.hexdigest():
        raise PreregError("time stamp failed: the answer is for other data")
    if info["nonce"] != nonce:
        raise PreregError("time stamp failed: the answer does not carry our random number (it can be a replay)")
    status, detail = _check_signature(reply, digest.hexdigest(), info)
    if status == "failed":
        raise PreregError(f"time stamp refused: its signature check failed: {detail}")
    write_new(target, reply, PreregError)
    return {"file": str(target), "gen_time": info["gen_time"], "tsa_url": url,
            "signature_check": "ok" if status == "ok" else "not checked", "signature_detail": detail}
