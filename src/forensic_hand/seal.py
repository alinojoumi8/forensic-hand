"""Seals and trusted time stamps.

A seal is a small file that names the ledger position and every evidence hash at one moment.
A time stamp authority then signs the hash of the seal file. That proves the case existed in
this state at that time, with a clock that is not ours.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat

from . import TOOL_NAME, __version__, tsa
from .ledger import utc_now
from .verify_case import OID_SHA256, parse_timestamp_response


class SealError(Exception):
    pass


def create_seal(case) -> dict:
    state = case.state()
    number = len(state["seals"]) + 1
    name = f"seals/seal-{number:04d}.json"
    path = case.path / name
    if path.exists():
        raise SealError(f"{name} exists but is not in the ledger; run the check command first")
    seq, head = case.ledger.head()
    body = {
        "kind": "forensic-hand seal",
        "format": 1,
        "case_id": state["case_id"],
        "seal_no": number,
        "ledger_seq": seq,
        "ledger_head": head,
        "evidence": [{"id": r["id"], "sha256": r["sha256"], "blake2b": r["blake2b"], "size": r["size"]}
                     for r in state["evidence"]],
        "created_claimed": utc_now(),
        "tool": {"name": TOOL_NAME, "version": __version__},
    }
    raw = (json.dumps(body, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    path.write_bytes(raw)
    os.chmod(path, stat.S_IREAD)
    digest = hashlib.sha256(raw).hexdigest()
    data = {"seal_no": number, "file": name, "sha256": digest, "ledger_seq": seq, "ledger_head": head}
    case.ledger.append("seal.created", data)
    return data


def timestamp_seal(case, seal_no: int | None = None, url: str = tsa.DEFAULT_TSA_URL, timeout: float = 20) -> dict:
    """Get a trusted time stamp for a seal. Only the hash of the seal file is sent."""
    seals = case.state()["seals"]
    if not seals:
        raise SealError("there is no seal yet; make a seal first")
    seal = seals[-1] if seal_no is None else next((s for s in seals if s["seal_no"] == seal_no), None)
    if seal is None:
        raise SealError(f"there is no seal number {seal_no}")
    if seal["timestamp"]:
        raise SealError(f"seal {seal['seal_no']} already has a time stamp")
    raw = (case.path / seal["file"]).read_bytes()
    digest = hashlib.sha256(raw)
    if digest.hexdigest() != seal["sha256"]:
        raise SealError(f"seal {seal['seal_no']}: the seal file was changed")

    try:
        reply, nonce = tsa.request_timestamp(url, digest.digest(), timeout=timeout)
    except tsa.TimestampError as exc:
        raise SealError(f"time stamp failed: {exc}") from exc
    try:
        info = parse_timestamp_response(reply)
    except ValueError as exc:
        raise SealError(f"time stamp failed: {exc}") from exc
    if not info["granted"]:
        raise SealError(f"time stamp failed: the server refused the request (status {info['status']})")
    if info["hash_oid"] != OID_SHA256 or info["imprint"] != digest.hexdigest():
        raise SealError("time stamp failed: the answer is for other data")
    if info["nonce"] != nonce:
        raise SealError("time stamp failed: the answer does not carry our random number (it can be a replay)")

    name = f"seals/seal-{seal['seal_no']:04d}.tsr"
    path = case.path / name
    path.write_bytes(reply)
    os.chmod(path, stat.S_IREAD)
    data = {
        "seal_no": seal["seal_no"], "tsa_url": url, "tsr_file": name,
        "tsr_sha256": hashlib.sha256(reply).hexdigest(),
        "gen_time": info["gen_time"], "serial": info["serial"], "policy": info["policy"],
    }
    case.ledger.append("seal.timestamped", data)
    return data
