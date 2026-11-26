"""Seals and trusted time stamps.

A seal is a small file that names the ledger position and every evidence hash at one moment.
A time stamp authority then signs the hash of the seal file. That proves the case existed in
this state at that time, with a clock that is not ours.

Each step writes its file first and its ledger event second. If the ledger event is not written,
the file is removed. If a run stopped hard between the two, the next run takes over the file
when it still matches, and refuses when it does not (that can mean the ledger was cut short).
"""

from __future__ import annotations

import hashlib
import json
import os
import stat

from . import TOOL_NAME, __version__, tsa
from . import verify_case as vc
from .ledger import LedgerError, utc_now
from .verify_case import OID_SHA256, parse_timestamp_response


class SealError(Exception):
    pass


# ---------------------------------------------------------------- file helpers

def _write_read_only(path, data: bytes) -> None:
    path.write_bytes(data)
    os.chmod(path, stat.S_IREAD)


def _remove(path) -> None:
    if path.exists():
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        path.unlink()


def _last_event_is(case, kind: str, data: dict) -> bool | None:
    """True or False: is the newest ledger event this one? None when the ledger cannot be read."""
    try:
        entries = case.ledger.entries()
    except LedgerError:
        return None
    return bool(entries) and entries[-1]["type"] == kind and entries[-1]["data"] == data


def _append_or_undo(case, kind: str, data: dict, path, wrote_file: bool) -> None:
    """Add the ledger event. If that fails and the event is surely not there, remove the new file."""
    try:
        case.ledger.append(kind, data)
    except BaseException as exc:
        if wrote_file and _last_event_is(case, kind, data) is False:
            _remove(path)
        if isinstance(exc, Exception):
            raise SealError(f"the {kind} event could not be written to the ledger: {exc}") from exc
        raise


# ---------------------------------------------------------------- seal

def seal_bytes(state: dict, number: int, seq: int, head: str) -> bytes:
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
    return (json.dumps(body, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def _matches_present_state(raw: bytes, state: dict, number: int, seq: int, head: str) -> bool:
    try:
        body = json.loads(raw.decode("utf-8"))
        listed = [(e["id"], e["sha256"], e["blake2b"], e["size"]) for e in body["evidence"]]
    except (ValueError, KeyError, TypeError):
        return False
    expected = [(r["id"], r["sha256"], r["blake2b"], r["size"]) for r in state["evidence"]]
    return (body.get("seal_no") == number and body.get("ledger_seq") == seq and body.get("ledger_head") == head
            and body.get("case_id") == state["case_id"] and listed == expected)


def create_seal(case) -> dict:
    state = case.state()
    number = len(state["seals"]) + 1
    name = f"seals/seal-{number:04d}.json"
    path = case.path / name
    seq, head = case.ledger.head()
    if path.exists():
        # Left by a run that stopped before it wrote the ledger. Take it over only if it is exact.
        raw = path.read_bytes()
        if not _matches_present_state(raw, state, number, seq, head):
            raise SealError(f"{name} exists but is not in the ledger, and it does not match the present case. "
                            "This can mean that the ledger was cut short. Run: fhand verify <case>")
        os.chmod(path, stat.S_IREAD)
        wrote = False
    else:
        raw = seal_bytes(state, number, seq, head)
        _write_read_only(path, raw)
        wrote = True
    data = {"seal_no": number, "file": name, "sha256": hashlib.sha256(raw).hexdigest(),
            "ledger_seq": seq, "ledger_head": head}
    _append_or_undo(case, "seal.created", data, path, wrote)
    return data


# ---------------------------------------------------------------- time stamp

def _check_signature(reply: bytes, digest_hex: str, info: dict, ca_file=None, openssl=None) -> tuple[str, str]:
    """Check the signature of the time stamp with OpenSSL (RFC 3161 asks the requester to do this)."""
    return vc.openssl_verify_timestamp(reply, digest_hex, info, ca_file, openssl)


def _read_reply(reply: bytes, digest_hex: str) -> dict:
    try:
        info = parse_timestamp_response(reply)
    except ValueError as exc:
        raise SealError(f"time stamp failed: {exc}") from exc
    if not info["granted"]:
        raise SealError(f"time stamp failed: the server refused the request (status {info['status']})")
    if info["hash_oid"] != OID_SHA256 or info["imprint"] != digest_hex:
        raise SealError("time stamp failed: the answer is for other data")
    return info


def timestamp_seal(case, seal_no: int | None = None, url: str = tsa.DEFAULT_TSA_URL, timeout: float = 20,
                   check_signature: bool = True, ca_file=None, openssl=None) -> dict:
    """Get a trusted time stamp for a seal. Only the hash of the seal file is sent.

    The signature of the answer is checked before it is recorded. A bad signature is refused.
    When the check cannot run (no OpenSSL), the stamp is recorded as "not checked", never as checked.
    """
    seals = case.state()["seals"]
    if not seals:
        raise SealError("there is no seal yet; make a seal first")
    seal = seals[-1] if seal_no is None else next((s for s in seals if s["seal_no"] == seal_no), None)
    if seal is None:
        raise SealError(f"there is no seal number {seal_no}")
    if seal["timestamp"]:
        raise SealError(f"seal {seal['seal_no']} already has a time stamp")
    digest = hashlib.sha256((case.path / seal["file"]).read_bytes())
    if digest.hexdigest() != seal["sha256"]:
        raise SealError(f"seal {seal['seal_no']}: the seal file was changed")

    name = f"seals/seal-{seal['seal_no']:04d}.tsr"
    path = case.path / name
    recovered = path.exists()
    if recovered:
        # Left by a run that stopped before it wrote the ledger. Our random number is lost,
        # so take the file over only if it is for this seal and its signature does not fail.
        reply = path.read_bytes()
        try:
            info = _read_reply(reply, digest.hexdigest())
        except SealError as exc:
            raise SealError(f"{name} exists but is not in the ledger, and it is not a time stamp for this seal "
                            f"({exc}). This can mean that the ledger was cut short. Run: fhand verify <case>") from exc
    else:
        try:
            reply, nonce = tsa.request_timestamp(url, digest.digest(), timeout=timeout)
        except tsa.TimestampError as exc:
            raise SealError(f"time stamp failed: {exc}") from exc
        info = _read_reply(reply, digest.hexdigest())
        if info["nonce"] != nonce:
            raise SealError("time stamp failed: the answer does not carry our random number (it can be a replay)")

    if check_signature:
        status, detail = _check_signature(reply, digest.hexdigest(), info, ca_file, openssl)
    else:
        status, detail = "skipped", "not asked for"
    if status == "failed":
        raise SealError(f"time stamp refused: its signature check failed: {detail}")

    if recovered:
        os.chmod(path, stat.S_IREAD)
    else:
        _write_read_only(path, reply)
    data = {
        "seal_no": seal["seal_no"], "tsa_url": url, "tsr_file": name,
        "tsr_sha256": hashlib.sha256(reply).hexdigest(),
        "gen_time": info["gen_time"], "serial": info["serial"], "policy": info["policy"],
        "signature_check": "ok" if status == "ok" else "not checked",
        "signature_detail": detail,
        "recovered_from_earlier_run": recovered,
    }
    _append_or_undo(case, "seal.timestamped", data, path, not recovered)
    return data
