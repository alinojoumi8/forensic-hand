"""Release: the only way a calibration can become usable in a case (Stage 4, phase 3).

A release checks, and refuses on any failure:
1. The calibration is complete and unchanged, and was fitted on real data (never "demo").
2. The pass marks name this calibration, and their time stamp is valid and signed.
3. The dossier is complete and unchanged; it tested this calibration, on the data that the pass
   marks named, for the use "publish"; it was made with these pass marks; and no writer of the
   test was used to calibrate.
4. The dossier's time stamp is valid, signed, and later than the stamp of the pass marks.
5. Every pass mark passed.

The release file holds the exact bytes of all five files, so that anyone can run the same checks
again (check_release). The checks stop mistakes and shortcuts. They cannot stop a person who fakes
the test data: the dossier names the data by hash, so another party can ask for it and test again.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from . import TOOL_NAME, __version__, prereg
from . import calibrate as cal
from . import verify_case as vc
from .ledger import utc_now

FORMAT = 1
FILES = ("calibration.json", "criteria.json", "criteria.json.tsr", "dossier.json", "dossier.json.tsr")


class ReleaseError(Exception):
    """The calibration cannot be released or used. The message is plain language."""


def _check_signature(reply: bytes, digest_hex: str, info: dict) -> tuple[str, str]:
    return vc.openssl_verify_timestamp(reply, digest_hex, info)


def _stamp(name: str, data: bytes, reply: bytes, problems: list[str]) -> dict | None:
    """Facts of a time stamp for these bytes, or None (with the problem noted)."""
    try:
        info = vc.parse_timestamp_response(reply)
    except ValueError as exc:
        problems.append(f"the time stamp of the {name} cannot be read: {exc}")
        return None
    if not info["granted"]:
        problems.append(f"the time stamp of the {name} was not granted")
        return None
    digest = hashlib.sha256(data).hexdigest()
    if info["hash_oid"] != vc.OID_SHA256 or info["imprint"] != digest:
        problems.append(f"the {name} file was changed after its time stamp (or the stamp is for other data)")
        return None
    status, detail = _check_signature(reply, digest, info)
    if status != "ok":
        problems.append(f"the signature of the {name} time stamp could not be checked as valid ({status}: {detail})")
        return None
    return {"gen_time": info["gen_time"], "epoch": info["gen_time_epoch"], "serial": info["serial"],
            "policy": info["policy"], "signature": detail}


def _check_files(files: dict[str, bytes]) -> tuple[list[str], dict]:
    from .validation import _results_hash

    problems: list[str] = []
    facts: dict = {}

    # 1. The calibration.
    try:
        calibration = json.loads(files["calibration.json"].decode("utf-8"))
        cal.check(calibration)
    except (UnicodeDecodeError, ValueError, cal.CalibrationError) as exc:
        return [f"the calibration cannot be used: {exc}"], facts
    facts["calibration"] = calibration
    if calibration["status"] == "demo" or any(d.get("synthetic") for d in calibration["data"]["datasets"]):
        problems.append("the calibration was fitted on synthetic data (a demo); it can never be released")
    elif calibration["status"] != "candidate":
        problems.append(f"the calibration has the status '{calibration['status']}'; only a candidate can be released")

    # 2. The pass marks and their stamp.
    try:
        criteria = prereg.parse_criteria(files["criteria.json"])
    except prereg.PreregError as exc:
        return [*problems, str(exc)], facts
    if criteria["calibration_sha256"] != calibration["results_sha256"]:
        problems.append("the pass marks do not name this calibration")
    if criteria["propositions"] != calibration["propositions"]["id"]:
        problems.append("the pass marks are for other propositions")
    criteria_stamp = _stamp("pass-marks", files["criteria.json"], files["criteria.json.tsr"], problems)

    # 3. The dossier.
    try:
        dossier = json.loads(files["dossier.json"].decode("utf-8"))
        if dossier.get("kind") != "forensic-hand validation dossier":
            raise ValueError("this is not a validation dossier")
        unchanged = _results_hash(dossier) == dossier["results_sha256"]
    except (UnicodeDecodeError, ValueError, KeyError, TypeError) as exc:
        return [*problems, f"the dossier cannot be read: {exc}"], facts
    if not unchanged:
        problems.append("the dossier was changed after it was made (its results hash does not match)")
    if dossier.get("purpose") != "publish":
        problems.append(f"the dossier was made for the use '{dossier.get('purpose')}'; a release needs a test whose "
                        "licence and consent allow publish (validate --purpose publish)")
    datasets = dossier.get("datasets") or []
    if any(d.get("synthetic") for d in datasets):
        problems.append("the test used synthetic data")
    tested = sorted(d.get("manifest_sha256") for d in datasets)
    if tested != sorted(d["manifest_sha256"] for d in criteria["test_data"]):
        problems.append("the dossier tested other data than the pass marks named (pre-registered)")
    marks_record = dossier.get("pass_marks") or {}
    if marks_record.get("criteria_sha256") != criteria.sha256:
        problems.append("the dossier was not made with these pass marks (validate --criteria)")
    lr = (dossier.get("tasks") or {}).get("lr")
    results = []
    if not isinstance(lr, dict) or lr.get("skipped"):
        problems.append("the dossier holds no likelihood-ratio test (validate --calibration)")
    else:
        if lr.get("calibration_sha256") != calibration["results_sha256"]:
            problems.append("the dossier tested another calibration")
        if lr.get("writers_overlap"):
            problems.append(f"{len(lr['writers_overlap'])} writer(s) of the test were also used to calibrate")
        try:
            results = prereg.evaluate(criteria["marks"], lr)
        except (KeyError, TypeError, IndexError) as exc:
            problems.append(f"the likelihood-ratio test in the dossier is not complete: {exc}")
        for r in results:
            if not r["pass"]:
                problems.append(f"pass mark {r['mark']} failed: {r['value'] if r['value'] is not None else r['note']} "
                                f"({r['text']} {r['limit']})")
    dossier_stamp = _stamp("dossier", files["dossier.json"], files["dossier.json.tsr"], problems)

    # 4. The order of the stamps.
    if criteria_stamp and dossier_stamp and not dossier_stamp["epoch"] > criteria_stamp["epoch"]:
        problems.append(f"the test was time stamped ({dossier_stamp['gen_time']}) before the pass marks "
                        f"({criteria_stamp['gen_time']}), or at the same second")
    facts.update({"criteria_sha256": criteria.sha256, "criteria_stamp": criteria_stamp,
                  "dossier_sha256": hashlib.sha256(files["dossier.json"]).hexdigest(),
                  "dossier_stamp": dossier_stamp, "marks": results,
                  "summary": None if not isinstance(lr, dict) or lr.get("skipped") else {
                      "cllr": lr["cllr"], "cllr_ci95": lr["cllr_ci95"], "misleading": lr["misleading"],
                      "pairs": lr["pairs"], "writers": lr["writers"], "strata": lr["strata"]}})
    return problems, facts


def _refuse(problems: list[str]) -> ReleaseError:
    return ReleaseError("the calibration cannot be released:\n- " + "\n- ".join(problems))


def make_release(calibration_path, criteria_path, dossier_path, criteria_tsr=None, dossier_tsr=None) -> dict:
    paths = {"calibration.json": Path(calibration_path), "criteria.json": Path(criteria_path),
             "criteria.json.tsr": Path(criteria_tsr or f"{criteria_path}.tsr"), "dossier.json": Path(dossier_path),
             "dossier.json.tsr": Path(dossier_tsr or f"{dossier_path}.tsr")}
    files = {}
    for name, path in paths.items():
        try:
            files[name] = path.read_bytes()
        except OSError as exc:
            raise ReleaseError(f"the file for {name} cannot be read ({path}): {exc}") from exc
    problems, facts = _check_files(files)
    if problems:
        raise _refuse(problems)
    return {
        "kind": "forensic-hand released calibration", "format": FORMAT, "status": "released",
        "tool": {"name": TOOL_NAME, "version": __version__},
        "calibration": facts["calibration"],
        "files": {name: base64.b64encode(files[name]).decode("ascii") for name in FILES},
        "facts": {k: v for k, v in facts.items() if k != "calibration"},
        "released_claimed": utc_now(),
    }


def check_release(bundle) -> dict:
    """Run every release check again from the bytes inside a release file. Return the facts."""
    if not isinstance(bundle, dict) or bundle.get("kind") != "forensic-hand released calibration" \
            or bundle.get("format") != FORMAT or bundle.get("status") != "released":
        raise ReleaseError("this is not a forensic-hand released calibration (format 1)")
    try:
        files = {name: base64.b64decode(bundle["files"][name], validate=True) for name in FILES}
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseError(f"the release file is not complete: {exc}") from exc
    problems, facts = _check_files(files)
    if problems:
        raise _refuse(problems)
    if bundle.get("calibration") != facts["calibration"]:
        raise ReleaseError("the release file was changed: its calibration does not match the calibration file inside")
    return facts


def save_release(bundle: dict, path) -> None:
    data = (json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    cal.write_new(path, data, ReleaseError)


def load_release(path) -> dict:
    try:
        bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReleaseError(f"the release file cannot be read: {exc}") from exc
    check_release(bundle)
    return bundle
