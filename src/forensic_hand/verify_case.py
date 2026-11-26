#!/usr/bin/env python3
"""Stand-alone checker for a forensic-hand case folder.

This file uses the Python standard library only. It is short on purpose: read it before you trust it.

Usage
    python verify_case.py <case-folder> [--ca-file roots.pem] [--openssl PATH]
                                        [--skip-tsa-signature] [--json]

What it checks
    1. The ledger is an unbroken hash chain.
    2. Each evidence file has the size and the hashes that the ledger recorded.
    3. Each seal file matches the ledger, and no seal file is missing from the ledger.
    4. Each time stamp token is for its seal file. OpenSSL checks the signature of the token.

What it cannot show
    - Events removed from the END of the ledger after the last seal.
    - Whether a file was genuine before it was put into the case.

Ledger line format
    <sha256 hex> <space> <json body> <newline>
    The hash is the SHA-256 of the exact bytes of the json body.
    The body holds: seq, prev (hash of the line before), time (clock of the computer), type, data.
"""

from __future__ import annotations

import argparse
import calendar
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

LEDGER_NAME = "ledger.log"
ZERO_HASH = "0" * 64

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"

EVIDENCE_PATH = re.compile(r"^evidence/[0-9a-f]{64}\.[a-z0-9]{1,8}$")
SEAL_PATH = re.compile(r"^seals/seal-\d{4}\.json$")
TSR_PATH = re.compile(r"^seals/seal-\d{4}\.tsr$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------- hashes

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path) -> dict:
    """Return sha256, blake2b and size of a file. Reads in pieces, so large files are fine."""
    sha, b2, size = hashlib.sha256(), hashlib.blake2b(), 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            sha.update(chunk)
            b2.update(chunk)
            size += len(chunk)
    return {"sha256": sha.hexdigest(), "blake2b": b2.hexdigest(), "size": size}


# ---------------------------------------------------------------- ledger

def parse_ledger(path) -> tuple[list[dict], list[str]]:
    """Read a ledger. Return (valid entries, errors). Reading stops at the first bad line."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        return [], [f"ledger cannot be read: {exc}"]
    lines = raw.split(b"\n")
    incomplete = lines.pop() != b""
    entries: list[dict] = []
    errors: list[str] = []
    prev = ZERO_HASH
    for number, line in enumerate(lines, start=1):
        label = f"ledger line {number}"
        digest, sep, body = line.partition(b" ")
        try:
            digest_text = digest.decode("ascii")
        except UnicodeDecodeError:
            digest_text = ""
        if not sep or not HEX64.match(digest_text):
            errors.append(f"{label}: wrong format")
            break
        if sha256_hex(body) != digest_text:
            errors.append(f"{label}: content does not match its hash")
            break
        try:
            obj = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            errors.append(f"{label}: content is not valid JSON")
            break
        if not isinstance(obj, dict) or not isinstance(obj.get("type"), str) or not isinstance(obj.get("data"), dict):
            errors.append(f"{label}: content has the wrong shape")
            break
        if obj.get("seq") != number - 1:
            errors.append(f"{label}: wrong sequence number (a line was removed or moved)")
            break
        if obj.get("prev") != prev:
            errors.append(f"{label}: does not link to the line before it")
            break
        obj["hash"] = digest_text
        entries.append(obj)
        prev = digest_text
    if incomplete and not errors:
        errors.append("ledger: the last line is not complete")
    return entries, errors


# ---------------------------------------------------------------- DER (only what a time stamp needs)

def der_read(data: bytes, pos: int, end: int | None = None) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the DER element at pos."""
    end = len(data) if end is None else end
    if pos + 2 > end:
        raise ValueError("data ends too early")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise ValueError("long tags are not supported")
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise ValueError("indefinite length is not supported")
    else:
        count = first & 0x7F
        if count > 4 or pos + count > end:
            raise ValueError("bad length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    if pos + length > end:
        raise ValueError("element is longer than the data")
    return tag, pos, pos + length


def der_children(data: bytes, start: int = 0, end: int | None = None) -> list[tuple[int, int, int]]:
    """Return the elements between start and end as (tag, content_start, content_end)."""
    end = len(data) if end is None else end
    out, pos = [], start
    while pos < end:
        tag, c_start, c_end = der_read(data, pos, end)
        out.append((tag, c_start, c_end))
        pos = c_end
    return out


def der_oid(content: bytes) -> str:
    if not content:
        raise ValueError("empty object identifier")
    first = min(content[0] // 40, 2)
    parts, value = [first, content[0] - 40 * first], 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _der_int(data: bytes, item: tuple[int, int, int]) -> int:
    return int.from_bytes(data[item[1]:item[2]], "big", signed=True)


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _generalized_time(text: str) -> tuple[str, int]:
    match = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$", text)
    _expect(match is not None, "time is not in the expected form")
    y, mo, d, h, mi, s = (int(g) for g in match.groups())
    _expect(1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 61, "time is out of range")
    return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}Z", calendar.timegm((y, mo, d, h, mi, s))


def parse_timestamp_response(der: bytes) -> dict:
    """Read an RFC 3161 TimeStampResp. This reads the fields. It does NOT check the signature."""
    try:
        return _parse_tsr(bytes(der))
    except (IndexError, ValueError) as exc:
        raise ValueError(f"time stamp response cannot be read: {exc}") from None


def _parse_tsr(data: bytes) -> dict:
    tag, start, end = der_read(data, 0)
    _expect(tag == 0x30 and end == len(data), "not one complete sequence")
    top = der_children(data, start, end)
    _expect(bool(top) and top[0][0] == 0x30, "no status")
    status_parts = der_children(data, top[0][1], top[0][2])
    _expect(bool(status_parts) and status_parts[0][0] == 0x02, "no status number")
    status = _der_int(data, status_parts[0])
    info = {
        "status": status, "granted": status in (0, 1), "hash_oid": None, "imprint": None,
        "gen_time": None, "gen_time_raw": None, "gen_time_epoch": None,
        "serial": None, "policy": None, "nonce": None,
    }
    if len(top) < 2:
        _expect(not info["granted"], "granted, but there is no token")
        return info

    # TimeStampToken = ContentInfo { signedData, [0] SignedData }
    _expect(top[1][0] == 0x30, "token is not a sequence")
    content_info = der_children(data, top[1][1], top[1][2])
    _expect(len(content_info) == 2 and content_info[0][0] == 0x06 and content_info[1][0] == 0xA0,
            "token has the wrong shape")
    _expect(der_oid(data[content_info[0][1]:content_info[0][2]]) == OID_SIGNED_DATA, "token is not signed data")
    wrapped = der_children(data, content_info[1][1], content_info[1][2])
    _expect(len(wrapped) == 1 and wrapped[0][0] == 0x30, "signed data has the wrong shape")
    signed = der_children(data, wrapped[0][1], wrapped[0][2])
    # SignedData = version INTEGER, digestAlgorithms SET, encapContentInfo SEQUENCE, ...
    _expect(len(signed) >= 3 and [s[0] for s in signed[:3]] == [0x02, 0x31, 0x30], "signed data has the wrong shape")
    encap = der_children(data, signed[2][1], signed[2][2])
    _expect(len(encap) == 2 and encap[0][0] == 0x06 and encap[1][0] == 0xA0, "token has no content")
    _expect(der_oid(data[encap[0][1]:encap[0][2]]) == OID_TST_INFO, "content is not time stamp info")
    octets = der_children(data, encap[1][1], encap[1][2])
    _expect(len(octets) == 1 and octets[0][0] == 0x04, "content encoding is not supported")
    tst = data[octets[0][1]:octets[0][2]]

    # TSTInfo = version, policy, messageImprint, serialNumber, genTime, [accuracy], [ordering], [nonce], ...
    tag, start, end = der_read(tst, 0)
    _expect(tag == 0x30 and end == len(tst), "time stamp info is not one sequence")
    fields = der_children(tst, start, end)
    _expect(len(fields) >= 5 and [f[0] for f in fields[:5]] == [0x02, 0x06, 0x30, 0x02, 0x18],
            "time stamp info has the wrong shape")
    imprint = der_children(tst, fields[2][1], fields[2][2])
    _expect(len(imprint) == 2 and imprint[0][0] == 0x30 and imprint[1][0] == 0x04, "imprint has the wrong shape")
    algorithm = der_children(tst, imprint[0][1], imprint[0][2])
    _expect(bool(algorithm) and algorithm[0][0] == 0x06, "imprint has no hash name")
    raw_time = tst[fields[4][1]:fields[4][2]].decode("ascii", "replace")
    info["policy"] = der_oid(tst[fields[1][1]:fields[1][2]])
    info["hash_oid"] = der_oid(tst[algorithm[0][1]:algorithm[0][2]])
    info["imprint"] = tst[imprint[1][1]:imprint[1][2]].hex()
    info["serial"] = str(_der_int(tst, fields[3]))
    info["gen_time_raw"] = raw_time
    info["gen_time"], info["gen_time_epoch"] = _generalized_time(raw_time)
    for field in fields[5:]:
        if field[0] == 0x02:
            info["nonce"] = _der_int(tst, field)
    return info


# ---------------------------------------------------------------- OpenSSL (signature of the time stamp)

def find_openssl(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit if Path(explicit).is_file() else None
    found = shutil.which("openssl")
    if found:
        return found
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("LOCALAPPDATA")):
        for sub in ("Git/mingw64/bin/openssl.exe", "Git/usr/bin/openssl.exe", "Programs/Git/mingw64/bin/openssl.exe"):
            if base and (Path(base) / sub).is_file():
                return str(Path(base) / sub)
    return None


def export_system_roots(target: str) -> int:
    """Write the root certificates that this computer trusts to a PEM file. Return how many."""
    import ssl

    certs = ssl.create_default_context().get_ca_certs(binary_form=True)
    with open(target, "w", encoding="ascii") as handle:
        handle.writelines(ssl.DER_cert_to_PEM_cert(der) for der in certs)
    return len(certs)


def openssl_verify_timestamp(tsr_path, data_path, info: dict, ca_file=None, openssl=None) -> tuple[str, str]:
    """Check the signature of a time stamp with OpenSSL. Return (status, detail).

    status is "ok", "failed" or "unavailable".
    The certificate chain is checked at the time of the stamp, not at today's date.
    """
    exe = find_openssl(openssl)
    if exe is None:
        return "unavailable", "OpenSSL was not found (install it, or use --openssl PATH)"
    with tempfile.TemporaryDirectory() as tmp:
        if ca_file:
            roots, source = str(ca_file), f"roots from {Path(ca_file).name}"
        else:
            roots = os.path.join(tmp, "roots.pem")
            try:
                count = export_system_roots(roots)
            except OSError as exc:
                return "unavailable", f"root certificates could not be read: {exc}"
            if count == 0:
                return "unavailable", "this computer has no root certificates (use --ca-file)"
            source = "roots from the trust store of this computer"
        # Some OpenSSL installs point at a configuration file that does not exist, and then stop.
        # Give OpenSSL an empty one, so that the check does not depend on the install.
        config = os.path.join(tmp, "openssl.cnf")
        with open(config, "w", encoding="ascii") as handle:
            handle.write("# empty on purpose\n")
        env = dict(os.environ, OPENSSL_CONF=config)
        cmd = [exe, "ts", "-verify", "-in", str(tsr_path), "-data", str(data_path), "-CAfile", roots]
        if info.get("gen_time_epoch") is not None:
            cmd += ["-attime", str(info["gen_time_epoch"])]
        try:
            version = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=30, env=env, check=False)
            done = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return "unavailable", f"OpenSSL did not run: {exc}"
    text = (done.stdout + "\n" + done.stderr).strip()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    name = " ".join(version.stdout.split()[:2]) or "OpenSSL"
    if done.returncode == 0 and "Verification: OK" in text:
        return "ok", f"{name}, {source}"
    if "Verification: FAILED" in text:
        errors = [ln for ln in lines if ":error:" in ln]
        return "failed", f"{name}: {(errors[0] if errors else 'no reason given')[:300]}"
    # No verdict line: OpenSSL stopped before the check. That is a tool problem, not a bad time stamp.
    return "unavailable", f"{name} could not run the check: {(lines[-1] if lines else 'no output')[:300]}"


# ---------------------------------------------------------------- the case check

def verify_case(case_dir, ca_file=None, openssl=None, check_tsa_signature=True) -> dict:
    root = Path(case_dir)
    problems: list[str] = []
    notes: list[str] = []
    summary = {"ledger_entries": 0, "ledger_head": ZERO_HASH, "evidence_files": 0, "seals": 0, "timestamps": 0}

    def result() -> dict:
        return {"ok": not problems, "problems": problems, "notes": notes, "summary": summary}

    ledger_path = root / LEDGER_NAME
    if not ledger_path.is_file():
        problems.append(f"this folder has no {LEDGER_NAME}: it is not a case folder")
        return result()
    entries, errors = parse_ledger(ledger_path)
    problems.extend(errors)
    summary["ledger_entries"] = len(entries)
    if entries:
        summary["ledger_head"] = entries[-1]["hash"]
    if not entries or entries[0]["type"] != "case.created":
        problems.append("ledger does not start with a case.created event")

    _check_evidence(root, entries, problems, summary)
    seal_events = _check_seals(root, entries, problems, summary)
    _check_timestamps(root, entries, seal_events, problems, notes, summary,
                      ca_file, openssl, check_tsa_signature)

    if not seal_events:
        notes.append("the case has no seal yet")
    else:
        last = max(event["seq"] for event in seal_events.values())
        newer = [e for e in entries[last + 1:] if e["type"] != "seal.timestamped"]
        if newer:
            notes.append(f"{len(newer)} ledger event(s) are newer than the last seal")
    return result()


def _check_evidence(root: Path, entries: list[dict], problems: list[str], summary: dict) -> None:
    recorded: dict[str, dict] = {}
    for entry in entries:
        if entry["type"] != "evidence.added":
            continue
        data = entry["data"]
        stored = data.get("stored_as")
        if not isinstance(stored, str) or not EVIDENCE_PATH.match(stored):
            problems.append(f"evidence {data.get('id')}: the ledger holds an unsafe file path")
            continue
        slot = recorded.setdefault(stored, {"ids": [], "data": data})
        slot["ids"].append(str(data.get("id")))
    for stored, slot in sorted(recorded.items()):
        ids, data = ", ".join(slot["ids"]), slot["data"]
        path = root / stored
        if not path.is_file():
            problems.append(f"evidence {ids}: file is missing ({stored})")
            continue
        actual = hash_file(path)
        if any(actual[key] != data.get(key) for key in ("sha256", "blake2b", "size")):
            problems.append(f"evidence {ids}: file content does not match the ledger ({stored})")
            continue
        summary["evidence_files"] += 1
    folder = root / "evidence"
    if folder.is_dir():
        for path in sorted(folder.iterdir()):
            if f"evidence/{path.name}" not in recorded:
                problems.append(f"evidence folder holds a file that the ledger does not know: {path.name}")


def _check_seals(root: Path, entries: list[dict], problems: list[str], summary: dict) -> dict[int, dict]:
    seal_events: dict[int, dict] = {}
    for entry in entries:
        if entry["type"] == "seal.created":
            seal_events[entry["data"].get("seal_no")] = entry
    known_files = {event["data"].get("file") for event in seal_events.values()}
    folder = root / "seals"
    if folder.is_dir():
        for path in sorted(folder.glob("*.json")):
            if f"seals/{path.name}" not in known_files:
                problems.append(f"seal file {path.name} is not in the ledger (the ledger may be cut short)")
    for number, event in sorted(seal_events.items(), key=lambda kv: str(kv[0])):
        data = event["data"]
        name = data.get("file")
        if not isinstance(name, str) or not SEAL_PATH.match(name):
            problems.append(f"seal {number}: the ledger holds an unsafe file path")
            continue
        path = root / name
        if not path.is_file():
            problems.append(f"seal {number}: seal file is missing")
            continue
        raw = path.read_bytes()
        if sha256_hex(raw) != data.get("sha256"):
            problems.append(f"seal {number}: seal file was changed")
            continue
        try:
            body = json.loads(raw.decode("utf-8"))
            seq, head = body["ledger_seq"], body["ledger_head"]
            listed = {(item["id"], item["sha256"]) for item in body["evidence"]}
        except (ValueError, KeyError, TypeError):
            problems.append(f"seal {number}: seal file cannot be read")
            continue
        if not isinstance(seq, int) or not 0 <= seq < len(entries) or entries[seq]["hash"] != head:
            problems.append(f"seal {number}: the ledger does not match the sealed state")
            continue
        if seq != event["seq"] - 1:
            problems.append(f"seal {number}: the seal does not cover the event just before it")
            continue
        expected = {(e["data"].get("id"), e["data"].get("sha256"))
                    for e in entries[:seq + 1] if e["type"] == "evidence.added"}
        if listed != expected:
            problems.append(f"seal {number}: the evidence list in the seal does not match the ledger")
            continue
        summary["seals"] += 1
    return seal_events


def _check_timestamps(root, entries, seal_events, problems, notes, summary, ca_file, openssl, check_signature) -> None:
    stamp_events = [e for e in entries if e["type"] == "seal.timestamped"]
    known_files = {e["data"].get("tsr_file") for e in stamp_events}
    folder = root / "seals"
    if folder.is_dir():
        for path in sorted(folder.glob("*.tsr")):
            if f"seals/{path.name}" not in known_files:
                problems.append(f"time stamp file {path.name} is not in the ledger (the ledger may be cut short)")
    for event in stamp_events:
        data = event["data"]
        number, name = data.get("seal_no"), data.get("tsr_file")
        seal_event = seal_events.get(number)
        if not isinstance(name, str) or not TSR_PATH.match(name) or seal_event is None:
            problems.append(f"seal {number}: the time stamp record in the ledger is not valid")
            continue
        path = root / name
        if not path.is_file():
            problems.append(f"seal {number}: time stamp file is missing")
            continue
        raw = path.read_bytes()
        if sha256_hex(raw) != data.get("tsr_sha256"):
            problems.append(f"seal {number}: time stamp file was changed")
            continue
        try:
            info = parse_timestamp_response(raw)
        except ValueError as exc:
            problems.append(f"seal {number}: {exc}")
            continue
        seal_hash = seal_event["data"].get("sha256")
        if not info["granted"] or info["hash_oid"] != OID_SHA256 or info["imprint"] != seal_hash:
            problems.append(f"seal {number}: the time stamp is not for this seal file")
            continue
        if info["gen_time"] != data.get("gen_time"):
            problems.append(f"seal {number}: the time in the ledger is not the time in the time stamp")
            continue
        summary["timestamps"] += 1
        if not check_signature:
            notes.append(f"seal {number}: time stamp says {info['gen_time']}; its signature was not checked (skipped)")
            continue
        seal_path = root / seal_event["data"]["file"]
        status, detail = openssl_verify_timestamp(path, seal_path, info, ca_file, openssl)
        if status == "ok":
            notes.append(f"seal {number}: time stamp {info['gen_time']} has a valid signature ({detail})")
        elif status == "failed":
            problems.append(f"seal {number}: time stamp signature check FAILED: {detail}")
        else:
            notes.append(f"seal {number}: time stamp says {info['gen_time']}; its signature was not checked: {detail}")


# ---------------------------------------------------------------- command line

def _say(text: str) -> None:
    sys.stdout.write(text.encode("ascii", "backslashreplace").decode("ascii") + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verify_case", description="Check a forensic-hand case folder.")
    parser.add_argument("case", help="the case folder")
    parser.add_argument("--ca-file", help="PEM file with the root certificates that you trust")
    parser.add_argument("--openssl", help="path to the OpenSSL program")
    parser.add_argument("--skip-tsa-signature", action="store_true", help="do not run OpenSSL")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)

    outcome = verify_case(args.case, ca_file=args.ca_file, openssl=args.openssl,
                          check_tsa_signature=not args.skip_tsa_signature)
    if args.json:
        _say(json.dumps(outcome, indent=2, sort_keys=True))
        return 0 if outcome["ok"] else 1
    info = outcome["summary"]
    _say("forensic-hand case check")
    _say(f"Folder:         {args.case}")
    _say(f"Ledger:         {info['ledger_entries']} event(s), head {info['ledger_head']}")
    _say(f"Evidence files: {info['evidence_files']} match the ledger")
    _say(f"Seals:          {info['seals']} valid, {info['timestamps']} with a time stamp for the seal")
    for note in outcome["notes"]:
        _say(f"NOTE:    {note}")
    for problem in outcome["problems"]:
        _say(f"PROBLEM: {problem}")
    _say("RESULT: OK" if outcome["ok"] else "RESULT: PROBLEMS FOUND")
    _say("Limit: events removed from the end of the ledger after the last seal cannot be seen.")
    return 0 if outcome["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
