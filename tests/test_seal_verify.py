from __future__ import annotations

import hashlib
import json
import os
import stat
import sys

import pytest
from conftest import fake_tsr

from forensic_hand import tsa
from forensic_hand import verify_case as vc
from forensic_hand.seal import SealError, create_seal, timestamp_seal


def _verify(case, **kw):
    kw.setdefault("check_tsa_signature", False)
    return vc.verify_case(case.path, **kw)


def _writable(path):
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)


def _fake_tsa(monkeypatch, *, digest_override=None, nonce_shift=0, status="granted"):
    def request(url, digest, timeout=20):
        nonce = 990001
        return fake_tsr(digest_override or digest, nonce + nonce_shift, status=status), nonce
    monkeypatch.setattr(tsa, "request_timestamp", request)


# ------------------------------------------------------------ seal

def test_a_fresh_sealed_case_verifies(case):
    seal = create_seal(case)
    result = _verify(case)
    assert seal["seal_no"] == 1
    assert result["ok"] is True and result["problems"] == []
    assert result["summary"]["evidence_files"] == 3
    assert result["summary"]["seals"] == 1


def test_the_seal_lists_every_evidence_hash_and_the_ledger_head(case):
    seal = create_seal(case)
    raw = (case.path / seal["file"]).read_bytes()
    body = json.loads(raw)
    entries = case.ledger.entries()
    assert {e["id"] for e in body["evidence"]} == {"Q1", "K1", "K2"}
    assert body["ledger_head"] == entries[body["ledger_seq"]]["hash"]
    assert entries[-1]["type"] == "seal.created"
    assert entries[-1]["data"]["sha256"] == hashlib.sha256(raw).hexdigest() == seal["sha256"]


def test_a_case_with_no_seal_verifies_with_a_note(case):
    result = _verify(case)
    assert result["ok"] is True
    assert any("seal" in n.lower() for n in result["notes"])


def test_a_second_seal_gets_the_next_number(case):
    create_seal(case)
    assert create_seal(case)["seal_no"] == 2
    assert _verify(case)["summary"]["seals"] == 2


# ------------------------------------------------------------ tamper detection

def test_one_changed_evidence_bit_is_detected(case):
    create_seal(case)
    path = case.path / case.state()["evidence"][1]["stored_as"]
    _writable(path)
    data = bytearray(path.read_bytes())
    data[-1] ^= 0x01
    path.write_bytes(data)
    result = _verify(case)
    assert result["ok"] is False
    assert any("K1" in p for p in result["problems"])


def test_a_missing_evidence_file_is_detected(case):
    create_seal(case)
    path = case.path / case.state()["evidence"][0]["stored_as"]
    _writable(path)
    path.unlink()
    result = _verify(case)
    assert result["ok"] is False and any("Q1" in p for p in result["problems"])


def test_an_unknown_file_in_the_evidence_folder_is_detected(case):
    create_seal(case)
    (case.path / "evidence" / "planted.png").write_bytes(b"x")
    result = _verify(case)
    assert result["ok"] is False and any("planted.png" in p for p in result["problems"])


def test_an_edited_ledger_is_detected(case):
    create_seal(case)
    path = case.ledger.path
    path.write_bytes(path.read_bytes().replace(b"Seal test", b"Seal t3st"))
    assert _verify(case)["ok"] is False


def test_a_ledger_cut_short_after_a_seal_is_detected(case):
    create_seal(case)
    path = case.ledger.path
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:3]))
    result = _verify(case)
    assert result["ok"] is False and any("seal" in p.lower() for p in result["problems"])


def test_an_edited_seal_file_is_detected(case):
    seal = create_seal(case)
    path = case.path / seal["file"]
    _writable(path)
    path.write_bytes(path.read_bytes().replace(b'"Q1"', b'"Q9"'))
    assert _verify(case)["ok"] is False


def test_a_folder_that_is_not_a_case_fails_cleanly(tmp_path):
    result = vc.verify_case(tmp_path)
    assert result["ok"] is False and result["problems"]


# ------------------------------------------------------------ time stamp

def test_a_time_stamp_is_recorded_and_checked(case, monkeypatch):
    create_seal(case)
    _fake_tsa(monkeypatch)
    stamp = timestamp_seal(case, url="http://tsa.invalid/tsr")
    assert stamp["gen_time"] == "2026-11-26T15:30:00Z"
    assert (case.path / stamp["tsr_file"]).is_file()
    assert case.state()["seals"][0]["timestamp"]["tsa_url"] == "http://tsa.invalid/tsr"
    result = _verify(case)
    assert result["ok"] is True
    assert result["summary"]["timestamps"] == 1
    assert any("signature" in n.lower() and "not checked" in n.lower() for n in result["notes"])


def test_the_time_stamp_request_carries_the_hash_of_the_seal_file(case, monkeypatch):
    seal = create_seal(case)
    seen = {}

    def request(url, digest, timeout=20):
        seen["digest"] = digest
        return fake_tsr(digest, 5), 5
    monkeypatch.setattr(tsa, "request_timestamp", request)
    timestamp_seal(case, url="http://tsa.invalid/tsr")
    assert seen["digest"].hex() == seal["sha256"]


@pytest.mark.parametrize("kwargs", [
    {"digest_override": hashlib.sha256(b"something else").digest()},
    {"nonce_shift": 1},
    {"status": "rejection"},
])
def test_a_wrong_time_stamp_is_refused_and_not_recorded(case, monkeypatch, kwargs):
    create_seal(case)
    _fake_tsa(monkeypatch, **kwargs)
    count = len(case.ledger.entries())
    with pytest.raises(SealError):
        timestamp_seal(case, url="http://tsa.invalid/tsr")
    assert len(case.ledger.entries()) == count
    assert list((case.path / "seals").glob("*.tsr")) == []


def test_a_time_stamp_needs_a_seal_first(case, monkeypatch):
    _fake_tsa(monkeypatch)
    with pytest.raises(SealError):
        timestamp_seal(case, url="http://tsa.invalid/tsr")


def test_a_swapped_time_stamp_file_is_detected(case, monkeypatch):
    create_seal(case)
    _fake_tsa(monkeypatch)
    stamp = timestamp_seal(case, url="http://tsa.invalid/tsr")
    path = case.path / stamp["tsr_file"]
    _writable(path)
    path.write_bytes(fake_tsr(hashlib.sha256(b"other").digest(), 5))
    assert _verify(case)["ok"] is False


def test_a_time_stamp_with_no_real_signature_fails_the_signature_check(case, monkeypatch):
    if vc.find_openssl() is None:
        pytest.skip("OpenSSL is not installed")
    create_seal(case)
    _fake_tsa(monkeypatch)
    timestamp_seal(case, url="http://tsa.invalid/tsr")
    result = vc.verify_case(case.path, check_tsa_signature=True)
    assert result["ok"] is False
    # The failure must be OpenSSL's own verdict, not a tool that did not start.
    assert any("signature check FAILED" in p and "OpenSSL" in p for p in result["problems"])


def test_a_broken_openssl_setup_is_a_note_and_not_a_false_alarm(case, monkeypatch):
    """Found on a real computer: an OpenSSL whose configuration file is missing must not report a bad time stamp."""
    create_seal(case)
    _fake_tsa(monkeypatch)
    timestamp_seal(case, url="http://tsa.invalid/tsr")
    # The Python program stands in for an OpenSSL that stops before it runs the check.
    result = vc.verify_case(case.path, check_tsa_signature=True, openssl=sys.executable)
    assert result["ok"] is True
    assert any("could not run the check" in n for n in result["notes"])


def test_the_signature_check_does_not_use_the_system_openssl_configuration(case, monkeypatch):
    if vc.find_openssl() is None:
        pytest.skip("OpenSSL is not installed")
    create_seal(case)
    _fake_tsa(monkeypatch)
    stamp = timestamp_seal(case, url="http://tsa.invalid/tsr")
    monkeypatch.setenv("OPENSSL_CONF", str(case.path / "no-such-file.cnf"))
    info = vc.parse_timestamp_response((case.path / stamp["tsr_file"]).read_bytes())
    status, detail = vc.openssl_verify_timestamp(case.path / stamp["tsr_file"], case.path / "seals" / "seal-0001.json", info)
    assert status == "failed" and "could not run" not in detail


def test_a_missing_openssl_is_a_note(case, monkeypatch):
    create_seal(case)
    _fake_tsa(monkeypatch)
    timestamp_seal(case, url="http://tsa.invalid/tsr")
    result = vc.verify_case(case.path, check_tsa_signature=True, openssl=str(case.path / "no-openssl.exe"))
    assert result["ok"] is True
    assert any("OpenSSL was not found" in n for n in result["notes"])


@pytest.mark.network
@pytest.mark.skipif(os.environ.get("FHAND_NETWORK") != "1", reason="set FHAND_NETWORK=1 to contact a real server")
def test_a_real_time_stamp_passes_the_openssl_signature_check(case):
    if vc.find_openssl() is None:
        pytest.skip("OpenSSL is not installed")
    create_seal(case)
    timestamp_seal(case)
    result = vc.verify_case(case.path, check_tsa_signature=True)
    assert result["ok"] is True, result["problems"]
    assert any("valid signature" in n for n in result["notes"])
