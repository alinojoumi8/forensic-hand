from __future__ import annotations

import hashlib

import pytest

from forensic_hand import verify_case as vc
from forensic_hand.ledger import Ledger, LedgerError


def _ledger(tmp_path, n=3) -> Ledger:
    lg = Ledger(tmp_path / "ledger.log")
    for i in range(n):
        lg.append("test.event", {"i": i})
    return lg


def test_empty_ledger_has_zero_head(tmp_path):
    lg = Ledger(tmp_path / "ledger.log")
    assert lg.head() == (-1, vc.ZERO_HASH)
    assert lg.entries() == []


def test_entries_are_chained(tmp_path):
    lg = Ledger(tmp_path / "ledger.log")
    a = lg.append("one", {"x": 1})
    b = lg.append("two", {"y": "é text"})
    assert (a["seq"], a["prev"]) == (0, vc.ZERO_HASH)
    assert (b["seq"], b["prev"]) == (1, a["hash"])
    assert [e["type"] for e in lg.entries()] == ["one", "two"]
    assert lg.entries()[1]["data"] == {"y": "é text"}
    assert lg.head() == (1, b["hash"])


def test_hash_covers_the_exact_bytes_of_the_line_body(tmp_path):
    lg = _ledger(tmp_path, 2)
    for line in lg.path.read_bytes().splitlines():
        digest, body = line.split(b" ", 1)
        assert hashlib.sha256(body).hexdigest() == digest.decode()


def test_an_edited_line_is_detected(tmp_path):
    lg = _ledger(tmp_path)
    raw = lg.path.read_bytes().replace(b'"i":1', b'"i":7')
    lg.path.write_bytes(raw)
    with pytest.raises(LedgerError):
        lg.entries()
    _, errors = vc.parse_ledger(lg.path)
    assert errors and "line 2" in errors[0]


def test_a_deleted_line_is_detected(tmp_path):
    lg = _ledger(tmp_path)
    lines = lg.path.read_bytes().splitlines(keepends=True)
    lg.path.write_bytes(lines[0] + lines[2])
    _, errors = vc.parse_ledger(lg.path)
    assert errors


def test_swapped_lines_are_detected(tmp_path):
    lg = _ledger(tmp_path)
    lines = lg.path.read_bytes().splitlines(keepends=True)
    lg.path.write_bytes(lines[1] + lines[0] + lines[2])
    _, errors = vc.parse_ledger(lg.path)
    assert errors


def test_append_refuses_to_extend_a_broken_ledger(tmp_path):
    lg = _ledger(tmp_path)
    lg.path.write_bytes(lg.path.read_bytes().replace(b'"i":1', b'"i":7'))
    with pytest.raises(LedgerError):
        lg.append("more", {})


def test_values_that_are_not_stable_json_are_rejected(tmp_path):
    lg = Ledger(tmp_path / "ledger.log")
    with pytest.raises(ValueError):
        lg.append("bad", {"v": float("nan")})
    assert lg.entries() == []


def test_text_with_line_breaks_stays_on_one_line(tmp_path):
    lg = Ledger(tmp_path / "ledger.log")
    lg.append("note", {"text": "first\nsecond\r\nthird"})
    assert lg.path.read_bytes().count(b"\n") == 1
    assert lg.entries()[0]["data"]["text"] == "first\nsecond\r\nthird"
