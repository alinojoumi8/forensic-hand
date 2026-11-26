"""The local workbench server: safety rules first, then the API."""

from __future__ import annotations

import http.client
import json

import pytest
from conftest import save_image
from test_workbench import signature_image

from forensic_hand.case import Case
from forensic_hand.server import start_server


@pytest.fixture
def srv(tmp_path):
    png = save_image(tmp_path / "q.png", signature_image(1), dpi=(300, 300))
    png2 = save_image(tmp_path / "k.png", signature_image(2), dpi=(300, 300))
    case = Case.create(tmp_path / "case", title="Server test")
    case.add_evidence(png, role="questioned")
    case.add_evidence(png2, role="known")
    server, _thread = start_server(case.path, port=0)
    yield server
    server.shutdown()
    server.server_close()


def call(srv, method, path, body=None, *, token=True, host=None, headers=None, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=30)
    head = {"Host": host or f"127.0.0.1:{srv.server_port}"}
    if token:
        head["X-FHand-Token"] = srv.app.token
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
        head["Content-Type"] = "application/json"
    head.update(headers or {})
    conn.request(method, path, body=data, headers=head)
    resp = conn.getresponse()
    payload = resp.read()
    conn.close()
    return resp, payload


def jcall(srv, method, path, body=None, **kw):
    resp, payload = call(srv, method, path, body, **kw)
    return resp.status, json.loads(payload) if payload else None


# ---------------------------------------------------------------- safety rules

def test_the_server_listens_only_on_this_computer(srv):
    assert srv.server_address[0] == "127.0.0.1"


def test_api_calls_without_the_token_are_refused(srv):
    assert call(srv, "GET", "/api/state", token=False)[0].status == 403
    assert call(srv, "GET", "/api/state", headers={"X-FHand-Token": "wrong"}, token=False)[0].status == 403


def test_the_token_also_works_in_the_address_for_pictures(srv):
    resp, body = call(srv, "GET", f"/api/page/Q1/1?w=200&t={srv.app.token}", token=False)
    assert resp.status == 200 and resp.getheader("Content-Type") == "image/png" and body[:4] == b"\x89PNG"


def test_a_foreign_host_name_is_refused(srv):
    """Stops DNS rebinding: a web page cannot reach the server through its own host name."""
    assert call(srv, "GET", "/api/state", host="evil.example:80")[0].status == 403
    assert call(srv, "GET", "/", host="evil.example")[0].status == 403


def test_the_page_shell_has_strict_security_headers(srv):
    resp, body = call(srv, "GET", "/", token=False)
    assert resp.status == 200 and b"<html" in body.lower()
    csp = resp.getheader("Content-Security-Policy")
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp
    assert resp.getheader("X-Content-Type-Options") == "nosniff"
    assert resp.getheader("Referrer-Policy") == "no-referrer"


@pytest.mark.parametrize("path", ["/static/../ledger.log", "/static/..%2fledger.log", "/static/nope.js",
                                  "/ledger.log", "/evidence/", "/api/crop/../../ledger.log"])
def test_paths_outside_the_app_are_not_served(srv, path):
    assert call(srv, "GET", path)[0].status in (400, 403, 404)


def test_a_post_must_be_json(srv):
    resp, _ = call(srv, "POST", "/api/note", raw=b"target=Q1&text=x",
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert resp.status == 415


def test_a_large_body_is_refused(srv):
    resp, _ = call(srv, "POST", "/api/note", raw=b"{" + b" " * 300_000 + b"}",
                   headers={"Content-Type": "application/json"})
    assert resp.status == 413


def test_a_post_without_the_token_changes_nothing(srv):
    case = Case.open(srv.app.case_path)
    before = len(case.ledger.entries())
    status, _ = jcall(srv, "POST", "/api/note", {"target": "Q1", "text": "x"}, token=False)
    assert status == 403 and len(case.ledger.entries()) == before


# ---------------------------------------------------------------- API

def test_state_lists_items_pages_and_findings(srv):
    status, state = jcall(srv, "GET", "/api/state")
    assert status == 200
    assert state["case"]["title"] == "Server test"
    assert [e["id"] for e in state["evidence"]] == ["Q1", "K1"]
    assert state["pages"]["Q1"][0]["width"] == 900
    assert state["crops"] == [] and state["notes"] == []


def test_crop_note_measure_copy_check_exhibit_report_and_seal(srv):
    status, crop = jcall(srv, "POST", "/api/crop", {"evidence_id": "Q1", "page": 1, "box": [0, 0, 600, 300],
                                                    "label": "Q sig"})
    assert status == 200 and crop["crop_id"] == "C1"
    assert jcall(srv, "POST", "/api/crop", {"evidence_id": "K1", "page": 1, "box": [0, 0, 600, 300]})[0] == 200
    resp, png = call(srv, "GET", "/api/crop/C1.png")
    assert resp.status == 200 and png[:4] == b"\x89PNG"
    assert jcall(srv, "POST", "/api/note", {"target": "C1", "text": "Tremor in the first loop"})[0] == 200
    status, m = jcall(srv, "POST", "/api/measure", {"crop_id": "C1", "kind": "line", "points": [[0, 0], [300, 0]]})
    assert status == 200 and m["length_mm"] == pytest.approx(25.4)
    status, clones = jcall(srv, "POST", "/api/clones", {})
    assert status == 200 and len(clones["pairs"]) == 1
    status, ex = jcall(srv, "POST", "/api/exhibit", {"title": "Chart", "panels": [{"crop_id": "C1"}, {"crop_id": "C2"}]})
    assert status == 200 and ex["exhibit_id"] == "E1"
    assert call(srv, "GET", "/api/exhibit/E1.png")[0].status == 200
    assert jcall(srv, "POST", "/api/report", {})[0] == 200
    resp, html = call(srv, "GET", "/report")
    assert resp.status == 200 and b"Chart" in html
    status, seal = jcall(srv, "POST", "/api/seal", {})
    assert status == 200 and seal["seal_no"] == 1
    status, state = jcall(srv, "GET", "/api/state")
    assert len(state["crops"]) == 2 and len(state["notes"]) == 1 and state["seals"][0]["seal_no"] == 1


def test_a_bad_request_gives_a_plain_error(srv):
    status, body = jcall(srv, "POST", "/api/crop", {"evidence_id": "Q1", "page": 9, "box": [0, 0, 10, 10]})
    assert status == 400 and "page" in body["error"]
    status, body = jcall(srv, "POST", "/api/crop", {"evidence_id": "Q1"})
    assert status == 400


def test_unknown_crop_and_exhibit_pictures_are_404(srv):
    assert call(srv, "GET", "/api/crop/C9.png")[0].status == 404
    assert call(srv, "GET", "/api/exhibit/E9.png")[0].status == 404
    assert call(srv, "GET", "/api/page/Q1/9?w=100")[0].status in (400, 404)
