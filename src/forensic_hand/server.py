"""The workbench: a small web server on this computer only, for one case.

Safety rules
- It listens on 127.0.0.1 only.
- Every data request needs a random token that is made when the server starts. The token is
  in the address that the server prints (after #, so the browser never sends it in a request
  line by itself); the page sends it in a header, or in the address for pictures.
- The Host header must name this server. That stops a web page from reaching it through
  DNS rebinding.
- A change (POST) must be JSON with the token header. Another web site cannot send that
  header without a CORS check, and this server answers no CORS check.
- No path from a request is used as a file path. Files are found through the ledger only.
- The page is served with a strict Content-Security-Policy: no inline code, no other origin.
"""

from __future__ import annotations

import hmac
import io
import json
import re
import secrets
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .case import Case, CaseError
from .findings import count_levels
from .ledger import LedgerError
from .pages import page_geometry, render_preview
from .report import write_report
from .seal import SealError, create_seal, timestamp_seal
from .work import add_crop, add_measurement, add_note, make_exhibit, run_clone_check, run_score, score_status

MAX_BODY = 256 * 1024
STATIC = {"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8",
          "app.css": "text/css; charset=utf-8"}
PAGE_CSP = ("default-src 'self'; img-src 'self' blob: data:; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
REPORT_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"

_PAGE_ROUTE = re.compile(r"^/api/page/([QKX]\d{1,5})/(\d{1,5})$")
_CROP_ROUTE = re.compile(r"^/api/crop/(C\d{1,6})\.png$")
_EXHIBIT_ROUTE = re.compile(r"^/api/exhibit/(E\d{1,6})\.png$")


class HttpError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class WorkbenchApp:
    def __init__(self, case_path) -> None:
        self.case_path = Path(case_path)
        Case.open(self.case_path)                      # fails early when it is not a case
        self.token = secrets.token_urlsafe(32)
        self.port: int | None = None

    def case(self) -> Case:
        return Case.open(self.case_path)

    # ------------------------------------------------------------ state for the page

    def state(self) -> dict:
        case = self.case()
        state = case.state()
        evidence, pages = [], {}
        for rec in state["evidence"]:
            check = state["files"].get(rec["id"])
            evidence.append({**{k: rec[k] for k in ("id", "role", "name", "media_type", "size", "sha256",
                                                    "signer", "doc_date", "note")},
                             "counts": count_levels(check["findings"]) if check else None})
            try:
                pages[rec["id"]] = page_geometry(case, rec)
            except CaseError:
                pages[rec["id"]] = []
        crop_keys = ("crop_id", "evidence_id", "page", "box", "units", "label", "width", "height", "dpi",
                     "method", "render_dpi", "sha256", "created")
        return {
            "tool": {"version": __version__},
            "case": {"case_id": state["case_id"], "title": state["title"]},
            "ledger": {"count": state["ledger_count"], "head": state["ledger_head"]},
            "evidence": evidence,
            "pages": pages,
            "files": {k: {"kind": v["kind"], "findings": v["findings"]} for k, v in state["files"].items()},
            "case_findings": state["case_findings"],
            "crops": [{k: c.get(k) for k in crop_keys} for c in state["crops"]],
            "measurements": state["measurements"],
            "notes": state["notes"],
            "clone_check": state["clone_check"],
            "exhibits": [{k: x.get(k) for k in ("exhibit_id", "title", "kind", "to_scale", "scale_dpi", "width",
                                                "height", "sha256", "created")} for x in state["exhibits"]],
            "seals": [{"seal_no": s["seal_no"], "sha256": s["sha256"], "created": s["created"],
                       "timestamp": (s["timestamp"] or {}).get("gen_time")} for s in state["seals"]],
            "report": (self.case_path / "reports" / "report.html").is_file(),
            "score": score_status(case),
            "scores": [{k: s.get(k) for k in ("score_id", "questioned", "known", "release_id", "log10_lr", "lr_text",
                                              "verbal", "bounded", "score", "created")}
                       | {"hp": s["propositions"]["hp"], "hd": s["propositions"]["hd"]} for s in state["scores"]],
        }

    # ------------------------------------------------------------ actions

    def post(self, path: str, body: dict):
        case = self.case()
        if path == "/api/crop":
            return add_crop(case, body.get("evidence_id"), body.get("page"), body.get("box"),
                            label=body.get("label"), dpi=body.get("dpi"))
        if path == "/api/note":
            return add_note(case, body.get("target"), body.get("text"), supersedes=body.get("supersedes"))
        if path == "/api/measure":
            return add_measurement(case, body.get("crop_id"), body.get("kind"), body.get("points"),
                                   note=body.get("note"))
        if path == "/api/clones":
            return run_clone_check(case)
        if path == "/api/exhibit":
            return make_exhibit(case, body.get("title"), panels=body.get("panels"),
                                kind=body.get("kind", "panels"), overlay=body.get("overlay"))
        if path == "/api/score":
            return run_score(case, body.get("questioned"), body.get("known"), body.get("release_id"))
        if path == "/api/report":
            report = write_report(case)
            return {"report": report.name}
        if path == "/api/seal":
            seal = create_seal(case)
            if body.get("timestamp") is True:
                seal = {**seal, "timestamp": timestamp_seal(case)}
            return seal
        raise HttpError(404, "not found")

    def picture(self, path: str, query: dict) -> bytes:
        case = self.case()
        state = case.state()
        if match := _PAGE_ROUTE.match(path):
            record = next((r for r in state["evidence"] if r["id"] == match.group(1)), None)
            if record is None:
                raise HttpError(404, "not found")
            try:
                width = int((query.get("w") or ["1600"])[0])
            except ValueError:
                raise HttpError(400, "w must be a whole number") from None
            img = render_preview(case, record, int(match.group(2)), width)
            buf = io.BytesIO()
            img.save(buf, "PNG", compress_level=1)
            return buf.getvalue()
        for route, items, key in ((_CROP_ROUTE, state["crops"], "crop_id"),
                                  (_EXHIBIT_ROUTE, state["exhibits"], "exhibit_id")):
            if match := route.match(path):
                item = next((x for x in items if x[key] == match.group(1)), None)
                if item is None:
                    raise HttpError(404, "not found")
                return (self.case_path / item["file"]).read_bytes()
        raise HttpError(404, "not found")


def _static(name: str) -> bytes:
    return resources.files("forensic_hand").joinpath("web", name).read_bytes()


def make_handler(app: WorkbenchApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "forensic-hand"
        sys_version = ""

        def log_message(self, fmt, *args):   # quiet: requests can carry the token
            pass

        # ------------------------------------------------------------ plumbing

        def _send(self, status: int, body: bytes, content_type: str, csp: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            if csp:
                self.send_header("Content-Security-Policy", csp)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, obj) -> None:
            self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").strip().lower()
            return host in {f"127.0.0.1:{app.port}", f"localhost:{app.port}"}

        def _token_ok(self, query: dict) -> bool:
            given = self.headers.get("X-FHand-Token") or (query.get("t") or [""])[0]
            return bool(given) and hmac.compare_digest(given.encode(), app.token.encode())

        def _body(self) -> dict:
            if not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
                raise HttpError(415, "send JSON")
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise HttpError(400, "bad length") from None
            if length > MAX_BODY:
                raise HttpError(413, "the request is too large")
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                raise HttpError(400, "the request is not valid JSON") from None
            if not isinstance(body, dict):
                raise HttpError(400, "the request must be a JSON object")
            return body

        def _handle(self, method: str) -> None:
            try:
                if not self._host_ok():
                    raise HttpError(403, "wrong host")
                parts = urlsplit(self.path)
                path, query = parts.path, parse_qs(parts.query)
                if method == "GET" and path in ("/", "/index.html"):
                    return self._send(200, _static("index.html"), STATIC["index.html"], PAGE_CSP)
                if method == "GET" and path.startswith("/static/"):
                    name = path[len("/static/"):]
                    if name not in STATIC or name == "index.html":
                        raise HttpError(404, "not found")
                    return self._send(200, _static(name), STATIC[name])
                if not self._token_ok(query):
                    raise HttpError(403, "missing or wrong token")
                if method == "GET" and path == "/api/state":
                    return self._json(200, app.state())
                if method == "GET" and path == "/report":
                    report = app.case_path / "reports" / "report.html"
                    if not report.is_file():
                        raise HttpError(404, "no report yet")
                    return self._send(200, report.read_bytes(), STATIC["index.html"], REPORT_CSP)
                if method == "GET" and path.startswith("/api/"):
                    return self._send(200, app.picture(path, query), "image/png")
                if method == "POST" and path.startswith("/api/"):
                    body = self._body()
                    return self._json(200, app.post(path, body))
                raise HttpError(404, "not found")
            except HttpError as exc:
                self._json(exc.status, {"error": str(exc)})
            except (CaseError, SealError, LedgerError) as exc:
                self._json(400, {"error": str(exc)})
            except Exception:  # noqa: BLE001 - never show a stack to the page
                traceback.print_exc(file=sys.stderr)
                self._json(500, {"error": "internal error; see the console of the workbench"})

        def do_GET(self):
            self._handle("GET")

        def do_HEAD(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    return Handler


class WorkbenchServer(ThreadingHTTPServer):
    daemon_threads = True
    app: WorkbenchApp


def create_server(case_path, port: int = 0) -> WorkbenchServer:
    app = WorkbenchApp(case_path)
    server = WorkbenchServer(("127.0.0.1", port), make_handler(app))
    server.app = app
    app.port = server.server_port
    return server


def start_server(case_path, port: int = 0) -> tuple[WorkbenchServer, threading.Thread]:
    """Start in a background thread (for tests). Call server.shutdown() to stop."""
    server = create_server(case_path, port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def address(server: WorkbenchServer) -> str:
    return f"http://127.0.0.1:{server.server_port}/#t={server.app.token}"
