from __future__ import annotations

import hashlib
import os
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from asn1crypto import tsp
from conftest import fake_tsr

from forensic_hand import tsa
from forensic_hand import verify_case as vc

DIGEST = hashlib.sha256(b"seal bytes").digest()


def test_the_request_is_readable_by_an_independent_library():
    req = tsp.TimeStampReq.load(tsa.build_request(DIGEST, nonce=123456789))
    assert req["version"].native == "v1"
    assert req["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"
    assert req["message_imprint"]["hashed_message"].native == DIGEST
    assert req["nonce"].native == 123456789
    assert req["cert_req"].native is True


def test_the_request_holds_only_the_hash():
    assert len(tsa.build_request(DIGEST, nonce=1)) < 80


def test_a_large_nonce_survives_the_round_trip():
    nonce = 2**63 + 5
    assert tsp.TimeStampReq.load(tsa.build_request(DIGEST, nonce=nonce))["nonce"].native == nonce
    assert vc.parse_timestamp_response(fake_tsr(DIGEST, nonce))["nonce"] == nonce


def test_a_digest_of_the_wrong_length_is_rejected():
    with pytest.raises(ValueError):
        tsa.build_request(b"too short", nonce=1)


def test_a_response_made_by_an_independent_library_is_parsed():
    info = vc.parse_timestamp_response(fake_tsr(DIGEST, nonce=77))
    assert info["granted"] is True and info["status"] == 0
    assert info["hash_oid"] == "2.16.840.1.101.3.4.2.1"
    assert info["imprint"] == DIGEST.hex()
    assert info["gen_time"] == "2026-11-26T15:30:00Z"
    assert info["serial"] == "4242"
    assert info["policy"] == "1.2.3.4.5"
    assert info["nonce"] == 77


def test_a_response_with_no_nonce_is_parsed():
    assert vc.parse_timestamp_response(fake_tsr(DIGEST, nonce=None))["nonce"] is None


def test_a_rejected_response_is_not_granted():
    info = vc.parse_timestamp_response(fake_tsr(DIGEST, None, status="rejection"))
    assert info["granted"] is False and info["status"] == 2
    assert info["imprint"] is None


@pytest.mark.parametrize("blob", [b"", b"hello", b"\x30\x03\x02\x01", b"\x30\x80\x00\x00"])
def test_a_broken_response_raises_value_error(blob):
    with pytest.raises(ValueError):
        vc.parse_timestamp_response(blob)


class _Handler(BaseHTTPRequestHandler):
    seen: dict = {}  # noqa: RUF012 - shared on purpose: the test reads what the server saw
    reply_status = 200

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).seen = {"body": body, "type": self.headers["Content-Type"], "agent": self.headers["User-Agent"]}
        req = tsp.TimeStampReq.load(body)
        reply = fake_tsr(req["message_imprint"]["hashed_message"].native, req["nonce"].native)
        self.send_response(type(self).reply_status)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_tsa():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Handler.reply_status = 200
    yield f"http://127.0.0.1:{server.server_port}/tsr"
    server.shutdown()
    server.server_close()


def test_the_query_is_posted_and_the_reply_comes_back(local_tsa):
    reply, nonce = tsa.request_timestamp(local_tsa, DIGEST, timeout=5)
    info = vc.parse_timestamp_response(reply)
    assert info["imprint"] == DIGEST.hex() and info["nonce"] == nonce
    assert _Handler.seen["type"] == "application/timestamp-query"
    assert _Handler.seen["body"] == tsa.build_request(DIGEST, nonce=nonce)
    assert _Handler.seen["agent"].startswith("forensic-hand/")


def test_a_server_error_becomes_a_timestamp_error(local_tsa):
    _Handler.reply_status = 500
    with pytest.raises(tsa.TimestampError):
        tsa.request_timestamp(local_tsa, DIGEST, timeout=5)


def test_an_unreachable_server_becomes_a_timestamp_error():
    with pytest.raises(tsa.TimestampError):
        tsa.request_timestamp("http://127.0.0.1:9/tsr", DIGEST, timeout=2)


@pytest.mark.parametrize("url", ["file:///C:/Windows/win.ini", "ftp://example.org/x", "not a url"])
def test_only_http_and_https_addresses_are_allowed(url):
    with pytest.raises(tsa.TimestampError):
        tsa.request_timestamp(url, DIGEST, timeout=2)


@pytest.mark.network
@pytest.mark.skipif(os.environ.get("FHAND_NETWORK") != "1", reason="set FHAND_NETWORK=1 to contact a real server")
def test_a_real_time_stamp_server_answers():
    digest = hashlib.sha256(b"forensic-hand network test " + os.urandom(16)).digest()
    reply, nonce = tsa.request_timestamp(tsa.DEFAULT_TSA_URL, digest, timeout=30)
    info = vc.parse_timestamp_response(reply)
    assert info["granted"] and info["imprint"] == digest.hex() and info["nonce"] == nonce
    stamped = datetime.strptime(info["gen_time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert abs(datetime.now(UTC) - stamped) < timedelta(minutes=10)
