"""Trusted time stamps (RFC 3161).

Only a 32-byte hash and a random number leave this computer. No file, no name, no case text.
The reply is signed by the time stamp authority. Anyone can check it later with OpenSSL.
"""

from __future__ import annotations

import secrets
import urllib.error
import urllib.parse
import urllib.request

from . import TOOL_NAME, __version__

DEFAULT_TSA_URL = "http://timestamp.digicert.com"
MAX_REPLY_BYTES = 256 * 1024
_OID_SHA256_DER = bytes.fromhex("608648016503040201")   # 2.16.840.1.101.3.4.2.1


class TimestampError(Exception):
    pass


def _tlv(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    size = (length.bit_length() + 7) // 8
    return bytes([tag, 0x80 | size]) + length.to_bytes(size, "big") + content


def _integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("only numbers of zero or more are supported")
    return _tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def build_request(digest: bytes, nonce: int | None = None, cert_req: bool = True) -> bytes:
    """Build a TimeStampReq for a SHA-256 digest.

    TimeStampReq ::= SEQUENCE { version 1, messageImprint { sha256, digest }, nonce, certReq }
    """
    if len(digest) != 32:
        raise ValueError("the digest must be 32 bytes (SHA-256)")
    algorithm = _tlv(0x30, _tlv(0x06, _OID_SHA256_DER) + b"\x05\x00")
    body = _integer(1) + _tlv(0x30, algorithm + _tlv(0x04, digest))
    if nonce is not None:
        body += _integer(nonce)
    if cert_req:
        body += b"\x01\x01\xff"
    return _tlv(0x30, body)


def request_timestamp(url: str, digest: bytes, timeout: float = 20) -> tuple[bytes, int]:
    """Send the digest to a time stamp server. Return (raw reply, the nonce that was sent)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise TimestampError("the time stamp address must start with http:// or https://")
    nonce = secrets.randbits(64) or 1
    request = urllib.request.Request(
        url, data=build_request(digest, nonce=nonce), method="POST",
        headers={"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply",
                 "User-Agent": f"{TOOL_NAME}/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            reply = response.read(MAX_REPLY_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise TimestampError(f"no answer from {parts.netloc}: {exc}") from exc
    if len(reply) > MAX_REPLY_BYTES:
        raise TimestampError(f"the answer from {parts.netloc} is too large")
    return reply, nonce
