"""Evidence store. A file is copied once, named by its SHA-256, and set read-only."""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from pathlib import Path

from .verify_case import hash_file

EXTENSION = {"pdf": ".pdf", "png": ".png", "jpeg": ".jpg", "tiff": ".tif", "bmp": ".bmp",
             "gif": ".gif", "webp": ".webp", "unknown": ".bin"}

USUAL_EXTENSIONS = {
    "pdf": {".pdf"}, "png": {".png"}, "jpeg": {".jpg", ".jpeg", ".jpe", ".jfif"},
    "tiff": {".tif", ".tiff"}, "bmp": {".bmp", ".dib"}, "gif": {".gif"}, "webp": {".webp"},
}


class StoreError(Exception):
    pass


def sniff_media_type(head: bytes) -> str:
    """Name the file type from its first bytes. The file name is not trusted."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith(b"BM") and len(head) >= 26:
        return "bmp"
    return "unknown"


def store_file(src: Path, evidence_dir: Path) -> dict:
    """Copy src into the store. Return its hashes, size, type and stored path."""
    sha, b2, size, head = hashlib.sha256(), hashlib.blake2b(), 0, b""
    incoming = evidence_dir / f".incoming-{uuid.uuid4().hex}"
    try:
        with open(src, "rb") as fin, open(incoming, "wb") as fout:
            while True:
                chunk = fin.read(1 << 20)
                if not chunk:
                    break
                if not head:
                    head = chunk[:2048]
                sha.update(chunk)
                b2.update(chunk)
                size += len(chunk)
                fout.write(chunk)
            fout.flush()
            os.fsync(fout.fileno())
        if size == 0:
            raise StoreError(f"file is empty: {src.name}")
        digest = sha.hexdigest()
        if hash_file(incoming)["sha256"] != digest:
            raise StoreError(f"the copy of {src.name} does not match the source; try again")
        media = sniff_media_type(head)
        final = evidence_dir / f"{digest}{EXTENSION[media]}"
        if final.exists():
            if hash_file(final)["sha256"] != digest:
                raise StoreError(f"a stored file is damaged: {final.name}")
            if os.access(final, os.W_OK):
                os.chmod(final, stat.S_IREAD)   # a stored copy must always be read-only
        else:
            # Read-only first, then publish: the stored copy is never writable, even for a moment.
            os.chmod(incoming, stat.S_IREAD)
            os.replace(incoming, final)
    finally:
        if incoming.exists():
            os.chmod(incoming, stat.S_IREAD | stat.S_IWRITE)
            incoming.unlink()
    return {"sha256": digest, "blake2b": b2.hexdigest(), "size": size, "media_type": media,
            "stored_as": f"evidence/{final.name}"}
