"""Datasets for validation: a manifest names every file with its hash, label, licence and consent.

Rules
- A file must match its hash, or the dataset is not used.
- The licence decides what the data may be used for. Research-only data (for example most
  academic signature sets) may be used for internal benchmarks only: never to calibrate, train
  or publish results of a commercial tool. Data with an unknown licence is not used at all.
- When a dataset needs consent, each item must point to a consent record that covers the use
  and is not withdrawn. Other items are left out, and the count is reported.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from .verify_case import hash_file

FORMAT = "forensic-hand dataset"
VERSION = 1
USES = ("benchmark", "calibrate", "train", "publish")
LICENSE_USES = {
    "own": set(USES),
    "commercial": set(USES),
    "research-only": {"benchmark"},
    "unknown": set(),
}
KINDS = {"genuine", "forgery-skilled", "forgery-random", "disguised", "copy", "other"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,120}$")


class DatasetError(Exception):
    pass


@dataclass
class Manifest:
    data: dict
    path: Path
    manifest_sha256: str

    @property
    def folder(self) -> Path:
        return self.path.parent

    @property
    def items(self) -> list[dict]:
        return self.data["items"]


def _safe_file(name) -> str:
    if not isinstance(name, str) or not name or "\\" in name:
        raise DatasetError(f"unsafe file path in the manifest: {name!r}")
    posix, windows = PurePosixPath(name), PureWindowsPath(name)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or ".." in posix.parts:
        raise DatasetError(f"unsafe file path in the manifest: {name!r}")
    return name


def _check_item(item, seen: set) -> None:
    if not isinstance(item, dict):
        raise DatasetError("each item must be an object")
    item_id = item.get("item_id")
    if not isinstance(item_id, str) or not _ID.match(item_id):
        raise DatasetError(f"bad item id: {item_id!r}")
    if item_id in seen:
        raise DatasetError(f"the item id {item_id} is used twice")
    seen.add(item_id)
    _safe_file(item.get("file"))
    if not isinstance(item.get("sha256"), str) or not _HEX64.match(item["sha256"]):
        raise DatasetError(f"{item_id}: missing or bad sha256")
    if not isinstance(item.get("size"), int) or item["size"] < 0:
        raise DatasetError(f"{item_id}: missing or bad size")
    if not isinstance(item.get("writer_id"), str) or not item["writer_id"]:
        raise DatasetError(f"{item_id}: missing writer_id")
    if item.get("kind") not in KINDS:
        raise DatasetError(f"{item_id}: kind must be one of {', '.join(sorted(KINDS))}")
    if not isinstance(item.get("stratum"), str) or not item["stratum"]:
        raise DatasetError(f"{item_id}: missing stratum")


def check_manifest(data) -> None:
    if not isinstance(data, dict) or data.get("format") != FORMAT or data.get("version") != VERSION:
        raise DatasetError("this is not a forensic-hand dataset manifest (version 1)")
    if not isinstance(data.get("title"), str) or not data["title"]:
        raise DatasetError("the manifest needs a title")
    lic = data.get("license")
    if not isinstance(lic, dict) or lic.get("class") not in LICENSE_USES or not isinstance(lic.get("name"), str):
        raise DatasetError(f"the licence needs a name and a class: {', '.join(LICENSE_USES)}")
    consent = data.get("consent")
    if not isinstance(consent, dict) or not isinstance(consent.get("records"), list):
        raise DatasetError("the manifest needs a consent section (it can be empty)")
    for rec in consent["records"]:
        if not isinstance(rec, dict) or not isinstance(rec.get("consent_id"), str):
            raise DatasetError("each consent record needs a consent_id")
        if not isinstance(rec.get("scopes"), list) or any(s not in USES for s in rec["scopes"]):
            raise DatasetError(f"consent {rec.get('consent_id')}: scopes must come from {', '.join(USES)}")
    items = data.get("items")
    if not isinstance(items, list) or not items:
        raise DatasetError("the manifest has no items")
    seen: set = set()
    for item in items:
        _check_item(item, seen)


def new_manifest(title, license_class, license_name, items, folder, consent=None, synthetic=False,
                 generator=None, license_url=None, notes=None) -> dict:
    """Make a manifest. The hash and size of each file are read from the folder now."""
    folder = Path(folder)
    full = []
    for item in items:
        name = _safe_file(item.get("file"))
        path = folder / name
        if not path.is_file():
            raise DatasetError(f"file not found: {name}")
        facts = hash_file(path)
        full.append({"stratum": "clean", **item, "sha256": facts["sha256"], "size": facts["size"]})
    data = {
        "format": FORMAT, "version": VERSION, "title": title, "synthetic": bool(synthetic),
        "license": {"class": license_class, "name": license_name, "url": license_url},
        "consent": {"required": consent is not None, "records": list(consent or [])},
        "generator": generator, "notes": notes, "items": full,
    }
    check_manifest(data)
    return data


def save_manifest(data: dict, path) -> None:
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def load_manifest(path) -> Manifest:
    path = Path(path)
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise DatasetError(f"the manifest cannot be read: {exc}") from exc
    check_manifest(data)
    return Manifest(data, path, hashlib.sha256(raw).hexdigest())


def verify(manifest: Manifest) -> list[str]:
    """Problems with the files: missing, changed, or outside the dataset folder."""
    problems = []
    root = manifest.folder.resolve()
    for item in manifest.items:
        path = (manifest.folder / item["file"]).resolve()
        if root not in path.parents:
            problems.append(f"{item['item_id']}: the file is outside the dataset folder")
            continue
        if not path.is_file():
            problems.append(f"{item['item_id']}: file is missing ({item['file']})")
            continue
        facts = hash_file(path)
        if facts["sha256"] != item["sha256"] or facts["size"] != item["size"]:
            problems.append(f"{item['item_id']}: file content does not match the manifest ({item['file']})")
    return problems


def require_use(manifest: Manifest, purpose: str) -> None:
    if purpose not in USES:
        raise DatasetError(f"the purpose must be one of: {', '.join(USES)}")
    lic = manifest.data["license"]
    if purpose not in LICENSE_USES[lic["class"]]:
        raise DatasetError(f"the licence of '{manifest.data['title']}' ({lic['class']}: {lic['name']}) "
                           f"does not allow this use: {purpose}")


def usable_items(manifest: Manifest, purpose: str) -> tuple[list[dict], dict]:
    """Items that may be used for this purpose, and why the others were left out."""
    consent = manifest.data["consent"]
    if not consent["required"]:
        return list(manifest.items), {}
    records = {r["consent_id"]: r for r in consent["records"]}
    used, excluded = [], Counter()
    for item in manifest.items:
        rec = records.get(item.get("consent_id"))
        if rec is None:
            excluded["no consent record"] += 1
        elif rec.get("withdrawn"):
            excluded["consent withdrawn"] += 1
        elif purpose not in rec["scopes"]:
            excluded[f"consent does not cover {purpose}"] += 1
        else:
            used.append(item)
    return used, dict(sorted(excluded.items()))


# ---------------------------------------------------------------- real collections

def _yes(text) -> bool:
    return str(text).strip().lower() in {"yes", "y", "true", "1"}


def _image_dpi(path: Path):
    from PIL import Image

    from .quality import _clean_dpi

    try:
        with Image.open(path) as img:
            return _clean_dpi(img.info.get("dpi"))
    except OSError:
        return None


def build_from_csv(folder, items_csv, title, license_class, license_name, consent_csv=None, out=None,
                   license_url=None, notes=None) -> dict:
    """Make a manifest for a real collection from a spreadsheet saved as CSV.

    items.csv columns: file, writer_id, kind, and optional stratum, consent_id, capture, source_item, item_id.
    consent.csv columns: consent_id, scopes (separated by ;), date, withdrawn (yes or no).
    Use pseudonymous writer ids. Keep the list of real names somewhere else.
    """
    folder = Path(folder)
    try:
        with open(items_csv, newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        consent = None
        if consent_csv:
            with open(consent_csv, newline="", encoding="utf-8-sig") as fh:
                consent = [{"consent_id": r["consent_id"].strip(),
                            "scopes": [s.strip() for s in (r.get("scopes") or "").split(";") if s.strip()],
                            "date": (r.get("date") or "").strip() or None,
                            "withdrawn": _yes(r.get("withdrawn", "no"))} for r in csv.DictReader(fh)]
    except (OSError, KeyError, csv.Error) as exc:
        raise DatasetError(f"the CSV file cannot be read: {exc}") from exc
    items = []
    for n, row in enumerate(rows, start=1):
        name = _safe_file((row.get("file") or "").strip())
        item = {
            "item_id": (row.get("item_id") or "").strip() or f"i{n:05d}",
            "file": name,
            "writer_id": (row.get("writer_id") or "").strip(),
            "kind": (row.get("kind") or "").strip(),
            "stratum": (row.get("stratum") or "").strip() or "clean",
            "capture": (row.get("capture") or "").strip() or None,
            "dpi": _image_dpi(folder / name),
        }
        for key in ("consent_id", "source_item"):
            if (row.get(key) or "").strip():
                item[key] = row[key].strip()
        items.append(item)
    manifest = new_manifest(title, license_class, license_name, items, folder, consent=consent, synthetic=False,
                            license_url=license_url, notes=notes)
    if out:
        save_manifest(manifest, out)
    return manifest
