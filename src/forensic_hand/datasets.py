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
import math
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
    for key in ("forger_id", "forger_consent_id"):
        if key in item and (not isinstance(item[key], str) or not item[key]):
            raise DatasetError(f"{item_id}: {key} must be a non-empty text")


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
    consent_ids: set = set()
    for rec in consent["records"]:
        if not isinstance(rec, dict) or not isinstance(rec.get("consent_id"), str):
            raise DatasetError("each consent record needs a consent_id")
        if rec["consent_id"] in consent_ids:
            # Two records with one id: the order of the list must never bring back a withdrawn consent.
            raise DatasetError(f"the consent id {rec['consent_id']} is used twice")
        consent_ids.add(rec["consent_id"])
        if not isinstance(rec.get("scopes"), list) or any(s not in USES for s in rec["scopes"]):
            raise DatasetError(f"consent {rec.get('consent_id')}: scopes must come from {', '.join(USES)}")
    items = data.get("items")
    if not isinstance(items, list) or not items:
        raise DatasetError("the manifest has no items")
    seen: set = set()
    for item in items:
        _check_item(item, seen)
    # A degraded scan may name its clean original by the original's sample name, so that name must be unique.
    names = Counter(i["sample"] for i in items if i["stratum"] == "clean" and i.get("sample"))
    shared = sorted(name for name, count in names.items() if count > 1)
    if shared:
        raise DatasetError(f"two or more clean items share the sample name {shared[0]}; each clean item needs its own")


def new_manifest(title, license_class, license_name, items, folder, consent=None, synthetic=False,
                 generator=None, license_url=None, notes=None, extra: dict | None = None) -> dict:
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
        "generator": generator, "notes": notes, "items": full, **(extra or {}),
    }
    check_manifest(data)
    return data


def _manifest_root(folder, out) -> tuple[Path, str]:
    """The folder that the file paths start from, and the path from it to the picture folder ("" or "a/b/").

    A manifest reads its files relative to its own folder (see Manifest.folder and verify). So a manifest
    saved in a folder above the pictures gets longer paths, and one saved anywhere else is refused.
    """
    folder = Path(folder)
    if out is None:
        return folder, ""
    base, pictures = Path(out).resolve().parent, folder.resolve()
    if base == pictures:
        return folder, ""
    if base not in pictures.parents:
        raise DatasetError("save the manifest in the picture folder or in a folder above it, "
                           f"so that it can find the pictures: {out}")
    return base, pictures.relative_to(base).as_posix() + "/"


def _rebased(items: list[dict], prefix: str) -> list[dict]:
    return [{**item, "file": _safe_file(prefix + item["file"])} for item in items] if prefix else items


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

    def problem(consent_id, who: str) -> str | None:
        rec = records.get(consent_id)
        if rec is None:
            return f"no {who}consent record"
        if rec.get("withdrawn"):
            return f"{who}consent withdrawn"
        if purpose not in rec["scopes"]:
            return f"{who}consent does not cover {purpose}"
        return None

    for item in manifest.items:
        # A skilled forgery is the forger's own handwriting: the forger's consent must cover the use too.
        reason = problem(item.get("consent_id"), "")
        if reason is None and (item.get("kind") == "forgery-skilled" or item.get("forger_id")):
            reason = problem(item.get("forger_consent_id"), "forger ")
        if reason:
            excluded[reason] += 1
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

    items.csv columns: file, writer_id, kind, and optional stratum, consent_id, capture, source_item, item_id,
    sample, forger_id (who made a skilled forgery; writer_id is the person whose signature it imitates),
    forger_consent_id (the forger's own consent record: a forgery is the forger's handwriting). Set `sample` on a degraded item (for example a blurred scan) to the item_id of its clean original,
    so that the validation can pair it; a clean original needs no sample.
    consent.csv columns: consent_id, scopes (separated by ;), date, withdrawn (yes or no).
    Use pseudonymous writer ids. Keep the list of real names somewhere else.
    The `file` column is the path inside the folder. Save the manifest in the folder or in a folder above it.
    """
    folder = Path(folder)
    root, prefix = _manifest_root(folder, out)
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
        for key in ("consent_id", "source_item", "sample", "forger_id", "forger_consent_id"):
            if (row.get(key) or "").strip():
                item[key] = row[key].strip()
        items.append(item)
    manifest = new_manifest(title, license_class, license_name, _rebased(items, prefix), root, consent=consent,
                            synthetic=False, license_url=license_url, notes=notes)
    if out:
        save_manifest(manifest, out)
    return manifest


# ---------------------------------------------------------------- public sets, read by their file names

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}
# Known layouts. Check that the names in your copy look like these before you rely on a preset.
PRESETS = {
    "cedar": {
        "pattern": r"(?:.*/)?(?P<kind>original|forgeries)_(?P<writer>\d+)_\d+\.png",
        "genuine": ["original"], "forgery": ["forgeries"],
        "note": "CEDAR: full_org/original_<writer>_<n>.png and full_forg/forgeries_<writer>_<n>.png",
    },
    "bhsig260": {
        "pattern": r"(?:.*/)?(?P<set>[BH])-S-(?P<writer>\d+)-(?P<kind>[GF])-\d+\.tiff?",
        "genuine": ["G"], "forgery": ["F"],
        "note": "BHSig260: <B or H>-S-<writer>-<G or F>-<n>.tif; Bengali (B) and Hindi (H) writers are different people",
    },
}
_BAD_ID = re.compile(r"[^A-Za-z0-9._@-]")


def _number(text: str) -> str:
    return str(int(text)) if text.isdigit() else text


def scan_names(folder, pattern: str, genuine, forgery) -> tuple[list[dict], dict]:
    """Items from the paths of the pictures in a folder (and its sub-folders), read with a pattern.

    The pattern is a regular expression for the whole path inside the folder, written with / between
    folders. It needs the named groups `writer` and `kind`; `set` (written before the writer number, for
    sets whose writers are numbered again per part) and `forger` are optional. A kind word that is in
    neither list is left out and counted. The match ignores upper and lower case.
    """
    try:
        rule = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise DatasetError(f"the pattern is not a valid regular expression: {exc}") from exc
    if not {"writer", "kind"} <= set(rule.groupindex):
        raise DatasetError("the pattern needs the named groups writer and kind, for example "
                           r"(?P<kind>original|forgeries)_(?P<writer>\d+)_\d+\.png")
    kinds = {w.casefold(): "genuine" for w in genuine or []} | {w.casefold(): "forgery-skilled" for w in forgery or []}
    if not kinds:
        raise DatasetError("name the kind words for genuine signatures and for forgeries (--genuine, --forgery)")
    folder = Path(folder)
    items, skipped, used_ids = [], [], set()
    for path in sorted(p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in IMAGE_SUFFIXES):
        rel = path.relative_to(folder).as_posix()
        match = rule.fullmatch(rel)
        kind = kinds.get(match.group("kind").casefold()) if match else None
        if kind is None:
            skipped.append(rel)
            continue
        groups = match.groupdict()
        writer = _number(groups["writer"])
        if groups.get("set"):
            writer = f"{groups['set'].upper()}-{writer}"
        item_id = _BAD_ID.sub("-", rel)[:110]
        if not item_id[:1].isalnum():
            item_id = f"i{item_id}"
        base, n = item_id, 1
        while item_id in used_ids:
            n += 1
            item_id = f"{base}-{n}"          # "-" is allowed in an item id (see _ID)
        used_ids.add(item_id)
        item = {"item_id": item_id, "file": _safe_file(rel), "writer_id": writer, "kind": kind, "stratum": "clean",
                "capture": "scan", "dpi": _image_dpi(path)}
        if kind == "forgery-skilled" and groups.get("forger"):
            item["forger_id"] = groups["forger"]
        items.append(item)
    if not items:
        raise DatasetError(f"no picture in {folder} matches the pattern ({len(skipped)} picture(s) looked at)")
    summary = {"pattern": pattern, "genuine": list(genuine or []), "forgery": list(forgery or []),
               "matched": len(items), "skipped": len(skipped), "skipped_examples": skipped[:5],
               "writers": len({i["writer_id"] for i in items}),
               "genuine_items": sum(i["kind"] == "genuine" for i in items),
               "forgery_items": sum(i["kind"] == "forgery-skilled" for i in items)}
    return items, summary


def build_from_names(folder, title, license_class, license_name, preset=None, pattern=None, genuine=None,
                     forgery=None, out=None, license_url=None, notes=None, dry_run: bool = False) -> dict:
    """Make a manifest for a set whose file names say the writer and the kind (for example a public set).

    Public signature sets usually allow non-commercial research only: register them as research-only,
    and the tool will use them for internal benchmarks only.
    The pattern is for the path inside the folder. Save the manifest (out) in the folder or in a folder
    above it; the import summary then says which folder the pattern was used in.
    """
    root, prefix = _manifest_root(folder, out)
    if preset is not None:
        if preset not in PRESETS:
            raise DatasetError(f"unknown preset {preset}; the presets are: {', '.join(PRESETS)}")
        pattern = pattern or PRESETS[preset]["pattern"]
        genuine = genuine or PRESETS[preset]["genuine"]
        forgery = forgery or PRESETS[preset]["forgery"]
    if not pattern:
        raise DatasetError("give a preset or a pattern")
    items, summary = scan_names(folder, pattern, genuine, forgery)
    summary = {"preset": preset, "folder": prefix.rstrip("/") or ".", **summary}
    items = _rebased(items, prefix)
    if dry_run:
        return {"import": summary, "items": items}
    manifest = new_manifest(title, license_class, license_name, items, root, synthetic=False,
                            license_url=license_url, notes=notes, extra={"import": summary})
    if out:
        save_manifest(manifest, out)
    return manifest


# ---------------------------------------------------------------- a fit group and a test group (Stage 4, Phase 5)

SPLIT_GROUPS = {"fit": "calibrate", "test": "publish"}
SPLIT_METHOD = ("test target = floor(test share x the writers who may join a group). A writer whose consent allows one "
                "group only goes there; those in the test group count toward the target. The rest of the target "
                "comes from the writers free to join either group, in the order of the SHA-256 of "
                "'<seed>:<writer id>' (hex text), as many as there are; the other free writers join the fit group.")


def _split_key(seed: int, writer: str) -> str:
    return hashlib.sha256(f"{seed}:{writer}".encode("utf-8")).hexdigest()


def _writers_for(manifest: Manifest, purpose: str) -> set[str]:
    """Writers with at least one genuine signature that may be used for this purpose."""
    used, _ = usable_items(manifest, purpose)
    return {i["writer_id"] for i in used if i["kind"] == "genuine"}


def split_manifest(path, seed: int, test_share: float = 0.5, fit_out=None, test_out=None,
                   dry_run: bool = False) -> dict:
    """Split a collection into a fit group (to calibrate) and a test group (to publish) with no writer in both.

    Each item goes with its writer; a skilled forgery goes with the writer it imitates. The order of the
    writers comes from the seed (see SPLIT_METHOD), so anyone can repeat the split. Consent decides first: a
    writer whose consent covers only calibrate joins the fit group, only publish the test group, and neither is
    left out. Split before you look at any result, and write the seed down. People whose handwriting is in both
    groups (for example a forger who imitated writers of both groups) are reported, not moved.
    """
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise DatasetError("the seed must be a whole number")
    if isinstance(test_share, bool) or not isinstance(test_share, int | float) or not math.isfinite(test_share) \
            or not 0 < test_share < 1:
        raise DatasetError("the test share must be a number between 0 and 1, for example 0.5")
    source = load_manifest(path)
    outs = {g: Path(out) if out else source.path.with_name(f"{source.path.stem}-{g}.json")
            for g, out in (("fit", fit_out), ("test", test_out))}
    for group, out in outs.items():
        if out.resolve().parent != source.folder.resolve():
            raise DatasetError(f"save the {group} manifest in the folder of the source manifest, so that its "
                               f"file paths stay right: {out}")
        if not dry_run and out.exists():
            raise DatasetError(f"the file exists already; choose a new name: {out}")
    if outs["fit"].resolve() == outs["test"].resolve():
        raise DatasetError("the fit manifest and the test manifest need two different names")

    writers = sorted({i["writer_id"] for i in source.items})
    can_fit, can_test = _writers_for(source, "calibrate"), _writers_for(source, "publish")
    forced = {"fit": [w for w in writers if w in can_fit and w not in can_test],
              "test": [w for w in writers if w in can_test and w not in can_fit]}
    left_out = [w for w in writers if w not in can_fit and w not in can_test]
    free = sorted((w for w in writers if w in can_fit and w in can_test), key=lambda w: _split_key(seed, w))
    # Round down, so that at a share of one half the fit group is not the smaller one (unless consent decides).
    target = math.floor(test_share * (len(writers) - len(left_out)))
    take = min(max(target - len(forced["test"]), 0), len(free))
    groups = {"fit": sorted(forced["fit"] + free[take:]), "test": sorted(forced["test"] + free[:take])}
    if not groups["fit"] or not groups["test"]:
        raise DatasetError(f"the split needs writers in both groups: {len(groups['fit'])} for fit, "
                           f"{len(groups['test'])} for test ({len(left_out)} left out)")
    share_note = None
    if len(groups["test"]) != target:
        share_note = (f"Consent placed the writers so that the test group has {len(groups['test'])} writer(s), "
                      f"not the {target} that the share asks for (fit group: {len(groups['fit'])}).")

    group_of = {w: g for g, ws in groups.items() for w in ws}
    kept = {g: [i for i in source.items if group_of.get(i["writer_id"]) == g] for g in groups}
    people = {g: set(groups[g]) | {i["forger_id"] for i in kept[g] if i.get("forger_id")} for g in groups}
    both = sorted(people["fit"] & people["test"])
    lic = source.data["license"]["class"]
    summary = {"source": str(source.path), "source_manifest_sha256": source.manifest_sha256, "seed": seed,
               "test_share": test_share, "method": SPLIT_METHOD, "forced": forced, "left_out": left_out,
               "share_note": share_note, "people_in_both_groups": both, "license_class": lic,
               "license_allows": {p: p in LICENSE_USES[lic] for p in SPLIT_GROUPS.values()}}
    for g in groups:
        summary[g] = {"path": str(outs[g]), "purpose": SPLIT_GROUPS[g], "writers": groups[g], "items": len(kept[g])}
    if dry_run:
        return summary
    datas = {}
    for g, other in (("fit", "test"), ("test", "fit")):
        named = {i.get(k) for i in kept[g] for k in ("consent_id", "forger_consent_id")} - {None}
        data = {**source.data, "items": kept[g],
                "title": f"{source.data['title']} ({g} group, split seed {seed})",
                "consent": {**source.data["consent"],
                            "records": [r for r in source.data["consent"]["records"] if r["consent_id"] in named]},
                "split": {"group": g, "purpose": SPLIT_GROUPS[g], "seed": seed, "test_share": test_share,
                          "method": SPLIT_METHOD, "source_manifest_sha256": source.manifest_sha256,
                          "writers": groups[g], "other_group_writers": len(groups[other]),
                          "left_out": left_out, "share_note": share_note, "people_in_both_groups": both}}
        check_manifest(data)
        datas[g] = data
    written: list[Path] = []
    try:
        for g in ("fit", "test"):
            outs[g].touch(exist_ok=False)          # claims the name; refuses a file that appeared meanwhile
            written.append(outs[g])
            save_manifest(datas[g], outs[g])
    except BaseException as exc:
        for out in written:                        # only files that this call made
            out.unlink(missing_ok=True)
        if isinstance(exc, Exception):
            raise DatasetError(f"the split could not be written, and nothing was kept: {exc}") from exc
        raise
    return summary
