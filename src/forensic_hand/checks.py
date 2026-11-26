"""Run every screen on every item, and record the results and the settings in the ledger."""

from __future__ import annotations

import platform
from datetime import date
from importlib import metadata
from pathlib import PurePath

from . import TOOL_NAME, __version__
from .config import DEFAULTS, config_sha256
from .findings import finding
from .pdf_audit import audit_pdf
from .quality import analyse_image_file
from .store import USUAL_EXTENSIONS

IMAGE_TYPES = {"png", "jpeg", "tiff", "bmp", "gif", "webp"}


def environment(cfg: dict) -> dict:
    """What ran: versions and settings. Another expert needs this to repeat the run."""
    packages = {}
    for name in ("pillow", "numpy", "pikepdf"):
        try:
            packages[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            packages[name] = None
    try:
        import pikepdf

        packages["qpdf"] = str(pikepdf.__libqpdf_version__)
    except Exception:  # noqa: BLE001
        packages["qpdf"] = None
    return {
        "tool": {"name": TOOL_NAME, "version": __version__},
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
        "packages": packages,
        "config": cfg,
        "config_sha256": config_sha256(cfg),
    }


def _extension_findings(record: dict) -> list[dict]:
    media = record["media_type"]
    extension = PurePath(record["name"] or "").suffix.lower()
    if media == "unknown":
        return [finding("FILE-UNKNOWN-TYPE", "notice", "The file type is not known to this tool.",
                        detail="The file is stored and hashed. No content checks were run.",
                        limits="This tool reads PDF and common image files only.")]
    if extension and extension not in USUAL_EXTENSIONS[media]:
        return [finding("FILE-EXT-MISMATCH", "notice", "The file name does not fit the file content.",
                        detail=f"The name ends in {extension}, but the content is {media.upper()}.",
                        limits="A renamed file causes this. It is not a sign of a change to the content.",
                        extension=extension, content=media)]
    return []


def case_level_findings(evidence: list[dict], cfg: dict) -> list[dict]:
    out: list[dict] = []
    questioned = [rec for rec in evidence if rec["role"] == "questioned"]
    known = [rec for rec in evidence if rec["role"] == "known"]

    if not questioned:
        out.append(finding("CASE-NO-QUESTIONED", "warning", "The case has no questioned item.",
                           limits="Add the item that is in dispute with the role: questioned."))
    count_limit = ("This counts files. One file can hold more than one signature. "
                   "The numbers are a guide and are to be confirmed with practising examiners.")
    if not known:
        out.append(finding("CASE-NO-KNOWN", "warning", "The case has no known sample. A comparison is not possible.",
                           limits=count_limit, known_count=0))
    elif len(known) < cfg["known_count_notice_below"]:
        level = "warning" if len(known) < cfg["known_count_warning_below"] else "notice"
        out.append(finding("CASE-FEW-KNOWN", level, f"The case has only {len(known)} known sample(s).",
                           detail="More samples show how much the writer's own signature changes from day to day.",
                           limits=count_limit, known_count=len(known)))

    by_hash: dict[str, list[str]] = {}
    for rec in evidence:
        by_hash.setdefault(rec["sha256"], []).append(rec["id"])
    for ids in by_hash.values():
        if len(ids) > 1:
            out.append(finding("CASE-DUPLICATE", "warning", f"The same file was added more than once: {', '.join(ids)}.",
                               detail="The bytes are identical. One of them is not an independent sample.",
                               limits="This compares whole files only. It does not compare signatures inside different files.",
                               ids=ids))

    undated = [rec["id"] for rec in questioned + known if not rec.get("doc_date")]
    if undated:
        out.append(finding("CASE-DATE-MISSING", "notice", f"{len(undated)} item(s) have no document date.",
                           detail="Without dates, the tool cannot tell if the known samples are from the same period.",
                           limits="The date is the one that you enter. The tool does not read dates from the documents.",
                           ids=undated))

    window_days = cfg["contemporaneous_years"] * 365.25
    dated_known = [(rec["id"], date.fromisoformat(rec["doc_date"])) for rec in known if rec.get("doc_date")]
    for rec in questioned:
        if not rec.get("doc_date") or not dated_known:
            continue
        when = date.fromisoformat(rec["doc_date"])
        nearest_id, nearest_date = min(dated_known, key=lambda item: abs((item[1] - when).days))
        gap = abs((nearest_date - when).days)
        if gap > window_days:
            out.append(finding(
                "CASE-NOT-CONTEMPORANEOUS", "warning",
                f"No known sample is from within {cfg['contemporaneous_years']} years of {rec['id']}.",
                detail=f"The nearest is {nearest_id}, {gap} days away. Handwriting changes with age and health.",
                limits="The time window is a guide. For an old or ill writer, a much shorter window is needed.",
                questioned=rec["id"], nearest_known=nearest_id, gap_days=gap))
    return out


def run_checks(case, config: dict | None = None) -> dict:
    cfg = dict(config or DEFAULTS)
    evidence = case.state()["evidence"]
    case.ledger.append("env.recorded", environment(cfg))
    files: dict[str, dict] = {}
    cache: dict[str, tuple[str, dict]] = {}
    for record in evidence:
        if record["sha256"] not in cache:
            path = case.path / record["stored_as"]
            media = record["media_type"]
            if media in IMAGE_TYPES:
                result = analyse_image_file(path, cfg)
                cache[record["sha256"]] = ("image", {"metrics": result["metrics"], "findings": result["findings"]})
            elif media == "pdf":
                result = audit_pdf(path, cfg)
                cache[record["sha256"]] = ("pdf", {"facts": result["facts"], "findings": result["findings"]})
            else:
                cache[record["sha256"]] = ("unknown", {"findings": []})
        kind, payload = cache[record["sha256"]]
        data = {"evidence_id": record["id"], "sha256": record["sha256"], "kind": kind, **payload,
                "findings": _extension_findings(record) + payload["findings"]}
        case.ledger.append("check.file", data)
        files[record["id"]] = data
    case_findings = case_level_findings(evidence, cfg)
    case.ledger.append("check.case", {"findings": case_findings})
    return {"files": files, "case_findings": case_findings}
