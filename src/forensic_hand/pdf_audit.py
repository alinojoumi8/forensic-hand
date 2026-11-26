"""PDF structure screen. Fixed rules only: no model, no guess.

Each result is a fact about the file plus the normal reasons that can also cause it.
Metadata is easy to edit. Treat every result as a lead to follow, never as proof alone.
"""

from __future__ import annotations

import io
import math
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pikepdf

from .config import DEFAULTS
from .findings import finding
from .quality import edge_sharpness, sharpness_findings
from .verify_case import sha256_hex

MAX_PAGES = 500
MAX_IMAGES = 400
MAX_REVISIONS = 20
MAX_DECODED_IMAGES = 20
MAX_FORM_DEPTH = 6
# Work limits for one file, all pages together. A small PDF can reuse drawings (Form XObjects)
# so that they expand to millions of placements. These limits stop that and report it.
MAX_OPERATORS = 1_000_000
MAX_FORM_PLACEMENTS = 5_000
MAX_PAGE_IMAGE_RECORDS = 1_000
IDENTITY = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)

_SECTION_END = re.compile(rb"startxref\s+(\d+)\s+%%EOF")
_PDF_DATE = re.compile(
    r"^(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?\s*(?:(Z)|([+-])(\d{2})'?(\d{2})?'?)?$")
_CONTENT_ANNOTS = {
    "FreeText", "Stamp", "Ink", "Square", "Circle", "Line", "Polygon", "PolyLine", "Redact", "Caret",
    "FileAttachment", "Text", "Highlight", "Underline", "StrikeOut", "Squiggly", "Watermark",
}
_XMP_KEYS = {
    "CreateDate": b"xmp:CreateDate", "ModifyDate": b"xmp:ModifyDate", "MetadataDate": b"xmp:MetadataDate",
    "CreatorTool": b"xmp:CreatorTool", "Producer": b"pdf:Producer",
    "DocumentID": b"xmpMM:DocumentID", "InstanceID": b"xmpMM:InstanceID",
}

_L_META = "Dates and program names in a PDF are plain text. Anyone can edit them. Many normal programs rewrite them."
_L_UPDATE = ("Normal actions also save a file this way: a digital signature, a filled form field, a comment, "
             "and some scanners. This does not show what was changed or who changed it.")
_L_LAYER = ("Some scanners split one page into layers. Programs also add logos, stamps and page numbers this way. "
            "This does not show who added it, or when.")
_L_DPI = "The value is computed from the picture size and its size on the page. It is exact for this file."
_L_SIG = "This tool does not test if a digital signature is valid. Use a signature validation tool for that."


# ---------------------------------------------------------------- small helpers

def _pdf_datetime(raw) -> datetime | None:
    match = _PDF_DATE.match(str(raw or "").strip())
    if not match:
        return None
    year, month, day, hour, minute, second, zulu, sign, tz_h, tz_m = match.groups()
    try:
        stamp = datetime(int(year), int(month or 1), int(day or 1), int(hour or 0), int(minute or 0), int(second or 0))
        if zulu:
            return stamp.replace(tzinfo=UTC)
        if sign:
            offset = timedelta(hours=int(tz_h), minutes=int(tz_m or 0))
            return stamp.replace(tzinfo=timezone(offset if sign == "+" else -offset))
        return stamp
    except ValueError:
        return None


def parse_pdf_date(raw) -> str | None:
    """Turn a PDF date such as D:20240101120000Z into ISO text. Return None when it is not a date."""
    stamp = _pdf_datetime(raw)
    return stamp.isoformat() if stamp else None


def _seconds_between(a: datetime, b: datetime) -> float:
    if (a.tzinfo is None) != (b.tzinfo is None):
        a, b = a.replace(tzinfo=None), b.replace(tzinfo=None)
    return (b - a).total_seconds()


def _text(value, limit: int = 300) -> str:
    try:
        text = str(value)
    except Exception:  # noqa: BLE001
        return ""
    return re.sub(r"[\x00-\x1f\x7f]", " ", text).strip()[:limit]


def _name(value) -> str:
    return _text(value).lstrip("/")


def _mul(m1, m2):
    a1, b1, c1, d1, e1, f1 = m1
    a2, b2, c2, d2, e2, f2 = m2
    return (a1 * a2 + b1 * c2, a1 * b2 + b1 * d2, c1 * a2 + d1 * c2, c1 * b2 + d1 * d2,
            e1 * a2 + f1 * c2 + e2, e1 * b2 + f1 * d2 + f2)


def _inherited(obj, key: str):
    for _ in range(50):
        if obj is None:
            return None
        value = obj.get(key)
        if value is not None:
            return value
        obj = obj.get("/Parent")
    return None


def _r(value: float, digits: int = 2) -> float:
    return round(float(value), digits)


# ---------------------------------------------------------------- raw bytes

def scan_raw(data: bytes) -> dict:
    """Facts that come from the bytes alone, before any PDF library reads the file."""
    header = re.search(rb"%PDF-(\d\.\d)", data[:1024])
    ends = []
    for match in _SECTION_END.finditer(data):
        end = match.end()
        if data[end:end + 2] == b"\r\n":
            end += 2
        elif data[end:end + 1] in (b"\n", b"\r"):
            end += 1
        ends.append(end)
    linearized = bool(re.search(rb"/Linearized\s", data[:2048]))
    trailing = len(data) - ends[-1] if ends and data[ends[-1]:].strip() else 0
    return {
        "size": len(data),
        "header_version": header.group(1).decode("ascii") if header else None,
        "header_offset": header.start() if header else None,
        "section_ends": ends,
        "linearized": linearized,
        "incremental_updates": max(0, len(ends) - 1 - (1 if linearized else 0)),
        "trailing_bytes": trailing,
    }


def _earlier_revisions(data: bytes, raw: dict) -> list[dict]:
    """Each save leaves the older file inside the newer one. List the older files."""
    ends = raw["section_ends"][:-1]
    if raw["linearized"]:
        ends = ends[1:]
    out = []
    for index, end in enumerate(ends[:MAX_REVISIONS], start=1):
        item = {"revision": index, "end": end, "sha256": sha256_hex(data[:end]),
                "opens": False, "pages": None, "producer": None, "mod_date": None}
        try:
            with pikepdf.open(io.BytesIO(data[:end])) as old:
                info = old.trailer.get("/Info")
                item.update(opens=True, pages=len(old.pages))
                if info is not None:
                    item["producer"] = _text(info.get("/Producer", "")) or None
                    item["mod_date"] = parse_pdf_date(info.get("/ModDate", ""))
        except Exception:  # noqa: BLE001 - an old revision that does not open is a fact, not an error
            item["opens"] = False
        out.append(item)
    return out


# ---------------------------------------------------------------- metadata and signatures

def _info_facts(pdf) -> tuple[dict, dict]:
    info, dates = {}, {}
    source = pdf.trailer.get("/Info")
    if source is None:
        return info, dates
    for key in ("Producer", "Creator", "Title", "Author", "Subject", "CreationDate", "ModDate"):
        try:
            value = source.get("/" + key)
        except Exception:  # noqa: BLE001
            value = None
        if value is None:
            continue
        text = _text(value)
        if key.endswith("Date"):
            stamp = _pdf_datetime(text)
            if stamp:
                dates[key] = stamp
            info[key] = stamp.isoformat() if stamp else text
        elif text:
            info[key] = text
    return info, dates


def _xmp_facts(pdf) -> dict:
    try:
        stream = pdf.Root.get("/Metadata")
        raw = stream.read_bytes() if stream is not None else b""
    except Exception:  # noqa: BLE001
        return {}
    out = {}
    for label, tag in _XMP_KEYS.items():
        match = (re.search(rb"<" + tag + rb"(?:\s[^>]*)?>([^<]{0,300})</" + tag + rb">", raw)
                 or re.search(tag + rb"\s*=\s*\"([^\"]{0,300})\"", raw))
        if match:
            out[label] = _text(match.group(1).decode("utf-8", "replace"))
    if raw:
        out["history_entries"] = len(re.findall(rb"stEvt:action", raw))
    return out


def _signatures(pdf, size: int) -> list[dict]:
    out = []
    for obj in pdf.objects:
        try:
            if not isinstance(obj, pikepdf.Dictionary) or "/ByteRange" not in obj or "/Contents" not in obj:
                continue
            byte_range = [int(v) for v in obj["/ByteRange"]]
            if len(byte_range) != 4:
                continue
            end = byte_range[2] + byte_range[3]
            out.append({
                "byte_range": byte_range,
                "signed_end": end,
                "covers_whole_file": byte_range[0] == 0 and end == size,
                "subfilter": _name(obj.get("/SubFilter", "")),
                "signing_time_claimed": parse_pdf_date(obj.get("/M", "")),
                "signer_name_claimed": _text(obj.get("/Name", "")) or None,
            })
        except Exception:  # noqa: BLE001, S112 - a broken object must not stop the audit
            continue
    return sorted(out, key=lambda sig: sig["signed_end"])


# ---------------------------------------------------------------- page content

class _Budget:
    """Work left for one file. Shared by every page and every nested drawing."""

    def __init__(self) -> None:
        self.operators = MAX_OPERATORS
        self.forms = MAX_FORM_PLACEMENTS
        self.exhausted = False
        self.stopped_on_page: int | None = None


class _BudgetExhausted(Exception):
    pass


class _PageScan:
    def __init__(self, budget: _Budget) -> None:
        self.budget = budget
        self.images: list[dict] = []
        self.images_not_kept = 0
        self.visible_text = 0
        self.invisible_text = 0

    def spend(self, kind: str) -> None:
        left = getattr(self.budget, kind) - 1
        setattr(self.budget, kind, left)
        if left < 0:
            self.budget.exhausted = True
            raise _BudgetExhausted

    def add_image(self, record: dict) -> None:
        if len(self.images) < MAX_PAGE_IMAGE_RECORDS:
            self.images.append(record)
        else:
            self.images_not_kept += 1


def _walk(target, resources, ctm, scan: _PageScan, depth: int) -> None:
    stack, render_mode = [], 0
    xobjects = resources.get("/XObject") if resources is not None else None
    for item in pikepdf.parse_content_stream(target):
        scan.spend("operators")
        operator = str(item.operator)
        operands = item.operands
        if operator == "q":
            stack.append((ctm, render_mode))
        elif operator == "Q":
            if stack:
                ctm, render_mode = stack.pop()
        elif operator == "cm" and len(operands) == 6:
            ctm = _mul(tuple(float(v) for v in operands), ctm)
        elif operator == "Tr" and operands:
            render_mode = int(operands[0])
        elif operator in ("Tj", "'", '"', "TJ") and operands:
            last = operands[-1]
            parts = list(last) if operator == "TJ" else [last]
            count = sum(len(bytes(p)) for p in parts if isinstance(p, pikepdf.String))
            if render_mode == 3:
                scan.invisible_text += count
            else:
                scan.visible_text += count
        elif operator == "INLINE IMAGE":
            image = getattr(item, "iimage", None)
            scan.add_image(_image_record(getattr(image, "width", 0), getattr(image, "height", 0), ctm, "inline", None))
        elif operator == "Do" and operands and xobjects is not None:
            xobj = xobjects.get(operands[0])
            if xobj is None:
                continue
            subtype = _name(xobj.get("/Subtype", ""))
            if subtype == "Image":
                record = _image_record(int(xobj.get("/Width", 0)), int(xobj.get("/Height", 0)), ctm,
                                       _name(xobj.get("/Filter", "")) or "none", xobj)
                record["stencil_mask"] = bool(xobj.get("/ImageMask", False))
                scan.add_image(record)
            elif subtype == "Form" and depth < MAX_FORM_DEPTH:
                scan.spend("forms")
                matrix = xobj.get("/Matrix")
                inner = _mul(tuple(float(v) for v in matrix), ctm) if matrix is not None and len(matrix) == 6 else ctm
                _walk(xobj, xobj.get("/Resources", resources), inner, scan, depth + 1)


def _image_record(width: int, height: int, ctm, filter_name: str, xobj) -> dict:
    drawn_w = math.hypot(ctm[0], ctm[1])
    drawn_h = math.hypot(ctm[2], ctm[3])
    record = {
        "width": int(width), "height": int(height),
        "drawn_w_pt": _r(drawn_w), "drawn_h_pt": _r(drawn_h),
        "dpi_x": _r(width * 72.0 / drawn_w, 1) if drawn_w > 0.01 else None,
        "dpi_y": _r(height * 72.0 / drawn_h, 1) if drawn_h > 0.01 else None,
        "filter": filter_name,
    }
    record["_xobj"] = xobj
    return record


def _scan_page(page_obj, number: int, cfg: dict, budget: _Budget) -> tuple[dict, list[dict]]:
    box = _inherited(page_obj, "/MediaBox")
    unit = float(page_obj.get("/UserUnit", 1))
    x0, y0, x1, y1 = (float(v) for v in box)
    page_w, page_h = abs(x1 - x0) * unit, abs(y1 - y0) * unit
    scan = _PageScan(budget)
    try:
        _walk(pikepdf.Page(page_obj), _inherited(page_obj, "/Resources"), IDENTITY, scan, 0)
    except _BudgetExhausted:
        budget.stopped_on_page = number   # keep what was read so far
    area = max(page_w * page_h, 1.0)
    for image in scan.images:
        image["page"] = number
        image["page_coverage"] = _r(min(1.0, image["drawn_w_pt"] * unit * image["drawn_h_pt"] * unit / area), 3)
    annots: dict[str, int] = {}
    for annot in page_obj.get("/Annots", []) or []:
        try:
            subtype = _name(annot.get("/Subtype", "")) or "unknown"
        except Exception:  # noqa: BLE001
            subtype = "unknown"
        if subtype not in ("Link", "Popup"):
            annots[subtype] = annots.get(subtype, 0) + 1
    facts = {"page": number, "width_pt": _r(page_w), "height_pt": _r(page_h),
             "images": len(scan.images) + scan.images_not_kept,
             "visible_text_bytes": scan.visible_text, "invisible_text_bytes": scan.invisible_text,
             "annotations": annots}
    return facts, scan.images


# ---------------------------------------------------------------- the audit

def audit_pdf(path, config: dict | None = None) -> dict:
    """Screen one PDF file. A broken file gives a finding, not a crash."""
    cfg = config or DEFAULTS
    data = Path(path).read_bytes()
    raw = scan_raw(data)
    facts: dict = {
        "size": raw["size"], "header_version": raw["header_version"], "linearized": raw["linearized"],
        "incremental_updates": raw["incremental_updates"], "trailing_bytes": raw["trailing_bytes"],
        "revisions": [], "signatures": [], "pages": None, "info": {}, "xmp": {},
        "page_facts": [], "page_images": [],
    }
    out: list[dict] = []

    try:
        pdf = pikepdf.open(io.BytesIO(data))
    except pikepdf.PasswordError:
        out.append(finding("PDF-ENCRYPTED", "warning", "The PDF needs a password. It was not examined.",
                           limits="The file is stored and hashed. Its content is not checked."))
        return {"facts": facts, "findings": out}
    except Exception as exc:  # noqa: BLE001 - any reader failure becomes a finding
        out.append(finding("PDF-UNREADABLE", "warning", "The file could not be read as a PDF.",
                           detail=f"{type(exc).__name__}: {str(exc)[:200]}",
                           limits="A file that does not open here can still open in another program."))
        return {"facts": facts, "findings": out}

    with pdf:
        facts["pages"] = len(pdf.pages)
        facts["pdf_version"] = _text(pdf.pdf_version)
        facts["encrypted"] = bool(pdf.is_encrypted)
        # Keep the message only. The part before ": " names a memory address, which changes on each run.
        facts["reader_warnings"] = [_text(str(w).split(": ", 1)[-1], 200) for w in pdf.get_warnings()][:10]
        info, dates = _info_facts(pdf)
        facts["info"], facts["xmp"] = info, _xmp_facts(pdf)
        facts["signatures"] = _signatures(pdf, raw["size"])
        facts["revisions"] = _earlier_revisions(data, raw)
        out.extend(_structure_findings(raw, facts, dates, cfg))
        out.extend(_page_findings(pdf, facts, cfg))
    return {"facts": facts, "findings": out}


def _structure_findings(raw: dict, facts: dict, dates: dict, cfg: dict) -> list[dict]:
    out: list[dict] = []
    tolerance = cfg["pdf_date_tolerance_seconds"]

    if raw["header_offset"]:
        out.append(finding("PDF-JUNK-BEFORE-HEADER", "notice", "There are bytes before the start of the PDF.",
                           detail=f"{raw['header_offset']} byte(s).",
                           limits="Some mail systems and old programs add bytes here.", bytes=raw["header_offset"]))
    if raw["trailing_bytes"]:
        out.append(finding("PDF-TRAILING-DATA", "notice", "There is data after the end of the PDF.",
                           detail=f"{raw['trailing_bytes']} byte(s) after the last end marker. A PDF reader ignores them.",
                           limits="Some programs add harmless bytes here. Look at the bytes to know what they are.",
                           bytes=raw["trailing_bytes"]))
    if facts["reader_warnings"]:
        out.append(finding("PDF-READER-WARNING", "notice", "The file structure is unusual. The PDF reader gave a warning.",
                           detail="Reader message: " + " / ".join(facts["reader_warnings"][:3]),
                           limits="A bad download, an old program or a rare PDF feature also causes this. "
                                  "It shows that a program wrote the file in an unusual way, not who or why.",
                           count=len(facts["reader_warnings"])))
    if facts["encrypted"]:
        out.append(finding("PDF-ENCRYPTED", "info", "The PDF is encrypted, but it opens with no password.",
                           limits="Many programs encrypt a file only to limit print or copy."))

    updates = raw["incremental_updates"]
    if updates:
        recoverable = sum(1 for rev in facts["revisions"] if rev["opens"])
        out.append(finding(
            "PDF-INCREMENTAL", "notice",
            f"The file was saved again {updates} time(s) after it was first written.",
            detail=f"{recoverable} earlier version(s) are still inside the file and can be opened and compared.",
            limits=_L_UPDATE, updates=updates, recoverable=recoverable))

    created, modified = dates.get("CreationDate"), dates.get("ModDate")
    if created and modified and _seconds_between(created, modified) > tolerance:
        out.append(finding("PDF-MODIFIED-DATE", "notice", "The file says it was changed after it was made.",
                           detail=f"Made {created.isoformat()}, changed {modified.isoformat()}.",
                           limits=_L_META, created=created.isoformat(), modified=modified.isoformat()))

    xmp, info = facts["xmp"], facts["info"]
    differences = []
    if xmp.get("Producer") and info.get("Producer") and xmp["Producer"] != info["Producer"]:
        differences.append("program name")
    xmp_modified = _iso_datetime(xmp.get("ModifyDate"))
    if xmp_modified and modified and abs(_seconds_between(modified, xmp_modified)) > tolerance:
        differences.append("change date")
    if differences:
        out.append(finding("PDF-META-MISMATCH", "notice", "The two metadata blocks of the file do not agree.",
                           detail="They differ in: " + ", ".join(differences) + ".",
                           limits=_L_META + " A program that updates only one block causes this.",
                           fields=differences))

    sigs = facts["signatures"]
    if sigs:
        out.append(finding("PDF-SIG-PRESENT", "info", f"The file holds {len(sigs)} digital signature(s).",
                           limits=_L_SIG, count=len(sigs)))
        last = sigs[-1]
        after = raw["size"] - last["signed_end"]
        if after > 0:
            out.append(finding(
                "PDF-SIG-AFTER", "warning", "Bytes were added to the file after the last digital signature.",
                detail=f"{after} byte(s) are not covered by any signature.",
                limits="A later time stamp or validation data also adds bytes, with no change to what you see. " + _L_SIG,
                bytes_after_signature=after))
        elif after < 0:
            out.append(finding("PDF-SIG-RANGE", "notice", "A digital signature points past the end of the file.",
                               detail="The file can be cut short.", limits=_L_SIG))
    return out


def _iso_datetime(text) -> datetime | None:
    try:
        return datetime.fromisoformat(str(text)) if text else None
    except ValueError:
        return None


def _page_findings(pdf, facts: dict, cfg: dict) -> list[dict]:
    out: list[dict] = []
    low_dpi, mid_dpi, ocr_pages, failed, decoded = [], [], [], [], 0
    annot_types: dict[str, int] = {}
    annot_pages: list[int] = []
    budget = _Budget()

    for number, page in enumerate(pdf.pages, start=1):
        if budget.exhausted:
            break
        if number > MAX_PAGES:
            out.append(finding("PDF-PAGE-LIMIT", "notice", f"Only the first {MAX_PAGES} pages were checked.",
                               limits="The rest of the file is stored and hashed, but not screened."))
            break
        try:
            page_facts, images = _scan_page(page.obj, number, cfg, budget)
        except Exception:  # noqa: BLE001 - one bad page must not stop the audit
            failed.append(number)
            continue
        facts["page_facts"].append(page_facts)

        main = max(images, key=lambda im: im["page_coverage"], default=None)
        is_scan = main is not None and main["page_coverage"] >= cfg["pdf_scan_coverage"]
        if is_scan:
            # Round first: a page scanned at "150 DPI" computes to 149.9 or 150.1 from the page size.
            dpis = [round(d) for d in (main["dpi_x"], main["dpi_y"]) if d]
            if dpis and min(dpis) < cfg["dpi_warning_below"]:
                low_dpi.append((number, min(dpis)))
            elif dpis and min(dpis) < cfg["dpi_notice_below"]:
                mid_dpi.append((number, min(dpis)))
            if decoded < MAX_DECODED_IMAGES and main.get("_xobj") is not None:
                decoded += 1
                score = _image_sharpness(main["_xobj"], cfg)
                if score is not False:
                    main["sharpness"] = score
                    out.extend(sharpness_findings(score, cfg, prefix="PDF-IMG", where=f"Page {number}: the scan")
                               if score is not None else [])
            overlays = [im for im in images if im is not main and not im.get("stencil_mask")
                        and im["page_coverage"] < cfg["pdf_overlay_max_coverage"]
                        and im["drawn_w_pt"] >= 10 and im["drawn_h_pt"] >= 10]
            if overlays:
                out.append(finding(
                    "PDF-IMAGE-OVERLAY", "notice",
                    f"Page {number}: {len(overlays)} smaller picture(s) lie on top of a full-page picture.",
                    detail="A signature that was pasted onto a scan looks like this. Compare the resolution of the pictures.",
                    limits=_L_LAYER, page=number, count=len(overlays),
                    scan_dpi=min(dpis) if dpis else None,
                    overlay_dpi=[im["dpi_x"] for im in overlays[:10]]))
            if page_facts["visible_text_bytes"]:
                out.append(finding(
                    "PDF-TEXT-OVER-SCAN", "notice", f"Page {number}: typed text lies on top of a scanned picture.",
                    detail=f"{page_facts['visible_text_bytes']} byte(s) of visible text were added as text, not as part of the scan.",
                    limits=_L_LAYER + " Page numbers and headers added by a program are typical.",
                    page=number, bytes=page_facts["visible_text_bytes"]))
        if page_facts["invisible_text_bytes"]:
            ocr_pages.append(number)
        if page_facts["annotations"]:
            annot_pages.append(number)
            for subtype, count in page_facts["annotations"].items():
                annot_types[subtype] = annot_types.get(subtype, 0) + count
        for image in images:
            image.pop("_xobj", None)
            if len(facts["page_images"]) < MAX_IMAGES:
                facts["page_images"].append(image)

    if low_dpi:
        out.append(finding("PDF-IMG-DPI-LOW", "warning", "Scanned page(s) have a resolution too low for fine stroke detail.",
                           detail=f"Lowest: {min(d for _, d in low_dpi)} DPI (warning below {cfg['dpi_warning_below']}).",
                           limits=_L_DPI, pages=[p for p, _ in low_dpi][:50], lowest_dpi=min(d for _, d in low_dpi)))
    if mid_dpi:
        out.append(finding("PDF-IMG-DPI-BELOW-300", "notice", "Scanned page(s) have a resolution below 300 DPI.",
                           detail=f"Lowest: {min(d for _, d in mid_dpi)} DPI.",
                           limits=_L_DPI, pages=[p for p, _ in mid_dpi][:50], lowest_dpi=min(d for _, d in mid_dpi)))
    if ocr_pages:
        out.append(finding("PDF-OCR-LAYER", "info", "The file has a hidden text layer (text recognition).",
                           detail="The hidden text can differ from what the picture shows.",
                           limits="Scanners add this layer so that you can search the text. It is normal.",
                           pages=ocr_pages[:50]))
    if annot_types:
        level = "notice" if set(annot_types) & _CONTENT_ANNOTS else "info"
        out.append(finding("PDF-ANNOTATIONS", level, "Items were added on top of the page content (annotations).",
                           detail=", ".join(f"{count} x {name}" for name, count in sorted(annot_types.items())) + ".",
                           limits="Comments, form fields and signature boxes are annotations. They are separate from the page "
                                  "content and can be added or removed at any time.",
                           by_type=annot_types, pages=annot_pages[:50]))
    if budget.exhausted:
        out.append(finding(
            "PDF-SCREEN-INCOMPLETE", "warning", "The page content is too complex. Screening of this file is not complete.",
            detail=f"Screening stopped on page {budget.stopped_on_page} of {facts['pages']}. "
                   "Notes for that page and the pages after it can be missing.",
            limits="Very complex drawings, or drawings that repeat themselves many times, cause this. "
                   "It does not show what the content is or who made it.",
            stopped_on_page=budget.stopped_on_page, operator_limit=MAX_OPERATORS, form_limit=MAX_FORM_PLACEMENTS))
    if failed:
        out.append(finding("PDF-PAGE-ERROR", "notice", "The content of some pages could not be read.",
                           detail=f"Pages: {', '.join(str(n) for n in failed[:30])}.",
                           limits="These pages are stored and hashed, but not screened.", pages=failed[:50]))
    return out


def _image_sharpness(xobj, cfg: dict):
    """Return the sharpness score, None when it cannot be measured, False when the picture cannot be decoded."""
    try:
        import numpy as np

        image = pikepdf.PdfImage(xobj).as_pil_image()
        gray = np.asarray(image.convert("L"))
        return edge_sharpness(gray, cfg["sharpness_tile_px"], cfg["sharpness_min_contrast"])["score"]
    except Exception:  # noqa: BLE001 - some image codecs are not supported; that is not a finding
        return False
