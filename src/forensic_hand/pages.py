"""Pages of an evidence file: their size, preview pictures, and exact regions for crops.

Pictures (PNG, JPEG, TIFF ...) are read as pixels. A crop of a picture is the exact source
pixels, with no resampling. PDF pages are drawn by PDFium; a crop of a PDF page is a new
drawing at a stated resolution, and the record says so.
"""

from __future__ import annotations

import math
import threading
from collections import OrderedDict
from pathlib import Path

import pikepdf
import pypdfium2 as pdfium
from PIL import Image

from .case import CaseError
from .quality import _clean_dpi

IMAGE_TYPES = {"png", "jpeg", "tiff", "bmp", "gif", "webp"}
MAX_PREVIEW_WIDTH = 4000
MIN_CROP_DPI, MAX_CROP_DPI, DEFAULT_PDF_DPI = 72, 1200, 300
MAX_RENDER_PIXELS = 60_000_000
MIN_BOX_SIDE = 4
PNG_SAFE_MODES = {"1", "L", "LA", "P", "RGB", "RGBA", "I;16"}

_cache: OrderedDict = OrderedDict()
_cache_lock = threading.Lock()
# PDFium is not safe to call from two threads at once.
_pdfium_lock = threading.Lock()


def _cached(key, make):
    with _cache_lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]
    value = make()
    with _cache_lock:
        _cache[key] = value
        while len(_cache) > 64:
            _cache.popitem(last=False)
    return value


def renderer_info() -> dict:
    return {"name": "pdfium", "version": str(pdfium.PDFIUM_INFO), "pypdfium2": str(pdfium.PYPDFIUM_INFO)}


def _source(case, record) -> Path:
    return case.path / record["stored_as"]


def _pdf_scan_dpi(path: Path) -> dict[int, int]:
    """Resolution of the picture that fills each page (a scan), by page number."""
    from .config import DEFAULTS
    from .pdf_audit import _Budget, _BudgetExhausted, _scan_page

    out: dict[int, int] = {}
    try:
        with pikepdf.open(path) as pdf:
            budget = _Budget()
            for number, page in enumerate(pdf.pages, start=1):
                try:
                    _, images = _scan_page(page.obj, number, DEFAULTS, budget)
                except _BudgetExhausted:
                    break
                except Exception:  # noqa: BLE001, S112 - a page that cannot be read has no known resolution
                    continue
                full = [im for im in images if im.get("page_coverage", 0) >= DEFAULTS["pdf_scan_coverage"]
                        and im.get("dpi_x") and im.get("dpi_y")]
                if full:
                    best = max(full, key=lambda im: im["page_coverage"])
                    out[number] = round(min(best["dpi_x"], best["dpi_y"]))
                if budget.exhausted:
                    break
    except Exception:  # noqa: BLE001 - the resolution is a help, not a must
        return out
    return out


def page_geometry(case, record) -> list[dict]:
    """One entry per page: units (px for pictures, pt for PDF), width, height, resolution."""
    media = record["media_type"]
    path = _source(case, record)

    def make():
        if media in IMAGE_TYPES:
            pages = []
            with Image.open(path) as img:
                for index in range(getattr(img, "n_frames", 1)):
                    img.seek(index)
                    pages.append({"page": index + 1, "units": "px", "width": img.width, "height": img.height,
                                  "dpi": _clean_dpi(img.info.get("dpi"))})
            return pages
        if media == "pdf":
            dpis = _pdf_scan_dpi(path)
            pages = []
            with _pdfium_lock:
                doc = pdfium.PdfDocument(str(path))
                try:
                    for index in range(len(doc)):
                        width, height = doc[index].get_size()
                        dpi = dpis.get(index + 1)
                        pages.append({"page": index + 1, "units": "pt", "width": round(width, 2),
                                      "height": round(height, 2), "dpi": [dpi, dpi] if dpi else None})
                finally:
                    doc.close()
            return pages
        return []

    try:
        return _cached(("geo", record["sha256"], media), make)
    except CaseError:
        raise
    except Exception as exc:
        raise CaseError(f"{record['id']}: the pages cannot be read ({type(exc).__name__})") from exc


def _page(case, record, page) -> dict:
    pages = page_geometry(case, record)
    if not isinstance(page, int) or isinstance(page, bool) or not 1 <= page <= len(pages):
        raise CaseError(f"{record['id']} has no page {page} (it has {len(pages)})")
    return pages[page - 1]


def _open_frame(path: Path, page: int) -> Image.Image:
    img = Image.open(path)
    img.seek(page - 1)
    img.load()
    return img


def render_preview(case, record, page, width: int) -> Image.Image:
    """A picture of a page for the screen. Not evidence: it is resized to fit."""
    geo = _page(case, record, page)
    width = max(16, min(int(width), MAX_PREVIEW_WIDTH))
    path = _source(case, record)

    def make():
        if geo["units"] == "px":
            with _open_frame(path, page) as frame:
                img = frame.convert("RGB")
            height = max(1, round(img.height * width / img.width))
            return img.resize((width, height), Image.LANCZOS)
        with _pdfium_lock:
            doc = pdfium.PdfDocument(str(path))
            try:
                return doc[page - 1].render(scale=width / geo["width"]).to_pil().convert("RGB")
            finally:
                doc.close()

    try:
        return _cached(("preview", record["sha256"], page, width), make)
    except Exception as exc:
        raise CaseError(f"{record['id']} page {page} cannot be drawn ({type(exc).__name__})") from exc


def _check_box(box, geo) -> list[float]:
    if not isinstance(box, list | tuple) or len(box) != 4:
        raise CaseError("the box must be four numbers: left, top, right, bottom")
    try:
        x0, y0, x1, y1 = (float(v) for v in box)
    except (TypeError, ValueError):
        raise CaseError("the box must be four numbers: left, top, right, bottom") from None
    if not all(math.isfinite(v) for v in (x0, y0, x1, y1)):
        raise CaseError("the box must be four finite numbers")
    if x0 < 0 or y0 < 0 or x1 > geo["width"] or y1 > geo["height"]:
        raise CaseError(f"the box is outside the page ({geo['width']} x {geo['height']} {geo['units']})")
    if x1 - x0 < MIN_BOX_SIDE or y1 - y0 < MIN_BOX_SIDE:
        raise CaseError("the box is too small")
    return [x0, y0, x1, y1]


def region(case, record, page, box, dpi=None) -> tuple[Image.Image, dict]:
    """The pixels of one area of a page, and how they were made."""
    geo = _page(case, record, page)
    x0, y0, x1, y1 = _check_box(box, geo)
    path = _source(case, record)
    if geo["units"] == "px":
        if dpi is not None:
            raise CaseError("a resolution can be chosen only for PDF pages; picture crops keep their own pixels")
        ibox = [round(x0), round(y0), round(x1), round(y1)]
        with _open_frame(path, page) as frame:
            img = frame.crop(tuple(ibox))
            img.load()
        converted = None
        if img.mode not in PNG_SAFE_MODES:
            converted = f"{img.mode} to RGB"
            img = img.convert("RGB")
        return img, {"units": "px", "box": ibox, "method": "pixels", "dpi": geo["dpi"], "render_dpi": None,
                     "renderer": None, "converted": converted}
    if dpi is None:
        dpi = geo["dpi"][0] if geo["dpi"] else DEFAULT_PDF_DPI
    if not isinstance(dpi, int | float) or isinstance(dpi, bool) or not MIN_CROP_DPI <= dpi <= MAX_CROP_DPI:
        raise CaseError(f"the resolution must be between {MIN_CROP_DPI} and {MAX_CROP_DPI} DPI")
    dpi = round(dpi)
    scale = dpi / 72.0
    if (x1 - x0) * scale * (y1 - y0) * scale > MAX_RENDER_PIXELS:
        raise CaseError("the area is too large at this resolution; choose a smaller box or a lower resolution")
    with _pdfium_lock:
        doc = pdfium.PdfDocument(str(path))
        try:
            pdf_page = doc[page - 1]
            # pypdfium2 draws the full page on a grid of ceil(size * scale) pixels and cuts
            # ceil(cut * scale) pixels from each side. Choose the pixel edges here, then pass cuts
            # that land exactly on them, so the crop is the same sub-picture of the full page.
            full_w = math.ceil(pdf_page.get_width() * scale)
            full_h = math.ceil(pdf_page.get_height() * scale)
            px0, py0 = math.floor(x0 * scale + 1e-6), math.floor(y0 * scale + 1e-6)
            px1, py1 = min(full_w, math.ceil(x1 * scale - 1e-6)), min(full_h, math.ceil(y1 * scale - 1e-6))
            cuts = [px0, full_h - py1, full_w - px1, py0]   # left, bottom, right, top, in pixels
            crop = tuple((c - 0.5) / scale if c > 0 else 0.0 for c in cuts)
            img = pdf_page.render(scale=scale, crop=crop).to_pil().convert("RGB")
        finally:
            doc.close()
    if img.size != (px1 - px0, py1 - py0):
        raise CaseError("the PDF renderer gave an unexpected picture size; the crop was not made")
    return img, {"units": "pt", "box": [round(v, 2) for v in (x0, y0, x1, y1)], "method": "pdfium-render",
                 "dpi": [dpi, dpi], "render_dpi": dpi, "pixel_box": [px0, py0, px1, py1],
                 "renderer": renderer_info(), "converted": None}
