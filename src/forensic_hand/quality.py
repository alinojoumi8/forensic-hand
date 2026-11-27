"""Image quality screen: resolution, sharpness, compression.

These checks tell the examiner what the picture is able to show. They say nothing about who
wrote a signature.
"""

from __future__ import annotations

import math

import numpy as np
from PIL import Image

from .config import DEFAULTS
from .findings import finding
from .imaging import to_8bit

# Standard JPEG luminance table (ITU T.81, Annex K). Used to estimate the quality setting.
_STD_LUMA = (
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
)
_STD_LUMA_SUM = sum(_STD_LUMA)

_EXIF_TAGS = {271: "Make", 272: "Model", 305: "Software", 306: "DateTime"}
_EXIF_GPS = 34853

_L_DPI = ("The number comes from the file. Cameras and software often write a default value "
          "such as 72 or 96. The true scan resolution can be different.")
_L_SHARP = ("The score is a screening value and is not validated on real casework. "
            "Thin or faint writing can give a low score on a good scan.")
_L_JPEG = ("The value is an estimate from the tables in the file. "
           "A file that was saved more than once can hide an earlier, stronger compression.")


def estimate_jpeg_quality(qtables) -> int | None:
    """Estimate the JPEG quality setting (1 to 100) from the first quantization table."""
    if not qtables:
        return None
    table = qtables.get(0, next(iter(qtables.values()))) if isinstance(qtables, dict) else qtables[0]
    values = list(table)
    if len(values) != 64:
        return None
    scale = 100.0 * sum(values) / _STD_LUMA_SUM
    if scale <= 0:
        return None
    quality = (200.0 - scale) / 2.0 if scale <= 100 else 5000.0 / scale
    return round(max(1.0, min(100.0, quality)))


def edge_sharpness(gray, tile: int = 512, min_contrast: float = 0.10) -> dict:
    """Score how sharp the strongest edges are. About 0.5 for a hard edge, lower when blurred.

    The picture is cut into tiles. A tile with too little contrast (blank paper) is skipped.
    The score of a tile is: median of its strongest gradients, divided by its contrast.
    The result is the median over the tiles, so a blank margin does not pull the score down.
    """
    pixels = np.asarray(gray)
    if pixels.dtype == bool:
        pixels = pixels.astype(np.uint8) * 255
    if pixels.ndim != 2:
        raise ValueError("edge_sharpness needs a grayscale picture")
    height, width = pixels.shape
    scores, total = [], 0
    for top in range(0, height, tile):
        for left in range(0, width, tile):
            block = pixels[top:top + tile, left:left + tile].astype(np.float32) / 255.0
            if block.shape[0] < 16 or block.shape[1] < 16:
                continue
            total += 1
            low, high = np.percentile(block, [0.1, 99.9])
            contrast = float(high - low)
            if contrast < min_contrast:
                continue
            grad_y, grad_x = np.gradient(block)
            magnitude = np.hypot(grad_x, grad_y)
            strong = magnitude[magnitude >= np.percentile(magnitude, 99.9)]
            scores.append(float(np.median(strong)) / contrast)
    if not scores:
        return {"score": None, "tiles_used": 0, "tiles_total": total}
    return {"score": round(float(np.median(scores)), 4), "tiles_used": len(scores), "tiles_total": total}


def _clean_dpi(raw) -> list[int] | None:
    try:
        x, y = float(raw[0]), float(raw[1])
    except (TypeError, ValueError, IndexError):
        return None
    if not (math.isfinite(x) and math.isfinite(y) and x > 1 and y > 1):
        return None
    return [round(x), round(y)]


def _exif_facts(img: Image.Image) -> dict:
    facts: dict = {}
    try:
        exif = img.getexif()
    except Exception:  # noqa: BLE001 - broken EXIF must never stop the intake
        return facts
    for tag, name in _EXIF_TAGS.items():
        value = exif.get(tag)
        if value:
            facts[name] = str(value).replace("\x00", "").strip()[:120]
    if exif.get(_EXIF_GPS):
        facts["has_gps"] = True   # the position itself is not copied into the ledger
    return facts


def sharpness_findings(score, cfg: dict, prefix: str = "IMG", where: str = "The picture") -> list[dict]:
    if score is None:
        return [finding(f"{prefix}-NO-DETAIL", "notice", f"{where} has no area with enough contrast to measure sharpness.",
                        limits="A blank or very faint page gives this result. It is not a sign of a problem by itself.")]
    if score < cfg["sharpness_warning_below"]:
        return [finding(f"{prefix}-BLUR", "warning", f"{where} is blurred. Fine stroke detail is lost.",
                        detail=f"Sharpness score {score} (warning below {cfg['sharpness_warning_below']}).",
                        limits=_L_SHARP, score=score)]
    if score < cfg["sharpness_notice_below"]:
        return [finding(f"{prefix}-SOFT", "notice", f"{where} is soft. Some fine stroke detail can be lost.",
                        detail=f"Sharpness score {score} (note below {cfg['sharpness_notice_below']}).",
                        limits=_L_SHARP, score=score)]
    return []


def analyse_image(img: Image.Image, config: dict | None = None) -> dict:
    cfg = config or DEFAULTS
    width, height = img.size
    dpi = _clean_dpi(img.info.get("dpi"))
    metrics: dict = {
        "format": img.format, "mode": img.mode, "width": width, "height": height, "dpi": dpi,
        "frames": int(getattr(img, "n_frames", 1)),
    }
    out: list[dict] = []

    if min(width, height) < cfg["min_side_px_warning_below"]:
        out.append(finding("IMG-SMALL", "warning", "The picture is very small.",
                           detail=f"{width} x {height} pixels.",
                           limits="A tight crop of one signature can be small and still usable. Check the resolution.",
                           width=width, height=height))

    if dpi is None:
        out.append(finding("IMG-DPI-UNKNOWN", "notice", "The file does not give its resolution (DPI).",
                           detail="Real sizes, such as the height of a letter in millimetres, cannot be measured.",
                           limits="A missing value does not mean that the scan is bad."))
    elif min(dpi) < cfg["dpi_warning_below"]:
        out.append(finding("IMG-DPI-LOW", "warning", "The resolution is too low for fine stroke detail.",
                           detail=f"{min(dpi)} DPI (warning below {cfg['dpi_warning_below']}).", limits=_L_DPI, dpi=min(dpi)))
    elif min(dpi) < cfg["dpi_notice_below"]:
        out.append(finding("IMG-DPI-BELOW-300", "notice", "The resolution is below 300 DPI.",
                           detail=f"{min(dpi)} DPI.", limits=_L_DPI, dpi=min(dpi)))

    gray = np.asarray(to_8bit(img).convert("L"))       # a 16-bit scan keeps its ink
    sharp = edge_sharpness(gray, cfg["sharpness_tile_px"], cfg["sharpness_min_contrast"])
    metrics["sharpness"] = sharp["score"]
    metrics["sharpness_tiles_used"] = sharp["tiles_used"]
    if img.mode == "1":
        out.append(finding("IMG-BILEVEL", "notice", "The picture is pure black and white, with no gray levels.",
                           detail="Shading inside a stroke is lost. Shading is one of the signs of pen pressure.",
                           limits="The outline of the writing can still be compared."))
        if sharp["score"] is None:
            out.extend(sharpness_findings(None, cfg))
    else:
        out.extend(sharpness_findings(sharp["score"], cfg))

    if img.format == "JPEG":
        quality = estimate_jpeg_quality(getattr(img, "quantization", None))
        metrics["jpeg_quality_estimate"] = quality
        if quality is not None and quality < cfg["jpeg_quality_notice_below"]:
            level = "warning" if quality < cfg["jpeg_quality_warning_below"] else "notice"
            out.append(finding("IMG-JPEG-QUALITY", level, "The picture has strong JPEG compression.",
                               detail=f"Estimated quality {quality} of 100. Compression adds blocks and halos near strokes.",
                               limits=_L_JPEG, quality=quality))

    exif = _exif_facts(img)
    if exif:
        metrics["exif"] = exif
    if exif.get("Make") or exif.get("Model"):
        out.append(finding("IMG-CAMERA", "info", "The file names a camera or phone.",
                           detail=f"{exif.get('Make', '')} {exif.get('Model', '')}".strip(),
                           limits="A photo is not a flat scan. Angle and light can change shapes. This text is easy to edit."))
    if exif.get("Software"):
        out.append(finding("IMG-SOFTWARE-TAG", "info", "The file names the software that saved it.",
                           detail=exif["Software"],
                           limits="Scanners and phones also write this field. It does not show that the picture was changed. "
                                  "This text is easy to edit."))
    return {"metrics": metrics, "findings": out}


def analyse_image_file(path, config: dict | None = None) -> dict:
    """Open one image file and screen it. A broken file gives a finding, not a crash."""
    try:
        with Image.open(path) as img:
            img.load()
            return analyse_image(img, config)
    except (OSError, ValueError, SyntaxError, Image.DecompressionBombError) as exc:
        return {"metrics": {}, "findings": [finding(
            "IMG-UNREADABLE", "warning", "The picture could not be opened.",
            detail=f"{type(exc).__name__}: {str(exc)[:200]}",
            limits="A file that does not open here can still open in another program.")]}
