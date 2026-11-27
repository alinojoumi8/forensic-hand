"""Small picture helpers shared by the screens, the charts and the report."""

from __future__ import annotations

import numpy as np
from PIL import Image

WIDE_GRAY = ("I", "I;16", "I;16L", "I;16B", "I;16N")


def to_8bit(img: Image.Image) -> Image.Image:
    """A 16-bit (or 32-bit integer) grey picture as 8-bit grey; any other picture is returned unchanged.

    A plain convert("L") or convert("RGB") clips every value above 255 to white, so the ink of a 16-bit
    scan would vanish. A value marked transparent in the file becomes white paper.
    """
    if img.mode not in WIDE_GRAY:
        return img
    values = np.asarray(img, dtype=np.float64)
    top = 65535.0 if values.size and float(values.max()) > 255 else 255.0
    out = np.clip(np.round(values / top * 255.0), 0, 255).astype(np.uint8)
    key = img.info.get("transparency")
    if isinstance(key, int | float) and not isinstance(key, bool):
        out[values == key] = 255
    return Image.fromarray(out)


_FRAME_ERRORS = (TypeError, ValueError, OSError, SyntaxError)
_JPEG_PREVIEW = 513            # TIFF tag JPEGInterchangeFormat: where a JPEG preview starts
_SIZE_TAGS = {256, 257}        # TIFF tags ImageWidth and ImageLength


def _is_jpeg_preview_block(img: Image.Image) -> bool:
    """True when the TIFF block that could not be read is the last one and is a JPEG preview with no size."""
    tags = getattr(img, "tag_v2", None)
    if tags is None:
        return False
    keys = set(tags.keys())
    return _JPEG_PREVIEW in keys and not keys & _SIZE_TAGS and not getattr(tags, "next", None)


def frame_count(img: Image.Image) -> tuple[int, str | None]:
    """The pages of a picture file that can be read, and what stopped the count.

    The second value is None (every page was read), "preview" (after the pages comes a last TIFF block that
    holds only a small JPEG preview with no size; some scanners write it), or "unreadable" (the page after
    the counted ones cannot be read, and pages after it were not counted). In both cases Pillow's page
    count (n_frames) raises an error and leaves the file on the broken block. So count page by page, and
    go back to the page the picture was on.
    """
    start = img.tell()
    try:
        return int(getattr(img, "n_frames", 1)), None
    except _FRAME_ERRORS:
        pass
    count, problem = 0, None
    while True:
        try:
            img.seek(count)
        except EOFError:
            break
        except _FRAME_ERRORS:
            problem = "preview" if _is_jpeg_preview_block(img) else "unreadable"
            break
        count += 1
    img.seek(start)
    return count, problem


def on_white(img: Image.Image) -> Image.Image:
    """An RGB picture in which transparent parts are white paper.

    Pillow's convert("RGB") drops the alpha channel. A transparent PNG with black writing on
    transparent black would then turn fully black, and the writing would vanish.
    A 16-bit grey scan is scaled to 8 bits first (to_8bit).
    """
    img = to_8bit(img)
    has_alpha = img.mode in ("RGBA", "LA", "PA", "RGBa", "La") or "transparency" in img.info
    if not has_alpha:
        return img.convert("RGB")
    rgba = img.convert("RGBA")
    paper = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
    return Image.alpha_composite(paper, rgba).convert("RGB")
