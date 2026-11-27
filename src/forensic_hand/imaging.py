"""Small picture helpers shared by the screens, the charts and the report."""

from __future__ import annotations

import numpy as np
from PIL import Image

WIDE_GRAY = ("I", "I;16", "I;16L", "I;16B", "I;16N")


def on_white(img: Image.Image) -> Image.Image:
    """An RGB picture in which transparent parts are white paper.

    Pillow's convert("RGB") drops the alpha channel. A transparent PNG with black writing on
    transparent black would then turn fully black, and the writing would vanish.
    A 16-bit grey scan is scaled to 8 bits first: a plain convert("RGB") clips every value above 255
    to white, and the ink would vanish too.
    """
    if img.mode in WIDE_GRAY:
        values = np.asarray(img, dtype=np.float64)
        top = 65535.0 if values.size and float(values.max()) > 255 else 255.0
        img = Image.fromarray(np.clip(np.round(values / top * 255.0), 0, 255).astype(np.uint8), "L")
    has_alpha = img.mode in ("RGBA", "LA", "PA", "RGBa", "La") or "transparency" in img.info
    if not has_alpha:
        return img.convert("RGB")
    rgba = img.convert("RGBA")
    paper = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
    return Image.alpha_composite(paper, rgba).convert("RGB")
