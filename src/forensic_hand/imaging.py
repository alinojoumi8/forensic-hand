"""Small picture helpers shared by the screens, the charts and the report."""

from __future__ import annotations

from PIL import Image


def on_white(img: Image.Image) -> Image.Image:
    """An RGB picture in which transparent parts are white paper.

    Pillow's convert("RGB") drops the alpha channel. A transparent PNG with black writing on
    transparent black would then turn fully black, and the writing would vanish.
    """
    has_alpha = img.mode in ("RGBA", "LA", "PA", "RGBa", "La") or "transparency" in img.info
    if not has_alpha:
        return img.convert("RGB")
    rgba = img.convert("RGBA")
    paper = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
    return Image.alpha_composite(paper, rgba).convert("RGB")
