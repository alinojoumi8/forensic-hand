"""Comparison charts (court exhibits) drawn from crops.

A chart shows crops side by side at the SAME physical scale when every crop has a known
resolution. When one does not, the chart says NOT TO SCALE in large letters. Every chart
states how it was made. The same crops and settings always give the same bytes.
"""

from __future__ import annotations

import io
import math

import numpy as np
from PIL import Image, ImageDraw, ImageFont
from PIL import __version__ as PILLOW_VERSION

from . import __version__

MAX_SCALE_DPI = 600
MAX_PANEL_SIDE = 2400
MARGIN, GAP = 48, 36
INK = (20, 20, 20)
MUTED = (95, 95, 95)
LINE = (200, 200, 200)
WARN = (160, 40, 0)


def _font(size: int):
    return ImageFont.load_default(size=size)


def _wrap(draw, text: str, font, width: int) -> list[str]:
    lines, line = [], ""
    for word in text.split():
        trial = f"{line} {word}".strip()
        if draw.textlength(trial, font=font) <= width or not line:
            line = trial
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines


def _text_block(draw, xy, lines, font, fill, spacing=6) -> int:
    x, y = xy
    for line in lines:
        draw.text((x, y), line, font=font, fill=fill)
        y += font.size + spacing
    return y


def _png(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=False)
    return buf.getvalue()


def common_scale(crops: list[dict]) -> int | None:
    """One resolution for all panels, or None when a crop has no known resolution."""
    if not crops or any(not c.get("dpi") for c in crops):
        return None
    scale = min(MAX_SCALE_DPI, max(max(c["dpi"]) for c in crops))
    widest = max(max(c["width"] * scale / c["dpi"][0], c["height"] * scale / c["dpi"][1]) for c in crops)
    if widest > MAX_PANEL_SIDE:
        scale = math.floor(scale * MAX_PANEL_SIDE / widest)
    return max(scale, 1)


def _panel_size(crop: dict, scale: int | None, height: int) -> tuple[int, int]:
    if scale:
        return (max(1, round(crop["width"] * scale / crop["dpi"][0])),
                max(1, round(crop["height"] * scale / crop["dpi"][1])))
    return max(1, round(crop["width"] * height / crop["height"])), height


def _resized(img: Image.Image, size: tuple[int, int]) -> Image.Image:
    img = img.convert("RGB")
    return img if img.size == size else img.resize(size, Image.LANCZOS)


def _header(draw, width, title, subtitle) -> int:
    y = MARGIN
    for line in _wrap(draw, title, _font(30), width - 2 * MARGIN):
        draw.text((MARGIN, y), line, font=_font(30), fill=INK)
        y += 38
    draw.text((MARGIN, y), subtitle, font=_font(16), fill=MUTED)
    return y + 40


def _footer_lines(to_scale: bool, scale: int | None, case_id: str, extra: list[str]) -> list[str]:
    lines = []
    if to_scale:
        lines.append(f"All panels are shown at the same scale: {scale} pixels per inch. Where a panel had to be "
                     "resized, Lanczos resampling was used. No contrast, colour or sharpness change was made.")
    else:
        lines.append("NOT TO SCALE: at least one crop has no known resolution, so all panels have the same height. "
                     "Do not compare sizes on this chart. No contrast, colour or sharpness change was made.")
    lines += extra
    lines.append(f"Each crop is taken from a sealed file and is recorded in the ledger of case {case_id}, "
                 "with the hash of this chart.")
    lines.append(f"Made with forensic-hand {__version__} (Pillow {PILLOW_VERSION}). This chart shows material for "
                 "comparison. It is not an opinion about who wrote any signature.")
    return lines


def _scale_bar(draw, x, y, scale: int) -> int:
    length = round(10 / 25.4 * scale)
    draw.rectangle([x, y, x + length, y + 6], fill=INK)
    draw.text((x + length + 10, y - 6), "10 mm", font=_font(14), fill=INK)
    return y + 20


def draw_panels(title: str, subtitle: str, items: list[dict], case_id: str) -> tuple[bytes, dict]:
    """items: [{"crop": record, "image": PIL image, "label": str, "source": evidence record}]"""
    crops = [it["crop"] for it in items]
    scale = common_scale(crops)
    height = min(600, max(c["height"] for c in crops)) if scale is None else 0
    sizes = [_panel_size(c, scale, height) for c in crops]
    cols = len(items) if len(items) <= 3 else (2 if len(items) == 4 else 3)
    rows = math.ceil(len(items) / cols)
    cell_w = max(max(w for w, _ in sizes), 320)
    caption_h = 130 if scale else 104
    image_h = max(h for _, h in sizes)
    cell_h = image_h + caption_h
    width = 2 * MARGIN + cols * cell_w + (cols - 1) * GAP

    probe = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    footer = []
    for line in _footer_lines(scale is not None, scale, case_id, []):
        footer += _wrap(probe, line, _font(14), width - 2 * MARGIN)
    title_lines = len(_wrap(probe, title, _font(30), width - 2 * MARGIN))
    top = MARGIN + 38 * title_lines + 40
    total_h = top + rows * cell_h + (rows - 1) * GAP + 24 + len(footer) * 20 + MARGIN

    img = Image.new("RGB", (width, total_h), "white")
    draw = ImageDraw.Draw(img)
    y0 = _header(draw, width, title, subtitle)
    if scale is None:
        draw.text((width - MARGIN - 220, MARGIN), "NOT TO SCALE", font=_font(26), fill=WARN)
    for index, (item, size) in enumerate(zip(items, sizes, strict=True)):
        row, col = divmod(index, cols)
        x = MARGIN + col * (cell_w + GAP)
        y = y0 + row * (cell_h + GAP)
        img.paste(_resized(item["image"], size), (x, y))
        draw.rectangle([x - 1, y - 1, x + size[0], y + size[1]], outline=LINE)
        cy = y + image_h + 10   # captions line up even when panels differ in height
        crop, src = item["crop"], item["source"]
        draw.text((x, cy), item["label"], font=_font(18), fill=INK)
        cy += 26
        info = [f"{crop['crop_id']} from {src['id']} ({src['name']}), page {crop['page']}",
                f"box {', '.join(str(v) for v in crop['box'])} {crop['units']}",
                f"source SHA-256 {crop['source_sha256'][:16]}..."]
        cy = _text_block(draw, (x, cy), [_wrap(draw, s, _font(13), cell_w)[0] for s in info], _font(13), MUTED, 4)
        if scale:
            _scale_bar(draw, x, cy + 6, scale)
    fy = y0 + rows * cell_h + (rows - 1) * GAP + 24
    draw.line([MARGIN, fy - 12, width - MARGIN, fy - 12], fill=LINE)
    _text_block(draw, (MARGIN, fy), footer, _font(14), MUTED, 6)
    return _png(img), {"to_scale": scale is not None, "scale_dpi": scale, "panel_sizes": [list(s) for s in sizes],
                       "width": img.width, "height": img.height, "pillow": PILLOW_VERSION}


def _darkness(img: Image.Image) -> np.ndarray:
    return 1.0 - np.asarray(img.convert("L"), dtype=np.float64) / 255.0


def draw_overlay(title: str, subtitle: str, a: dict, b: dict, params: dict, case_id: str) -> tuple[bytes, dict]:
    """a and b: {"crop", "image", "label", "source"}. b is moved, turned and scaled onto a."""
    crops = [a["crop"], b["crop"]]
    scale = common_scale(crops)
    height = min(600, max(c["height"] for c in crops)) if scale is None else 0
    size_a = _panel_size(a["crop"], scale, height)
    size_b = _panel_size(b["crop"], scale, height)
    img_a = _resized(a["image"], size_a)
    img_b = _resized(b["image"], (max(1, round(size_b[0] * params["scale"])), max(1, round(size_b[1] * params["scale"]))))
    if params["rotation"]:
        img_b = img_b.rotate(params["rotation"], resample=Image.BICUBIC, expand=True, fillcolor="white")
    pad = 40
    cw = max(img_a.width, img_b.width) + 2 * pad + 2 * abs(round(params["dx"]))
    ch = max(img_a.height, img_b.height) + 2 * pad + 2 * abs(round(params["dy"]))
    layer_a = Image.new("RGB", (cw, ch), "white")
    layer_b = Image.new("RGB", (cw, ch), "white")
    layer_a.paste(img_a, ((cw - img_a.width) // 2, (ch - img_a.height) // 2))
    layer_b.paste(img_b, ((cw - img_b.width) // 2 + round(params["dx"]), (ch - img_b.height) // 2 + round(params["dy"])))
    da, db = _darkness(layer_a), _darkness(layer_b)
    rgb = np.stack([1 - db, (1 - da) * (1 - db), 1 - da], axis=-1)
    panel = Image.fromarray(np.clip(np.round(rgb * 255), 0, 255).astype(np.uint8), mode="RGB")

    width = max(cw + 2 * MARGIN, 900)
    probe = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    legend = [f"Red: {a['crop']['crop_id']} from {a['source']['id']} ({a['source']['name']}) - {a['label']}",
              f"Blue: {b['crop']['crop_id']} from {b['source']['id']} ({b['source']['name']}) - {b['label']}",
              (f"Blue was moved {params['dx']}, {params['dy']} px, turned {params['rotation']} degrees and scaled "
               f"{params['scale']} times. The examiner set this alignment by hand. Dark purple shows where both inks lie.")]
    footer = []
    for line in _footer_lines(scale is not None, scale, case_id, legend):
        footer += _wrap(probe, line, _font(14), width - 2 * MARGIN)
    title_lines = len(_wrap(probe, title, _font(30), width - 2 * MARGIN))
    top = MARGIN + 38 * title_lines + 40
    total_h = top + ch + 40 + len(footer) * 20 + MARGIN
    img = Image.new("RGB", (width, total_h), "white")
    draw = ImageDraw.Draw(img)
    y0 = _header(draw, width, title, subtitle)
    if scale is None:
        draw.text((width - MARGIN - 220, MARGIN), "NOT TO SCALE", font=_font(26), fill=WARN)
    img.paste(panel, (MARGIN, y0))
    draw.rectangle([MARGIN - 1, y0 - 1, MARGIN + cw, y0 + ch], outline=LINE)
    fy = y0 + ch + 24
    if scale:
        fy = _scale_bar(draw, MARGIN, fy, scale) + 10
    _text_block(draw, (MARGIN, fy), footer, _font(14), MUTED, 6)
    return _png(img), {"to_scale": scale is not None, "scale_dpi": scale, "panel_sizes": [list(size_a), list(size_b)],
                       "width": img.width, "height": img.height, "pillow": PILLOW_VERSION}
