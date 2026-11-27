"""Synthetic signatures for validation, made with the Sigma-Lognormal model of handwriting.

Why synthetic: the tool needs labelled data (who wrote what, which item is a copy) that is
free of licence limits and of personal data. Synthetic data shows how a method behaves. It
does NOT show error rates on real casework. Every result built on it must say so.

The model (Plamondon's kinematic theory): a pen movement is a sum of strokes. Each stroke has
a speed profile shaped like a lognormal curve and turns smoothly from one direction to another.
- A writer is a set of strokes (the "motor plan").
- A genuine signature: the plan, with small natural variation; fast, overlapping strokes; the
  pen lands and lifts while moving (tapered ends).
- A skilled forgery: another person copies the shape. Strokes are slower and drawn one by one
  (less overlap, so sharper corners), with tremor and blunt ends.
- A digital copy: an image of a genuine signature that is resized, compressed and pasted.
"""

from __future__ import annotations

import io
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageFilter

GENERATOR_VERSION = 2   # 2: colour pictures (pen and stamp colours)
STRATA = ("clean", "ruled", "stamp", "blur", "jpeg", "dpi150", "stamp-same")
PAPER_RGB = (250, 250, 247)
PEN_RGB = {"black": (18, 18, 24), "blue": (28, 42, 125)}
STAMP_COLORS = {"red": (200, 40, 50), "blue": (40, 70, 180), "violet": (115, 50, 155), "black": (45, 45, 50)}
# A stamp in another colour than the pen (the usual case), and one in the pen's own colour (the hard case).
STAMP_CONTRAST = {"black": ("red", "blue", "violet"), "blue": ("red", "violet", "black")}
RATE = 200.0            # samples per second
MARGIN_MM = 3.0
SUPERSAMPLE = 3


@dataclass(frozen=True)
class Stroke:
    t0: float           # start time (s)
    D: float            # length (mm)
    mu: float           # log-time delay
    sigma: float        # log-response time
    theta_s: float      # start direction (rad)
    theta_e: float      # end direction (rad)


@dataclass
class Writer:
    components: list[list[Stroke]]
    gaps: list[tuple[float, float]]           # pen-up move between components (mm)
    slant_deg: float
    width_mm: float


@dataclass
class Sample:
    kind: str
    components: list[list[Stroke]]
    gaps: list[tuple[float, float]]
    rotation_deg: float = 0.0
    scale: float = 1.0
    width_mm: float = 0.4
    taper: bool = True
    tremor: tuple[float, float, float, float] | None = None   # amplitude mm, frequency Hz, two phases
    meta: dict = field(default_factory=dict)


# ---------------------------------------------------------------- the kinematic model

def erf(x):
    """Error function (Abramowitz and Stegun 7.1.26, error below 1.5e-7), for arrays."""
    x = np.asarray(x, dtype=np.float64)
    sign = np.sign(x)
    a = np.abs(x)
    t = 1.0 / (1.0 + 0.3275911 * a)
    poly = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))))
    return sign * (1.0 - poly * np.exp(-a * a))


def lognormal_speed(t, s: Stroke) -> np.ndarray:
    t = np.asarray(t, dtype=np.float64)
    dt = t - s.t0
    out = np.zeros_like(t)
    on = dt > 0
    lg = np.log(dt[on])
    out[on] = s.D / (s.sigma * math.sqrt(2 * math.pi) * dt[on]) * np.exp(-((lg - s.mu) ** 2) / (2 * s.sigma ** 2))
    return out


def _progress(t, s: Stroke) -> np.ndarray:
    """Share of the stroke done at time t (0 to 1): the lognormal cumulative curve."""
    dt = np.asarray(t, dtype=np.float64) - s.t0
    out = np.zeros_like(dt)
    on = dt > 0
    out[on] = 0.5 * (1 + erf((np.log(dt[on]) - s.mu) / (s.sigma * math.sqrt(2))))
    return out


def trajectory(components: list[list[Stroke]], rate: float = RATE) -> list[np.ndarray]:
    """Pen path of each component (pen down) as rows of x, y (mm), speed (mm/s), time (s)."""
    out = []
    for strokes in components:
        end = max(s.t0 + math.exp(s.mu + 4 * s.sigma) for s in strokes)
        t = np.arange(0.0, end, 1.0 / rate)
        vx = np.zeros_like(t)
        vy = np.zeros_like(t)
        for s in strokes:
            speed = lognormal_speed(t, s)
            angle = s.theta_s + (s.theta_e - s.theta_s) * _progress(t, s)
            vx += speed * np.cos(angle)
            vy += speed * np.sin(angle)
        x = np.concatenate([[0.0], np.cumsum(vx) / rate])
        y = np.concatenate([[0.0], np.cumsum(vy) / rate])
        tt = np.concatenate([[0.0], t + 1.0 / rate])
        speed = np.concatenate([[0.0], np.hypot(vx, vy)])
        out.append(np.column_stack([x, y, speed, tt]))
    return out


# ---------------------------------------------------------------- writers and samples

def new_writer(rng: np.random.Generator) -> Writer:
    """A random motor plan: 1 to 3 pen-down parts of 6 to 12 strokes, mostly up and down, moving right."""
    components = []
    for _ in range(int(rng.integers(1, 4))):
        strokes, t, up, last_up = [], 0.0, bool(rng.integers(0, 2)), (math.radians(60), 6.0)
        for _ in range(int(rng.integers(6, 13))):
            if up:
                theta = math.radians(rng.normal(58, 10))
                length = rng.uniform(3.0, 11.0)
                last_up = (theta, length)
            else:
                theta = math.radians(rng.normal(-80, 10))
                # Balance the height of the up stroke, so the signature stays on a line.
                length = last_up[1] * math.sin(last_up[0]) / abs(math.sin(theta)) * rng.uniform(0.8, 1.2)
            turn = (rng.choice([-1, 1]) * rng.uniform(2.4, 3.4)) if rng.random() < 0.15 else rng.uniform(-0.9, 0.9)
            strokes.append(Stroke(t0=t, D=float(length), mu=float(rng.uniform(-1.9, -1.5)),
                                  sigma=float(rng.uniform(0.18, 0.32)), theta_s=float(theta), theta_e=float(theta + turn)))
            t += float(rng.uniform(0.08, 0.14))
            up = not up
        components.append(strokes)
    gaps = [(float(rng.uniform(1.5, 4.5)), float(rng.normal(0, 1.5))) for _ in range(len(components) - 1)]
    writer = Writer(components, gaps, 0.0, float(rng.uniform(0.3, 0.5)))
    # Level the baseline: turn the plan so that its start-to-end line is about flat, like most signatures.
    path = np.concatenate([xy for xy, _ in sample_points(Sample("plan", components, gaps))])
    drift = math.degrees(math.atan2(path[-1, 1] - path[0, 1], path[-1, 0] - path[0, 0]))
    writer.slant_deg = float(-drift + rng.normal(0, 4))
    return writer


def _jitter(strokes, rng, *, t0=0.0, D=0.0, mu=0.0, sigma=0.0, theta=0.0, stretch=1.0, slow=0.0, sigma_scale=(1, 1)):
    return [Stroke(t0=max(0.0, s.t0 * stretch + rng.normal(0, t0)), D=s.D * (1 + rng.normal(0, D)),
                   mu=s.mu + slow + rng.normal(0, mu),
                   sigma=max(0.08, s.sigma * rng.uniform(*sigma_scale) + rng.normal(0, sigma)),
                   theta_s=s.theta_s + rng.normal(0, theta), theta_e=s.theta_e + rng.normal(0, theta))
            for s in strokes]


def genuine(writer: Writer, rng: np.random.Generator) -> Sample:
    comps = [_jitter(c, rng, t0=0.008, D=0.06, mu=0.04, sigma=0.02, theta=0.06) for c in writer.components]
    gaps = [(dx + rng.normal(0, 0.4), dy + rng.normal(0, 0.4)) for dx, dy in writer.gaps]
    return Sample("genuine", comps, gaps, rotation_deg=writer.slant_deg + rng.normal(0, 1.5),
                  scale=1 + rng.normal(0, 0.04), width_mm=writer.width_mm, taper=True)


def skilled_forgery(writer: Writer, rng: np.random.Generator) -> Sample:
    """A copy of the shape by another hand: slower, stroke by stroke, with tremor and blunt ends."""
    model = genuine(writer, rng)
    stretch, slow = rng.uniform(1.6, 2.4), rng.uniform(0.4, 0.8)
    comps = [_jitter(c, rng, D=0.08, theta=0.09, stretch=stretch, slow=slow, sigma_scale=(0.8, 1.0))
             for c in model.components]
    tremor = (float(rng.uniform(0.08, 0.2)), float(rng.uniform(5, 9)),
              float(rng.uniform(0, 2 * math.pi)), float(rng.uniform(0, 2 * math.pi)))
    return Sample("forgery-skilled", comps, model.gaps, rotation_deg=model.rotation_deg + rng.normal(0, 1.5),
                  scale=model.scale * (1 + rng.normal(0, 0.05)), width_mm=writer.width_mm * rng.uniform(0.9, 1.2),
                  taper=False, tremor=tremor, meta={"stretch": round(float(stretch), 3), "slow": round(float(slow), 3)})


def sample_points(sample: Sample, rate: float = RATE) -> list[tuple[np.ndarray, np.ndarray]]:
    """Final pen path of each part: xy in mm (y up), and speed in mm/s."""
    parts, cursor = [], None
    for k, arr in enumerate(trajectory(sample.components, rate)):
        xy = arr[:, :2].copy()
        if cursor is not None:
            gap = sample.gaps[k - 1] if k - 1 < len(sample.gaps) else (3.0, 0.0)
            xy += cursor + np.array(gap) - xy[0]
        cursor = xy[-1].copy()
        if sample.tremor:
            amp, freq, px, py = sample.tremor
            t = arr[:, 3] + 7.0 * k
            xy += amp * np.column_stack([np.sin(2 * math.pi * freq * t + px), np.sin(2 * math.pi * freq * 1.13 * t + py)])
        parts.append(xy)
    angle = math.radians(sample.rotation_deg)
    rot = np.array([[math.cos(angle), -math.sin(angle)], [math.sin(angle), math.cos(angle)]]) * sample.scale
    out = []
    for xy in parts:
        xy = xy @ rot.T
        speed = np.hypot(*np.gradient(xy, axis=0).T) * rate
        out.append((xy, speed))
    return out


def execution_stats(sample: Sample, rate: float = RATE) -> dict:
    """Mean pen speed (mm/s) and log dimensionless jerk (higher = less smooth; tremor raises it).

    Dimensionless jerk = (sum of squared jerk) x duration^5 / path length^2 (Hogan and Flash). It
    does not depend on size or speed, so it compares a fast hand with a slow one fairly.
    """
    speeds, ldj = [], []
    for xy, speed in sample_points(sample, rate):
        speeds.append(speed)
        jerk = np.diff(xy, n=3, axis=0) * rate ** 3
        duration = len(xy) / rate
        length = float(np.sum(np.hypot(*np.diff(xy, axis=0).T)))
        if length > 0:
            ldj.append(math.log(float(np.sum(jerk ** 2)) / rate * duration ** 5 / length ** 2))
    return {"mean_speed": float(np.mean(np.concatenate(speeds))), "jerk": float(np.mean(ldj))}


# ---------------------------------------------------------------- pictures

def render(sample: Sample, dpi: int = 300, rng: np.random.Generator | None = None, pen: str = "black") -> Image.Image:
    """Draw the pen path as ink on paper (RGB). Slow pen: wider, darker line. Genuine ends taper."""
    parts = sample_points(sample)
    allxy = np.concatenate([xy for xy, _ in parts])
    (minx, miny), (maxx, maxy) = allxy.min(axis=0), allxy.max(axis=0)
    k = dpi / 25.4 * SUPERSAMPLE
    width = math.ceil((maxx - minx + 2 * MARGIN_MM) * k)
    height = math.ceil((maxy - miny + 2 * MARGIN_MM) * k)
    canvas = Image.new("L", (width, height), 250)
    draw = ImageDraw.Draw(canvas)
    for xy, speed in parts:
        px = (xy[:, 0] - minx + MARGIN_MM) * k
        py = (maxy - xy[:, 1] + MARGIN_MM) * k
        n = len(px)
        taper = np.ones(n)
        if sample.taper and n > 10:
            ramp = max(2, int(0.08 * n))
            taper[:ramp] = np.linspace(0.35, 1, ramp)
            taper[-ramp:] = np.linspace(1, 0.35, ramp)
        w = sample.width_mm * np.clip(1.5 - speed / 180.0, 0.6, 1.5) * taper * k
        ink = np.clip(20 + 60 * speed / 200.0, 20, 85)
        gray = 250 - (250 - ink) * np.sqrt(taper)
        for i in range(n - 1):
            r = max(0.5, w[i] / 2)
            fill = int(gray[i])
            draw.line([(px[i], py[i]), (px[i + 1], py[i + 1])], fill=fill, width=max(1, round(w[i])))
            draw.ellipse([px[i] - r, py[i] - r, px[i] + r, py[i] + r], fill=fill)
    img = canvas.resize((max(1, round(width / SUPERSAMPLE)), max(1, round(height / SUPERSAMPLE))), Image.LANCZOS)
    gray = np.asarray(img, dtype=np.float64)
    if rng is not None:
        gray = gray + rng.normal(0, 1.2, gray.shape)
    # Colourise: darkness of the line is the share of pen colour over the paper colour.
    share = np.clip((250.0 - gray) / 230.0, 0, 1)[..., None]
    paper = np.array(PAPER_RGB, dtype=np.float64)
    rgb = paper * (1 - share) + np.array(PEN_RGB[pen], dtype=np.float64) * share
    return Image.fromarray(np.clip(rgb, 0, 255).round().astype(np.uint8), "RGB")


def png_bytes(img: Image.Image, dpi: int) -> bytes:
    buf = io.BytesIO()
    img.save(buf, "PNG", dpi=(dpi, dpi), optimize=False)
    return buf.getvalue()


def _jpeg(img: Image.Image, quality: int) -> Image.Image:
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    with Image.open(buf) as out:
        return out.convert(img.mode)


def _stamp(img: Image.Image, dpi: int, rng: np.random.Generator, color: str, name: str):
    mm = dpi / 25.4
    cx, cy = img.width * rng.uniform(0.2, 0.8), img.height * rng.uniform(0.2, 0.8)
    r = img.height * rng.uniform(0.35, 0.5)
    strength, w = float(rng.uniform(0.55, 0.85)), max(1, round(0.5 * mm))
    mask = Image.new("L", img.size, 0)
    d = ImageDraw.Draw(mask)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=255, width=w)
    d.ellipse([cx - 0.8 * r, cy - 0.8 * r, cx + 0.8 * r, cy + 0.8 * r], outline=255, width=max(1, w // 2))
    for i in range(10):       # short marks between the rings, like stamp lettering
        a = 2 * math.pi * i / 10
        d.line([(cx + 0.84 * r * math.cos(a), cy + 0.84 * r * math.sin(a)),
                (cx + 0.95 * r * math.cos(a + 0.2), cy + 0.95 * r * math.sin(a + 0.2))], fill=255, width=max(1, w // 2))
    # Ink layers multiply: where the stamp covers the pen line, both inks darken the paper.
    alpha = np.asarray(mask, dtype=np.float64)[..., None] / 255.0 * strength
    tint = np.array(STAMP_COLORS[color], dtype=np.float64) / np.array(PAPER_RGB, dtype=np.float64)
    out = np.asarray(img.convert("RGB"), dtype=np.float64) * (1 - alpha + alpha * np.clip(tint, 0, 1))
    return (Image.fromarray(np.clip(out, 0, 255).round().astype(np.uint8), "RGB"), dpi,
            {"name": name, "color": color, "center_frac": [round(cx / img.width, 3), round(cy / img.height, 3)],
             "radius_px": round(r, 1), "strength": round(strength, 3)})


def degrade(img: Image.Image, dpi: int, name: str, rng: np.random.Generator,
            pen: str = "black") -> tuple[Image.Image, int, dict]:
    """Apply one named document problem. Returns the picture, its resolution and what was done."""
    mm = dpi / 25.4
    if name == "clean":
        return img.copy(), dpi, {"name": name}
    if name == "ruled":
        y = int(img.height * rng.uniform(0.72, 0.85))
        gray, w = int(rng.uniform(60, 110)), max(1, round(0.25 * mm))
        layer = Image.new(img.mode, img.size, (255,) * len(img.getbands()) if len(img.getbands()) > 1 else 255)
        ImageDraw.Draw(layer).line([(0, y), (img.width, y)], fill=(gray,) * len(img.getbands())
                                   if len(img.getbands()) > 1 else gray, width=w)
        return ImageChops.darker(img, layer), dpi, {"name": name, "y_frac": round(y / img.height, 3), "gray": gray,
                                                     "width_px": w}
    if name == "stamp":
        return _stamp(img, dpi, rng, str(rng.choice(STAMP_CONTRAST[pen])), name)
    if name == "stamp-same":
        return _stamp(img, dpi, rng, pen, name)
    if name == "blur":
        sigma = round(float(rng.uniform(1.6, 2.4)), 3)
        return img.filter(ImageFilter.GaussianBlur(sigma)), dpi, {"name": name, "sigma_px": sigma}
    if name == "jpeg":
        quality = int(rng.integers(35, 56))
        return _jpeg(img, quality), dpi, {"name": name, "quality": quality}
    if name == "dpi150":
        size = (max(1, round(img.width * 150 / dpi)), max(1, round(img.height * 150 / dpi)))
        return img.resize(size, Image.LANCZOS), 150, {"name": name, "from_dpi": dpi}
    raise ValueError(f"unknown degradation: {name}")


def make_copy(img: Image.Image, dpi: int, rng: np.random.Generator) -> tuple[Image.Image, int, dict]:
    """A digital copy of a signature: resized, saved as JPEG, turned a little, pasted on a page."""
    resize = round(float(rng.uniform(0.6, 1.25)), 3)
    quality = int(rng.integers(60, 91))
    rotation = round(float(rng.uniform(-2.5, 2.5)), 3)
    background = int(rng.integers(238, 251))
    small = img.resize((max(1, round(img.width * resize)), max(1, round(img.height * resize))), Image.LANCZOS)
    fill = PAPER_RGB if img.mode == "RGB" else 250
    turned = _jpeg(small, quality).rotate(rotation, resample=Image.BICUBIC, expand=True, fillcolor=fill)
    mx, my = (int(rng.uniform(2, 6) * dpi / 25.4) for _ in range(2))
    page_fill = (background, background, background - 3) if img.mode == "RGB" else background
    page = Image.new(img.mode, (turned.width + 2 * mx, turned.height + 2 * my), page_fill)
    page.paste(turned, (mx, my))
    return page, dpi, {"kind": "digital-copy", "resize": resize, "jpeg_quality": quality, "rotation_deg": rotation,
                       "background": background}


# ---------------------------------------------------------------- a whole dataset

def generate_dataset(out, writers: int = 12, genuine: int = 4, forgeries: int = 2, seed: int = 1,
                     strata=STRATA, dpi: int = 300, writer_prefix: str = "w") -> dict:
    """Write a labelled synthetic dataset (pictures and manifest.json) to an empty folder.

    writer_prefix starts each writer id (w001, w002, ...). Two sets with other prefixes have no writer
    id in common, as a calibration set and its test set must not.
    """
    from . import datasets

    out = Path(out)
    if not isinstance(writer_prefix, str) or not writer_prefix.isascii() or not writer_prefix.isalnum() \
            or len(writer_prefix) > 20:
        raise datasets.DatasetError("the writer prefix must be 1 to 20 letters or digits")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise datasets.DatasetError(f"the folder is not empty; choose a new folder: {out}")
    (out / "images").mkdir(parents=True, exist_ok=True)
    items: list[dict] = []

    def save(item_id, img, img_dpi, **fields):
        name = f"images/{item_id}.png"
        (out / name).write_bytes(png_bytes(img, img_dpi))
        items.append({"item_id": item_id, "file": name, "dpi": [img_dpi, img_dpi], "capture": "synthetic", **fields})

    for w in range(writers):
        wid = f"{writer_prefix}{w + 1:03d}"
        rng = np.random.default_rng([seed, 1, w])
        writer = new_writer(rng)
        pen = ("black", "blue")[int(np.random.default_rng([seed, 3, w]).integers(0, 2))]
        originals = []
        for g in range(genuine):
            sid = f"{wid}-g{g + 1}"
            img = render(_sample(writer, "genuine", rng), dpi, rng, pen=pen)
            save(sid, img, dpi, writer_id=wid, kind="genuine", stratum="clean", sample=sid, pen=pen)
            originals.append((sid, img, "genuine"))
        for f in range(forgeries):
            sid = f"{wid}-f{f + 1}"
            img = render(_sample(writer, "forgery-skilled", rng), dpi, rng, pen=pen)
            save(sid, img, dpi, writer_id=wid, kind="forgery-skilled", stratum="clean", sample=sid, pen=pen)
            originals.append((sid, img, "forgery-skilled"))
        for si, stratum in enumerate(strata):
            for oi, (sid, img, kind) in enumerate(originals):
                srng = np.random.default_rng([seed, 2, w, si, oi])
                if stratum != "clean":
                    bad, bad_dpi, params = degrade(img, dpi, stratum, srng, pen=pen)
                    save(f"{sid}@{stratum}", bad, bad_dpi, writer_id=wid, kind=kind, stratum=stratum, sample=sid,
                         degradation=params, pen=pen)
                if kind == "genuine":
                    copy, copy_dpi, copy_params = make_copy(img, dpi, srng)
                    copy, copy_dpi, params = degrade(copy, copy_dpi, stratum, srng, pen=pen)
                    save(f"{sid}-copy@{stratum}", copy, copy_dpi, writer_id=wid, kind="copy", stratum=stratum,
                         sample=f"{sid}-copy", source_item=sid, degradation={**params, "copy": copy_params}, pen=pen)
    manifest = datasets.new_manifest(
        title=f"Synthetic signatures (seed {seed})", license_class="own",
        license_name="Generated by forensic-hand; no personal data; no third-party rights",
        items=items, folder=out, synthetic=True,
        generator={"name": "forensic-hand sigma-lognormal", "version": GENERATOR_VERSION, "seed": seed,
                   "writers": writers, "genuine": genuine, "forgeries": forgeries, "strata": list(strata), "dpi": dpi,
                   "writer_prefix": writer_prefix})
    datasets.save_manifest(manifest, out / "manifest.json")
    return manifest


def _sample(writer: Writer, kind: str, rng: np.random.Generator) -> Sample:
    return genuine(writer, rng) if kind == "genuine" else skilled_forgery(writer, rng)
