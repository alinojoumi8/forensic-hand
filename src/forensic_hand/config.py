"""Screening settings. Each check run records these values and their hash in the ledger."""

from __future__ import annotations

import hashlib
import json

DEFAULTS = {
    "version": 1,
    "status": "Screening values. Not validated on real casework. A qualified examiner decides.",

    # Resolution. Low resolution hides fine stroke detail.
    "dpi_warning_below": 150,
    "dpi_notice_below": 300,
    "min_side_px_warning_below": 300,

    # Sharpness score: strongest edges of a tile, divided by the contrast of the tile.
    # A hard edge gives about 0.5. Blur makes the score fall.
    "sharpness_warning_below": 0.14,
    "sharpness_notice_below": 0.22,
    "sharpness_tile_px": 512,
    "sharpness_min_contrast": 0.10,

    # JPEG quality estimate (from the tables in the file).
    "jpeg_quality_warning_below": 60,
    "jpeg_quality_notice_below": 80,

    # Known samples. More samples show the natural variation of a writer.
    # Source of the numbers: the design document. To be confirmed with practising examiners.
    "known_count_warning_below": 5,
    "known_count_notice_below": 15,
    "contemporaneous_years": 3,

    # Copy check (digital cut and paste). Screening values, to be validated.
    # Ink is scaled so that its spread (radius of gyration) is this many pixels, then blurred a little.
    # Long straight lines and the 2% of ink farthest from the centre are ignored. Tuned on synthetic
    # lines only: copies (resized, turned up to 3 degrees, JPEG, pasted on a printed line) scored
    # 0.975 or more; natural variation 0.79 or less (0.91 for an unusually steady hand).
    "clone_radius_px": 160,
    # 3.0 (was 1.5): chosen on synthetic seed 1, checked on seed 2 (see docs/testing). It makes the
    # check more tolerant of blurred and recompressed copies; false alarms stayed at 0.
    "clone_blur_px": 3.0,
    "clone_rotations_deg": [-3, -2, -1, 0, 1, 2, 3],
    # Remove a second ink of another colour (a stamp) before comparing. Two inks only when their hues
    # differ by this many degrees, or one is neutral (black or grey) and the other is coloured.
    "clone_ink_separation": True,
    "clone_ink_hue_deg": 15,   # 2x the largest hue drift measured inside one synthetic pen line (7.8)
    "clone_notice_at": 0.90,
    "clone_warning_at": 0.95,
    "clone_max_aspect_diff": 0.10,
    "clone_min_ink_fraction": 0.002,

    # PDF
    "pdf_scan_coverage": 0.8,
    "pdf_overlay_max_coverage": 0.5,
    "pdf_date_tolerance_seconds": 60,
}


def config_sha256(config: dict | None = None) -> str:
    raw = json.dumps(config or DEFAULTS, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
