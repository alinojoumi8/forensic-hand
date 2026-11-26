"""Pack a case folder into one zip file for another party. The checker travels inside."""

from __future__ import annotations

import zipfile
from pathlib import Path

from .ledger import LOCK_NAME
from .verify_case import hash_file


class ExportError(Exception):
    pass


def export_case(case, out_path) -> dict:
    out = Path(out_path)
    if out.exists():
        raise ExportError(f"the file exists already; choose a new name: {out}")
    if case.path.resolve() in out.resolve().parents:
        raise ExportError("save the bundle outside the case folder")
    # The lock file only coordinates writers on this computer; it is not part of the case.
    files = sorted(p for p in case.path.rglob("*") if p.is_file() and p.name != LOCK_NAME)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "x", zipfile.ZIP_DEFLATED) as bundle:
        for path in files:
            # Fixed date and order: the same case always gives the same zip bytes.
            info = zipfile.ZipInfo(path.relative_to(case.path).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            bundle.writestr(info, path.read_bytes())
    return {"path": str(out), "files": len(files), **hash_file(out)}
