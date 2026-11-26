"""Intake report: one HTML file that needs no network, and the same content as JSON.

Every value that comes from a file or from the user is escaped. File metadata is hostile input.
"""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from . import TOOL_NAME, __version__
from .findings import count_levels
from .ledger import utc_now

LIMITS = [
    "Indentations in the paper (pressure grooves, and writing from a sheet that lay on top).",
    "Ink chemistry: whether two inks are different, and the order of crossing strokes.",
    "Retouching and pen lifts that only a microscope shows.",
    "The paper itself: watermarks, fibres, erasures, staple holes.",
    "The true scale, when the file does not give a reliable resolution.",
]

LEVEL_WORD = {"info": "Info", "notice": "Note", "warning": "Warning"}
ROLE_WORD = {"questioned": "Questioned", "known": "Known", "other": "Other"}

_CSS = """
:root{--bg:#fbfbfa;--fg:#1c1c1a;--muted:#5d5d58;--line:#d9d8d2;--card:#fff;--warn:#8a3a00;--warnbg:#fdebd8;
--note:#5a4a00;--notebg:#fbf3c9;--info:#1e4a6b;--infobg:#e3eef6;--ok:#1f5a2e;--okbg:#e2f1e5}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--muted:#a3a29b;--line:#3a3a36;--card:#1f1f1d;
--warn:#ffb784;--warnbg:#4a2609;--note:#f1dd7e;--notebg:#3f3608;--info:#a9d1ee;--infobg:#17354a;--ok:#9fd9ad;--okbg:#173a20}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:26px;margin:0 0 4px;text-wrap:balance}
h2{font-size:18px;margin:36px 0 10px;padding-top:14px;border-top:1px solid var(--line)}
h3{font-size:15px;margin:22px 0 6px}
p{margin:6px 0}
.muted{color:var(--muted)}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;overflow-wrap:anywhere}
.banner{border:1px solid var(--line);border-left:5px solid var(--info);background:var(--card);padding:12px 16px;margin:18px 0;border-radius:4px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;background:var(--card)}
th,td{text-align:left;vertical-align:top;padding:7px 10px;border:1px solid var(--line)}
th{font-weight:600;white-space:nowrap}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.tag{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
.warning{color:var(--warn);background:var(--warnbg)}
.notice{color:var(--note);background:var(--notebg)}
.info{color:var(--info);background:var(--infobg)}
.ok{color:var(--ok);background:var(--okbg)}
.finding{background:var(--card);border:1px solid var(--line);border-radius:4px;padding:10px 14px;margin:8px 0}
.finding .title{font-weight:600}
.finding .limits{color:var(--muted);font-size:14px}
.file{margin-top:26px}
ul{margin:6px 0;padding-left:22px}
@media print{body{background:#fff;color:#000}main{max-width:none;padding:0}.finding,table{break-inside:avoid}}
"""


def _e(value) -> str:
    return escape("" if value is None else str(value), quote=True)


def _size(count: int) -> str:
    if count >= 1024 * 1024:
        return f"{count / (1024 * 1024):.1f} MB"
    if count >= 1024:
        return f"{count / 1024:.1f} KB"
    return f"{count} bytes"


def _finding_html(item: dict) -> str:
    detail = f"<div>{_e(item['detail'])}</div>" if item.get("detail") else ""
    return (
        f'<div class="finding"><span class="tag {_e(item["level"])}">{_e(LEVEL_WORD.get(item["level"], item["level"]))}</span> '
        f'<span class="title">{_e(item["title"])}</span> <span class="muted mono">{_e(item["code"])}</span>'
        f'{detail}<div class="limits">What this does not prove: {_e(item["limits"])}</div></div>'
    )


def _findings_block(findings: list[dict]) -> str:
    if not findings:
        return '<p><span class="tag ok">Clear</span> The screens found nothing to report.</p>'
    order = {"warning": 0, "notice": 1, "info": 2}
    return "".join(_finding_html(f) for f in sorted(findings, key=lambda f: order.get(f["level"], 3)))


def _facts_table(rows: list[tuple[str, object]]) -> str:
    cells = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in rows if v not in (None, "", [], {}))
    return f'<div class="scroll"><table>{cells}</table></div>' if cells else ""


def _file_facts(check: dict) -> list[tuple[str, object]]:
    if check["kind"] == "image":
        m = check.get("metrics", {})
        dpi = m.get("dpi")
        return [
            ("Format", m.get("format")), ("Size in pixels", f"{m.get('width')} x {m.get('height')}" if m.get("width") else None),
            ("Colour mode", m.get("mode")), ("Resolution in the file", f"{dpi[0]} x {dpi[1]} DPI" if dpi else "not given"),
            ("Sharpness score", m.get("sharpness")), ("JPEG quality estimate", m.get("jpeg_quality_estimate")),
            ("Camera or software named in the file", " / ".join(str(v) for k, v in (m.get("exif") or {}).items() if k != "has_gps")),
        ]
    if check["kind"] == "pdf":
        f = check.get("facts", {})
        info = f.get("info", {})
        scans = [im for im in f.get("page_images", []) if im.get("page_coverage", 0) >= 0.8 and im.get("dpi_x")]
        return [
            ("Pages", f.get("pages")), ("PDF version", f.get("pdf_version") or f.get("header_version")),
            ("Program that made it (Producer)", info.get("Producer")), ("Creator", info.get("Creator")),
            ("Author", info.get("Author")), ("Title", info.get("Title")),
            ("Made (as the file says)", info.get("CreationDate")), ("Changed (as the file says)", info.get("ModDate")),
            ("Saved again after first write", f"{f.get('incremental_updates')} time(s)" if f.get("incremental_updates") else None),
            ("Digital signatures", len(f.get("signatures", [])) or None),
            ("Lowest scan resolution", f"{min(im['dpi_x'] for im in scans)} DPI" if scans else None),
        ]
    return []


def build_report(case) -> tuple[str, dict]:
    """Return (html, data). This reads the case. It writes nothing."""
    state = case.state()
    generated = utc_now()
    all_findings = list(state["case_findings"] or [])
    for check in state["files"].values():
        all_findings.extend(check["findings"])
    counts = count_levels(all_findings)
    data = {
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_claimed": generated,
        "case": {"case_id": state["case_id"], "title": state["title"], "created_claimed": state["created"]},
        "ledger": {"count": state["ledger_count"], "head": state["ledger_head"]},
        "counts": counts,
        "limits_of_a_digital_copy": LIMITS,
        "evidence": state["evidence"],
        "case_findings": state["case_findings"],
        "files": state["files"],
        "seals": state["seals"],
        "env": state["env"],
    }

    parts: list[str] = []
    add = parts.append
    add(f"<h1>{_e(state['title'])}</h1>")
    add(f'<p class="muted">Intake report &middot; case <span class="mono">{_e(state["case_id"])}</span> &middot; '
        f'made {_e(generated)} (clock of this computer) &middot; {_e(TOOL_NAME)} {_e(__version__)}</p>')
    add('<div class="banner"><strong>This report is not an opinion about who wrote a signature.</strong> '
        "It records which files came in, proves that they did not change, and lists screening notes for a "
        "qualified examiner. Each note is a lead to check, with its limits. No note is proof alone.</div>")

    # ---- integrity
    add("<h2>1. Is the case file intact?</h2>")
    add(f'<p>The ledger holds {state["ledger_count"]} event(s). Its last hash is:</p>'
        f'<p class="mono">{_e(state["ledger_head"])}</p>')
    if not state["seals"]:
        add('<p><span class="tag notice">Note</span> The case has no seal yet.</p>')
    for seal in state["seals"]:
        stamp = seal.get("timestamp")
        add(f'<h3>Seal {_e(seal["seal_no"])}</h3>')
        rows = [("Seal file", seal["file"]), ("SHA-256 of the seal file", seal["sha256"]),
                ("Covers the ledger up to event", seal["ledger_seq"]),
                ("Made (clock of this computer)", seal["created"])]
        if stamp:
            rows += [("Trusted time stamp", stamp["gen_time"]), ("Time stamp authority", stamp["tsa_url"]),
                     ("Serial number", stamp["serial"]), ("Token file", stamp["tsr_file"])]
        add(_facts_table(rows))
        if not stamp:
            add('<p><span class="tag notice">Note</span> No trusted time stamp. All times for this seal come from the '
                "clock of this computer, and that clock can be wrong or can be changed.</p>")
    add("<p>Anyone can repeat the check. The checker is one file of plain Python in the case folder:</p>"
        '<p class="mono">python verify_case.py &lt;case folder&gt;</p>')

    # ---- limits
    add("<h2>2. What a digital copy cannot show</h2>")
    add("<p>This case holds scans, photos or PDF files. Only an examination of the original paper can show:</p><ul>")
    for line in LIMITS:
        add(f"<li>{_e(line)}</li>")
    add("</ul><p>Examine the original document when you can.</p>")

    # ---- case notes
    add("<h2>3. Notes on the case as a whole</h2>")
    if state["case_findings"] is None:
        add('<p><span class="tag notice">Note</span> Not checked yet. Run the check command.</p>')
    else:
        add(f'<p class="muted">Checked {_e(state["checked_at"])} (clock of this computer). '
            f'In total: {counts["warning"]} warning(s), {counts["notice"]} note(s), {counts["info"]} info item(s).</p>')
        add(_findings_block(state["case_findings"]))

    # ---- evidence
    add("<h2>4. Items in the case</h2>")
    add('<div class="scroll"><table><tr><th>ID</th><th>Role</th><th>File name</th><th>Type</th><th>Size</th>'
        "<th>Signer</th><th>Document date</th><th>SHA-256</th></tr>")
    for rec in state["evidence"]:
        add(f'<tr><td><strong>{_e(rec["id"])}</strong></td><td>{_e(ROLE_WORD.get(rec["role"], rec["role"]))}</td>'
            f'<td>{_e(rec["name"])}</td><td>{_e(rec["media_type"])}</td><td class="num">{_e(_size(rec["size"]))}</td>'
            f'<td>{_e(rec.get("signer") or "")}</td><td class="num">{_e(rec.get("doc_date") or "")}</td>'
            f'<td class="mono">{_e(rec["sha256"])}</td></tr>')
    add("</table></div>")
    if not state["evidence"]:
        add("<p>The case has no items.</p>")

    # ---- per file
    add("<h2>5. Notes on each item</h2>")
    for rec in state["evidence"]:
        add(f'<div class="file"><h3>{_e(rec["id"])} &middot; {_e(rec["name"])}</h3>')
        if rec.get("note"):
            add(f"<p>Note from intake: {_e(rec['note'])}</p>")
        add(f'<p class="muted mono">BLAKE2b {_e(rec["blake2b"])}</p>')
        check = state["files"].get(rec["id"])
        if check is None:
            add('<p><span class="tag notice">Note</span> Not checked yet. Run the check command.</p></div>')
            continue
        add(_findings_block(check["findings"]))
        add(_facts_table(_file_facts(check)))
        add("</div>")

    # ---- method
    add("<h2>6. Method and settings</h2>")
    env = state["env"]
    if env:
        packages = ", ".join(f"{k} {v}" for k, v in sorted(env["packages"].items()))
        add(_facts_table([("Tool", f"{env['tool']['name']} {env['tool']['version']}"), ("Python", env["python"]),
                          ("System", env["platform"]), ("Libraries", packages),
                          ("SHA-256 of the settings", env["config_sha256"]), ("Status of the settings", env["config"].get("status"))]))
        settings = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in sorted(env["config"].items())
                           if k not in ("status",))
        add(f'<h3>Settings used</h3><div class="scroll"><table>{settings}</table></div>')
    else:
        add("<p>No check has run yet.</p>")
    add('<p class="muted">The screens use fixed rules. They use no machine learning model and send no data out. '
        "The same files and the same settings give the same notes.</p>")

    html = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(state['title'])} - intake report</title><style>{_CSS}</style></head>"
        f"<body><main>{''.join(parts)}</main></body></html>\n"
    )
    return html, data


def write_report(case) -> Path:
    html, data = build_report(case)
    folder = case.path / "reports"
    folder.mkdir(exist_ok=True)
    (folder / "report.json").write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                                        encoding="utf-8")
    path = folder / "report.html"
    path.write_text(html, encoding="utf-8")
    return path
