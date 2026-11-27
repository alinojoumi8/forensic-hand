"""Command line for forensic-hand. Run `fhand` with no arguments to see the commands."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, tsa, verify_case
from .calibrate import PROPOSITIONS, CalibrationError
from .case import Case, CaseError
from .checks import run_checks
from .config import DEFAULTS
from .datasets import PRESETS, USES, DatasetError
from .export import ExportError, export_case
from .findings import count_levels
from .ledger import LedgerError
from .prereg import DEFAULT_MARKS as PASS_MARKS
from .prereg import PreregError
from .release import ReleaseError
from .report import write_report
from .seal import SealError, create_seal, timestamp_seal
from .validation import TASKS


def _say(text: str, stream=None) -> None:
    stream = stream or sys.stdout
    try:
        print(text, file=stream)
    except UnicodeEncodeError:
        print(text.encode("ascii", "backslashreplace").decode("ascii"), file=stream)


def _error(text: str) -> None:
    _say(f"error: {text}", sys.stderr)


def _add_files(case: Case, paths, role: str, signer=None, doc_date=None, note=None) -> None:
    for path in paths or []:
        record = case.add_evidence(path, role=role, signer=signer, doc_date=doc_date, note=note)
        _say(f"Added {record['id']:<4} {record['name']}  sha256 {record['sha256']}")


def _check(case: Case) -> None:
    result = run_checks(case)
    findings = list(result["case_findings"])
    for item in result["files"].values():
        findings.extend(item["findings"])
    counts = count_levels(findings)
    _say(f"Checks: {counts['warning']} warning(s), {counts['notice']} note(s), {counts['info']} info item(s)")


def _seal(case: Case, timestamp: bool, url: str) -> int:
    """Make a seal. Return 0, or 1 when the time stamp was asked for and failed."""
    seal = create_seal(case)
    _say(f"Seal {seal['seal_no']}: sha256 {seal['sha256']}")
    if not timestamp:
        _say("Time stamp: none. Nothing left this computer.")
        return 0
    try:
        stamp = timestamp_seal(case, url=url)
    except SealError as exc:
        _error(str(exc))
        _say("Time stamp: FAILED. The seal is kept. Try again later with: fhand stamp <case>")
        return 1
    _say_stamp(stamp)
    return 0


def _say_stamp(stamp: dict) -> None:
    _say(f"Time stamp: {stamp['gen_time']} from {stamp['tsa_url']} (only the seal hash was sent)")
    if stamp["signature_check"] == "ok":
        _say(f"Signature:  checked ({stamp['signature_detail']})")
    else:
        _say(f"Signature:  NOT checked: {stamp['signature_detail']}")


# ---------------------------------------------------------------- commands

def cmd_new(args) -> int:
    case = Case.create(args.case, title=args.title)
    _say(f"Case folder: {case.path}")
    return 0


def cmd_add(args) -> int:
    _add_files(Case.open(args.case), args.files, args.role, args.signer, args.date, args.note)
    return 0


def cmd_date(args) -> int:
    Case.open(args.case).annotate(args.id, doc_date=args.date)
    _say(f"{args.id}: document date is now {args.date}")
    return 0


def cmd_check(args) -> int:
    _check(Case.open(args.case))
    return 0


def cmd_seal(args) -> int:
    return _seal(Case.open(args.case), args.timestamp, args.tsa_url)


def cmd_stamp(args) -> int:
    _say_stamp(timestamp_seal(Case.open(args.case), url=args.tsa_url))
    return 0


def cmd_report(args) -> int:
    _say(f"Report: {write_report(Case.open(args.case))}")
    return 0


def cmd_verify(args) -> int:
    argv = [str(args.case)]
    if args.ca_file:
        argv += ["--ca-file", args.ca_file]
    if args.openssl:
        argv += ["--openssl", args.openssl]
    if args.skip_tsa_signature:
        argv.append("--skip-tsa-signature")
    if args.json:
        argv.append("--json")
    return verify_case.main(argv)


def cmd_export(args) -> int:
    done = export_case(Case.open(args.case), args.out)
    _say(f"Bundle: {done['path']}")
    _say(f"Files:  {done['files']}")
    _say(f"sha256: {done['sha256']}")
    return 0


def cmd_synth(args) -> int:
    from .synth import STRATA, generate_dataset

    manifest = generate_dataset(args.out, writers=args.writers, genuine=args.genuine, forgeries=args.forgeries,
                                seed=args.seed, dpi=args.dpi, strata=STRATA, writer_prefix=args.writer_prefix)
    _say(f"Synthetic dataset: {args.out}")
    _say(f"Items: {len(manifest['items'])} from {args.writers} writer(s), seed {args.seed}")
    _say("These are generated signatures. They show how a method behaves, not real error rates.")
    return 0


def cmd_dataset_verify(args) -> int:
    from .datasets import load_manifest, verify

    manifest = load_manifest(args.manifest)
    problems = verify(manifest)
    data = manifest.data
    _say(f"Dataset: {data['title']}{' (synthetic)' if data['synthetic'] else ''}")
    _say(f"Licence: {data['license']['class']}: {data['license']['name']}")
    _say(f"Items:   {len(manifest.items)} from {len({i['writer_id'] for i in manifest.items})} writer(s)")
    _say(f"Consent: {'required, ' + str(len(data['consent']['records'])) + ' record(s)' if data['consent']['required'] else 'not required'}")
    for problem in problems:
        _say(f"PROBLEM: {problem}")
    _say("RESULT: OK" if not problems else "RESULT: PROBLEMS FOUND")
    return 0 if not problems else 1


def cmd_dataset_build(args) -> int:
    from .datasets import build_from_csv

    out = args.out or str(Path(args.folder) / "manifest.json")
    if Path(out).exists():
        raise DatasetError(f"the file exists already; choose a new name: {out}")
    manifest = build_from_csv(args.folder, args.csv, title=args.title, license_class=args.license_class,
                              license_name=args.license_name, consent_csv=args.consent, out=out,
                              license_url=args.license_url)
    _say(f"Manifest: {out}")
    _say(f"Items:    {len(manifest['items'])}")
    return 0


def cmd_dataset_import(args) -> int:
    from .datasets import build_from_names

    out = args.out or str(Path(args.folder) / "manifest.json")
    if Path(out).exists() and not args.dry_run:
        raise DatasetError(f"the file exists already; choose a new name: {out}")
    done = build_from_names(args.folder, title=args.title, license_class=args.license_class,
                            license_name=args.license_name, preset=args.preset, pattern=args.pattern,
                            genuine=args.genuine, forgery=args.forgery, out=None if args.dry_run else out,
                            license_url=args.license_url, dry_run=args.dry_run)
    facts = done["import"]
    _say(f"{facts['matched']} picture(s) match: {facts['writers']} writer(s), {facts['genuine_items']} genuine, "
         f"{facts['forgery_items']} skilled forgeries")
    if facts["skipped"]:
        _say(f"Left out (no match, or another kind): {facts['skipped']}, for example: "
             + ", ".join(facts["skipped_examples"]))
    if args.license_class == "research-only":
        _say("Research-only data: internal benchmarks only (validate --purpose benchmark). It can never calibrate "
             "a score or be published.")
    if args.dry_run:
        _say("Dry run: nothing was written.")
    else:
        _say(f"Manifest: {out}")
    return 0


def cmd_calibrate(args) -> int:
    from .calibrate import calibrate, save_calibration

    if Path(args.out).exists():
        raise CalibrationError(f"the file exists already; choose a new name: {args.out}")
    if args.min_known < 2:
        raise CalibrationError("--min-known must be 2 or more")
    body = calibrate(args.manifests, args.propositions, config={**DEFAULTS, "score_min_known": args.min_known},
                     strata=args.strata)
    save_calibration(body, args.out)
    model, pairs = body["model"], body["data"]["pairs"]
    _say(f"Calibration: {args.out}")
    _say(f"Propositions: {args.propositions}. Pairs: {pairs['same']} same writer, {pairs['different']} for Hd, "
         f"{len(body['data']['writers'])} writer(s). Strata: {', '.join(body['conditions']['strata'])}")
    _say(f"Model: log10 LR = {model['a']} x score + {model['b']}, kept between {model['lower']} and {model['upper']}")
    if body["status"] == "demo":
        _say("Status: demo (synthetic data). A case can never use it.")
    else:
        _say("Status: candidate. A case cannot use it until a release checks it against time stamped pass marks.")
    _say(f"Calibration hash: {body['results_sha256']}")
    return 0


def cmd_validate(args) -> int:
    from .calibrate import load_calibration
    from .prereg import load_criteria
    from .validation import run_validation, write_dossier

    if (Path(args.out) / "dossier.json").exists():
        raise DatasetError(f"a dossier exists already in {args.out}; choose a new folder")
    calibration = load_calibration(args.calibration) if args.calibration else None
    criteria = load_criteria(args.criteria) if args.criteria else None
    dossier = run_validation(args.manifests, purpose=args.purpose, blur_samples=args.blur_samples,
                             jpeg_samples=args.jpeg_samples, calibration=calibration, criteria=criteria,
                             config={**DEFAULTS, "score_min_known": args.min_known}, tasks=args.tasks)
    path = write_dossier(dossier, args.out)
    tasks = dossier["tasks"]
    if "copy-check" in tasks:
        copy = tasks["copy-check"]["all"]
        same = copy["negatives"]["same-writer"]["warning"]
        _say(f"Copy check, all strata: copies flagged {copy['positives']['warning']['rate']}, "
             f"same-writer false alarms {same['rate']} ({same['k']}/{same['n']})")
    score = tasks.get("writer-score")
    if score is None:
        pass
    elif score.get("skipped"):
        _say(f"Writer score: not measured: {score['skipped']}")
    else:
        neg = score["all"]["negatives"]
        _say(f"Writer score (raw, all strata): AUC against skilled forgeries {neg['skilled-forgery']['auc']}, "
             f"against other writers {neg['other-writer']['auc']}")
    lr = dossier["tasks"].get("lr")
    if lr and lr.get("skipped"):
        _say(f"LR: not measured: {lr['skipped']}")
    elif lr:
        mis = lr["misleading"]
        _say(f"LR ({lr['status']} calibration): Cllr {lr['cllr']} (95% by writers {lr['cllr_ci95'][0]} to "
             f"{lr['cllr_ci95'][1]}); misleading for Hp {mis['hp']['rate']}, for Hd {mis['hd']['rate']}")
        if lr["writers_overlap"]:
            _say(f"Warning: {len(lr['writers_overlap'])} writer(s) were also used to calibrate: not a fair test.")
    marks = dossier.get("pass_marks")
    if marks:
        failed = [r["mark"] for r in marks["results"] if not r["pass"]]
        _say("Pass marks: all passed." if marks["passed"] else f"Pass marks: FAILED: {', '.join(failed) or 'no test'}")
    _say(f"Results hash: {dossier['results_sha256']}")
    _say(f"Dossier: {path}")
    flags = [d["synthetic"] for d in dossier["datasets"]]
    if all(flags):
        _say("Synthetic data only: not error rates on real casework.")
    elif any(flags):
        _say("Real and synthetic data are mixed: the pooled numbers are not real error rates.")
    return 0


def cmd_prereg(args) -> int:
    from .calibrate import load_calibration
    from .prereg import DEFAULT_MARKS, save_criteria, write_criteria

    marks = {name: getattr(args, name) for name in DEFAULT_MARKS}
    body = write_criteria(load_calibration(args.calibration), args.test, marks, note=args.note)
    save_criteria(body, args.out)
    _say(f"Pass marks: {args.out}")
    for name, value in marks.items():
        _say(f"  {name}: {value}")
    _say("Next: time stamp this file now, before you run the test:")
    _say(f"  fhand stamp-file {args.out}")
    return 0


def cmd_stamp_file(args) -> int:
    from .prereg import stamp_file

    done = stamp_file(args.file, url=args.tsa_url)
    _say(f"Time stamp: {done['gen_time']} from {done['tsa_url']} (only the file hash was sent)")
    _say(f"Saved: {done['file']}")
    if done["signature_check"] == "ok":
        _say(f"Signature: checked ({done['signature_detail']})")
    else:
        _say(f"Signature: NOT checked: {done['signature_detail']}. A release needs a checked signature.")
    return 0


def cmd_release(args) -> int:
    from .release import make_release, save_release

    if Path(args.out).exists():
        raise ReleaseError(f"the file exists already; choose a new name: {args.out}")
    bundle = make_release(args.calibration, args.criteria, args.dossier)
    save_release(bundle, args.out)
    facts = bundle["facts"]
    _say(f"Pass marks stamped {facts['criteria_stamp']['gen_time']}; test stamped {facts['dossier_stamp']['gen_time']}")
    for r in facts["marks"]:
        _say(f"  pass  {r['text']} {r['limit']}: {r['value'] if r['value'] is not None else r.get('note')}")
    _say(f"Released: {args.out}")
    _say("A case can use this file with: fhand score <case> --release " + str(args.out))
    return 0


def cmd_score(args) -> int:
    from .work import add_release, run_score

    case = Case.open(args.case)
    try:
        raw = Path(args.release).read_bytes()
    except OSError as exc:
        raise CaseError(f"the release file cannot be read: {exc}") from exc
    rel = add_release(case, raw)
    s = run_score(case, args.questioned, args.known, rel["release_id"])
    _say(f"Score {s['score_id']}: {s['questioned']} against {', '.join(s['known'])} (release {rel['release_id']})")
    _say(f"Hp: {s['propositions']['hp']}")
    _say(f"Hd: {s['propositions']['hd']}")
    bound = " (held at a bound of the test data)" if s["bounded"] else ""
    _say(f"LR {s['lr_text']} (log10 {s['log10_lr']:+.2f}){bound}: {s['verbal']}")
    _say(f"Raw score {s['score']}. Pass marks stamped {rel['criteria_stamp']}; test stamped {rel['dossier_stamp']}.")
    _say("The examiner decides. The LR is one input, not a verdict. The report (section 7) lists its limits.")
    return 0


def cmd_serve(args) -> int:
    import webbrowser

    from .server import address, create_server

    try:
        server = create_server(args.case, port=args.port)
    except OSError as exc:
        raise CaseError(f"the workbench could not start on port {args.port}: {exc}") from exc
    url = address(server)
    _say("Workbench running on this computer only. Keep this window open; press Ctrl+C to stop.")
    _say(f"Open: {url}")
    _say("The address holds a one-time key. Do not share it.")
    sys.stdout.flush()   # show the address at once, also when the output is not a terminal
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _say("Workbench stopped.")
    finally:
        server.server_close()
    return 0


def cmd_intake(args) -> int:
    case = Case.create(args.case, title=args.title)
    _say(f"Case folder: {case.path}")
    _add_files(case, args.questioned, "questioned")
    _add_files(case, args.known, "known")
    _add_files(case, args.other, "other")
    _check(case)
    code = _seal(case, args.timestamp, args.tsa_url)
    _say(f"Report: {write_report(case)}")
    return code


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fhand",
        description="Sealed intake for forensic document examination. Decision support. Not a verdict tool.",
    )
    parser.add_argument("--version", action="version", version=f"forensic-hand {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")

    def with_tsa(p):
        p.add_argument("--tsa-url", default=tsa.DEFAULT_TSA_URL, help="time stamp server (default: %(default)s)")

    p = sub.add_parser("intake", help="do it all: new case, add files, check, seal, report")
    p.add_argument("case", help="new, empty folder for the case")
    p.add_argument("--title", required=True)
    p.add_argument("--questioned", nargs="+", default=[], metavar="FILE", help="the item(s) in dispute")
    p.add_argument("--known", nargs="+", default=[], metavar="FILE", help="known samples of the writer")
    p.add_argument("--other", nargs="+", default=[], metavar="FILE", help="other files to keep with the case")
    p.add_argument("--timestamp", action="store_true", help="get a trusted time stamp (sends one hash out)")
    with_tsa(p)
    p.set_defaults(func=cmd_intake)

    p = sub.add_parser("new", help="make an empty case")
    p.add_argument("case")
    p.add_argument("--title", required=True)
    p.set_defaults(func=cmd_new)

    p = sub.add_parser("add", help="add file(s) to a case")
    p.add_argument("case")
    p.add_argument("files", nargs="+", metavar="FILE")
    p.add_argument("--role", required=True, choices=["questioned", "known", "other"])
    p.add_argument("--date", help="date of the document, as 2021-05-03")
    p.add_argument("--signer", help="name of the person who is said to have signed")
    p.add_argument("--note")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("date", help="set or correct the document date of an item")
    p.add_argument("case")
    p.add_argument("id", help="item id, for example K1")
    p.add_argument("date", help="as 2021-05-03")
    p.set_defaults(func=cmd_date)

    p = sub.add_parser("check", help="run the quality and PDF screens")
    p.add_argument("case")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("seal", help="seal the present state of the case")
    p.add_argument("case")
    p.add_argument("--timestamp", action="store_true", help="get a trusted time stamp (sends one hash out)")
    with_tsa(p)
    p.set_defaults(func=cmd_seal)

    p = sub.add_parser("stamp", help="get a trusted time stamp for the last seal (sends one hash out)")
    p.add_argument("case")
    with_tsa(p)
    p.set_defaults(func=cmd_stamp)

    p = sub.add_parser("report", help="write reports/report.html")
    p.add_argument("case")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("verify", help="check that nothing in the case changed")
    p.add_argument("case")
    p.add_argument("--ca-file")
    p.add_argument("--openssl")
    p.add_argument("--skip-tsa-signature", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("export", help="pack the case into one zip file for another party")
    p.add_argument("case")
    p.add_argument("out", help="name of the new zip file")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("serve", help="open the workbench in your browser (this computer only)")
    p.add_argument("case")
    p.add_argument("--port", type=int, default=0, help="port number (default: a free port)")
    p.add_argument("--no-browser", action="store_true", help="print the address but do not open a browser")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("synth", help="make a labelled synthetic signature dataset for validation")
    p.add_argument("out", help="new, empty folder")
    p.add_argument("--writers", type=int, default=12)
    p.add_argument("--genuine", type=int, default=4, help="genuine signatures per writer")
    p.add_argument("--forgeries", type=int, default=2, help="skilled forgeries per writer")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--dpi", type=int, default=300)
    p.add_argument("--writer-prefix", default="w", help="start of each writer id (default: %(default)s)")
    p.set_defaults(func=cmd_synth)

    p = sub.add_parser("dataset", help="check or build a dataset manifest")
    dsub = p.add_subparsers(dest="dataset_command", metavar="command")
    q = dsub.add_parser("verify", help="check every file of a dataset against its manifest")
    q.add_argument("manifest")
    q.set_defaults(func=cmd_dataset_verify)
    q = dsub.add_parser("build", help="make a manifest for a real collection from a CSV file")
    q.add_argument("folder", help="the folder that holds the scans")
    q.add_argument("--csv", required=True,
                   help="items CSV: file, writer_id, kind, stratum, consent_id, capture, source_item, sample")
    q.add_argument("--title", required=True)
    q.add_argument("--license-class", required=True, choices=["own", "commercial", "research-only", "unknown"])
    q.add_argument("--license-name", required=True)
    q.add_argument("--license-url")
    q.add_argument("--consent", help="consent CSV: consent_id, scopes (a;b), date, withdrawn")
    q.add_argument("--out", help="manifest file (default: manifest.json in the folder)")
    q.set_defaults(func=cmd_dataset_build)
    q = dsub.add_parser("import", help="make a manifest for a set whose file names say the writer and the kind")
    q.add_argument("folder", help="the folder of the set (sub-folders are read too)")
    q.add_argument("--preset", choices=list(PRESETS), help="a known layout: " + "; ".join(
        f"{k}: {v['note']}" for k, v in PRESETS.items()))
    q.add_argument("--pattern", help="regular expression for the path inside the folder (/ between folders), "
                                     "with the named groups writer and kind, and optionally set and forger")
    q.add_argument("--genuine", nargs="+", metavar="WORD", help="kind words for genuine signatures")
    q.add_argument("--forgery", nargs="+", metavar="WORD", help="kind words for skilled forgeries")
    q.add_argument("--title", required=True)
    q.add_argument("--license-class", required=True, choices=["own", "commercial", "research-only", "unknown"],
                   help="most public signature sets are research-only")
    q.add_argument("--license-name", required=True)
    q.add_argument("--license-url")
    q.add_argument("--out", help="manifest file (default: manifest.json in the folder)")
    q.add_argument("--dry-run", action="store_true", help="show what matches; write nothing")
    q.set_defaults(func=cmd_dataset_import)

    p = sub.add_parser("validate", help="measure the screens on labelled data and write a dossier")
    p.add_argument("manifests", nargs="+", metavar="MANIFEST")
    p.add_argument("--out", required=True, help="new folder for dossier.html and dossier.json")
    p.add_argument("--purpose", default="benchmark", choices=list(USES))
    p.add_argument("--blur-samples", type=int, default=12)
    p.add_argument("--jpeg-samples", type=int, default=12)
    p.add_argument("--calibration", help="also measure the LRs of this calibration file on the data")
    p.add_argument("--criteria", help="pass marks file (fhand prereg) to record and check in the dossier")
    p.add_argument("--min-known", type=int, default=DEFAULTS["score_min_known"],
                   help="known signatures per comparison for the raw writer score (default: %(default)s)")
    p.add_argument("--tasks", nargs="+", choices=list(TASKS), metavar="TASK",
                   help=f"run only these tasks: {', '.join(TASKS)} (default: all)")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("calibrate", help="fit the writer score to a likelihood ratio (Stage 4)")
    p.add_argument("manifests", nargs="+", metavar="MANIFEST")
    p.add_argument("--propositions", required=True, choices=list(PROPOSITIONS),
                   help="what Hd is: a skilled forger, or a random other writer")
    p.add_argument("--out", required=True, help="new calibration file (JSON)")
    p.add_argument("--strata", nargs="+", help="only these conditions (default: all in the data)")
    p.add_argument("--min-known", type=int, default=DEFAULTS["score_min_known"],
                   help="known signatures per comparison (default: %(default)s)")
    p.set_defaults(func=cmd_calibrate)

    p = sub.add_parser("prereg", help="write the pass marks for a calibration before its test (Stage 4)")
    p.add_argument("calibration", help="the calibration file to test")
    p.add_argument("--test", nargs="+", required=True, metavar="MANIFEST", help="the test data (not yet opened)")
    p.add_argument("--out", required=True, help="new pass marks file (JSON)")
    p.add_argument("--note", help="free text, for example who agreed the marks")
    for name, value in PASS_MARKS.items():
        p.add_argument(f"--{name.replace('_', '-')}", dest=name, type=type(value), default=value,
                       help=f"(default: {value})")
    p.set_defaults(func=cmd_prereg)

    p = sub.add_parser("stamp-file", help="get a trusted time stamp for a file (sends one hash out)")
    p.add_argument("file")
    with_tsa(p)
    p.set_defaults(func=cmd_stamp_file)

    p = sub.add_parser("release", help="check a calibration against its stamped pass marks and test (Stage 4)")
    p.add_argument("--calibration", required=True)
    p.add_argument("--criteria", required=True, help="the pass marks file; its stamp is <file>.tsr")
    p.add_argument("--dossier", required=True, help="the test dossier.json; its stamp is dossier.json.tsr")
    p.add_argument("--out", required=True, help="new release file (JSON)")
    p.set_defaults(func=cmd_release)

    p = sub.add_parser("score", help="likelihood ratio for a questioned crop (needs a released calibration)")
    p.add_argument("case")
    p.add_argument("--release", required=True, help="the release file (fhand release); it is checked again")
    p.add_argument("--questioned", required=True, metavar="CROP", help="crop of the questioned signature, e.g. C1")
    p.add_argument("--known", nargs="+", required=True, metavar="CROP", help="crops of known signatures")
    p.set_defaults(func=cmd_score)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except (CaseError, ExportError, LedgerError, DatasetError, CalibrationError, PreregError, ReleaseError) as exc:
        _error(str(exc))
        return 2
    except SealError as exc:
        _error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
