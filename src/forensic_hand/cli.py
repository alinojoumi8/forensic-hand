"""Command line for forensic-hand. Run `fhand` with no arguments to see the commands."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, tsa, verify_case
from .case import Case, CaseError
from .checks import run_checks
from .datasets import USES, DatasetError
from .export import ExportError, export_case
from .findings import count_levels
from .ledger import LedgerError
from .report import write_report
from .seal import SealError, create_seal, timestamp_seal


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
                                seed=args.seed, dpi=args.dpi, strata=STRATA)
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


def cmd_validate(args) -> int:
    from .validation import run_validation, write_dossier

    if (Path(args.out) / "dossier.json").exists():
        raise DatasetError(f"a dossier exists already in {args.out}; choose a new folder")
    dossier = run_validation(args.manifests, purpose=args.purpose, blur_samples=args.blur_samples,
                             jpeg_samples=args.jpeg_samples)
    path = write_dossier(dossier, args.out)
    copy = dossier["tasks"]["copy-check"]["all"]
    same = copy["negatives"]["same-writer"]["warning"]
    _say(f"Copy check, all strata: copies flagged {copy['positives']['warning']['rate']}, "
         f"same-writer false alarms {same['rate']} ({same['k']}/{same['n']})")
    _say(f"Results hash: {dossier['results_sha256']}")
    _say(f"Dossier: {path}")
    if any(d["synthetic"] for d in dossier["datasets"]):
        _say("Synthetic data only: not error rates on real casework.")
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
    p.set_defaults(func=cmd_synth)

    p = sub.add_parser("dataset", help="check or build a dataset manifest")
    dsub = p.add_subparsers(dest="dataset_command", metavar="command")
    q = dsub.add_parser("verify", help="check every file of a dataset against its manifest")
    q.add_argument("manifest")
    q.set_defaults(func=cmd_dataset_verify)
    q = dsub.add_parser("build", help="make a manifest for a real collection from a CSV file")
    q.add_argument("folder", help="the folder that holds the scans")
    q.add_argument("--csv", required=True, help="items CSV: file, writer_id, kind, stratum, consent_id, capture")
    q.add_argument("--title", required=True)
    q.add_argument("--license-class", required=True, choices=["own", "commercial", "research-only", "unknown"])
    q.add_argument("--license-name", required=True)
    q.add_argument("--license-url")
    q.add_argument("--consent", help="consent CSV: consent_id, scopes (a;b), date, withdrawn")
    q.add_argument("--out", help="manifest file (default: manifest.json in the folder)")
    q.set_defaults(func=cmd_dataset_build)

    p = sub.add_parser("validate", help="measure the screens on labelled data and write a dossier")
    p.add_argument("manifests", nargs="+", metavar="MANIFEST")
    p.add_argument("--out", required=True, help="new folder for dossier.html and dossier.json")
    p.add_argument("--purpose", default="benchmark", choices=list(USES))
    p.add_argument("--blur-samples", type=int, default=12)
    p.add_argument("--jpeg-samples", type=int, default=12)
    p.set_defaults(func=cmd_validate)
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
    except (CaseError, ExportError, LedgerError, DatasetError) as exc:
        _error(str(exc))
        return 2
    except SealError as exc:
        _error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
