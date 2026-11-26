"""Command line for forensic-hand. Run `fhand` with no arguments to see the commands."""

from __future__ import annotations

import argparse
import sys

from . import __version__, tsa, verify_case
from .case import Case, CaseError
from .checks import run_checks
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
    except (CaseError, ExportError, LedgerError) as exc:
        _error(str(exc))
        return 2
    except SealError as exc:
        _error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
