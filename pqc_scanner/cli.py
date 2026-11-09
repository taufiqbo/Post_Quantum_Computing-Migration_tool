"""The pqc-scan command: read the options, run the scan, print and save reports.

Examples:
    pqc-scan samples
    pqc-scan . --exclude tests --exclude rules --html reports/report.html
    pqc-scan samples --min-confidence high --json out.json --csv out.csv
"""

import argparse
from pathlib import Path

from .report import summarise, write_csv, write_html, write_json
from .rules import load_rules
from .scanner import scan_folder

CONFIDENCE_ORDER = ["low", "medium", "high"]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pqc-scan",
        description="Find quantum-vulnerable cryptography in code, configs and certificates.")
    parser.add_argument("folder", nargs="?", default=".",
                        help="folder to scan (default: the current folder)")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                        help="skip files or folders with this name, e.g. tests or *.yaml "
                             "(use it more than once to skip several)")
    parser.add_argument("--min-confidence", choices=CONFIDENCE_ORDER, default="low",
                        help="hide findings below this confidence (default: low = show all)")
    parser.add_argument("--json", metavar="FILE", help="also save the results as JSON")
    parser.add_argument("--csv", metavar="FILE", help="also save the results as CSV")
    parser.add_argument("--html", metavar="FILE", help="also save an HTML report")
    parser.add_argument("--quiet", action="store_true",
                        help="only print the summary, not every finding")
    return parser


def keep(finding, min_confidence):
    """Is this finding's confidence at least min_confidence?"""
    return CONFIDENCE_ORDER.index(finding.confidence) >= CONFIDENCE_ORDER.index(min_confidence)


def print_findings(findings):
    for f in findings:
        print(f"[{f.severity.upper():8}] {f.algorithm:28} {f.file}:{f.line}  ({f.confidence})")
        print(f"           {f.snippet}")
        if f.detail:
            print(f"           detail: {f.detail}")
        print(f"           fix: {f.replacement}")
        print()


def save(write, path, *args):
    """Make sure the output folder exists, write the file, and say where it went."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    write(*args, path)
    print(f"Saved {path}")


def main(argv=None):
    args = build_parser().parse_args(argv)   # argv=None means "use the real command line"

    if not Path(args.folder).is_dir():
        print(f"pqc-scan: {args.folder} is not a folder")
        return 2

    findings, files_scanned = scan_folder(args.folder, load_rules(), exclude=args.exclude)
    findings = [f for f in findings if keep(f, args.min_confidence)]

    if not args.quiet:
        print_findings(findings)

    s = summarise(findings, files_scanned)
    print(f"Scanned {s['files_scanned']} files: {s['vulnerable']} quantum-vulnerable findings, "
          f"{s['quantum_safe']} quantum-safe findings.")
    print(f"Quantum-readiness score: {s['score']}/100 (grade {s['grade']})")

    if args.json:
        save(write_json, args.json, findings, files_scanned)
    if args.csv:
        save(write_csv, args.csv, findings)
    if args.html:
        save(write_html, args.html, findings, files_scanned)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
