"""Command line entry point: ``python -m xssscan.cli --root DIR --out FILE``."""

import argparse
import json
import sys

from .report import scan, write_report, summarize


def build_parser():
    parser = argparse.ArgumentParser(
        prog="python -m xssscan.cli",
        description="Static DOM XSS detector (Python standard library only).")
    parser.add_argument("--root", required=True,
                        help="Directory containing .html/.js files to scan.")
    parser.add_argument("--out", required=True,
                        help="Path of the JSON report to write.")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    findings, scanned_files = scan(args.root)
    write_report(findings, args.out)
    counts = summarize(findings)
    summary = {
        "scanned_files": scanned_files,
        "finding_count": len(findings),
        "by_sink_type": counts,
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
