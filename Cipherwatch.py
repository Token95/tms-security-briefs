"""
CipherBrief — Executive briefing from CrowdStrike, Nessus, and Blumira exports.

Sibling tool to CipherWatch.
Version: 0.2.0
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from enrich import enrich_findings
from parsers import PARSERS, detect_source
from report import summarize, write_csv, write_json, write_pdf

VERSION = "0.2.0"
BANNER = f"CipherBrief v{VERSION}  —  Watch the flow. Guard the cipher."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Turn CrowdStrike / Nessus / Blumira exports into an executive brief."
    )
    p.add_argument(
        "-s",
        "--source",
        choices=("crowdstrike", "nessus", "blumira", "auto"),
        default="auto",
        help="Export type (default: auto-detect from filename)",
    )
    p.add_argument("-i", "--input", required=True, help="Path to the incoming CSV export")
    p.add_argument(
        "-o",
        "--outdir",
        default="brief_out",
        help="Output directory (default: brief_out)",
    )
    p.add_argument("--offline", action="store_true", help="Skip NVD and CISA KEV live lookups")
    p.add_argument(
        "--cache",
        default=".cipherbrief_nvd_cache.json",
        help="NVD response cache file",
    )
    p.add_argument("--no-pdf", action="store_true", help="Skip PDF (still write supporting JSON + CSV)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    src_path = Path(args.input).expanduser()
    if not src_path.exists():
        print(f"Input not found: {src_path}", file=sys.stderr)
        return 2
    if src_path.suffix.lower() != ".csv":
        print("All incoming reports must be CSV. Re-export from the console as CSV.", file=sys.stderr)
        return 2

    source = args.source
    if source == "auto":
        source = detect_source(src_path)
        if not source:
            print(
                "Could not detect source from filename. Pass --source crowdstrike|nessus|blumira",
                file=sys.stderr,
            )
            return 2

    print(BANNER)
    print(f"Source : {source}")
    print(f"Input  : {src_path}")

    findings = PARSERS[source](src_path)
    print(f"Parsed : {len(findings)} findings")

    findings = enrich_findings(
        findings,
        offline=args.offline,
        cache_path=Path(args.cache),
    )
    mode = "offline (source + cache only)" if args.offline else "NVD API + CISA KEV"
    print(f"Enrich : {mode}")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stem = f"cipherbrief_{source}_{src_path.stem}"

    summary = summarize(findings, source, src_path.name)
    write_json(summary, outdir / f"{stem}.json")
    write_csv(findings, outdir / f"{stem}.csv")
    if not args.no_pdf:
        write_pdf(summary, outdir / f"{stem}.pdf")

    print(f"Wrote  : {outdir / (stem + '.json')}")
    print(f"         {outdir / (stem + '.csv')}")
    if not args.no_pdf:
        print(f"         {outdir / (stem + '.pdf')}")
    print(
        "Snapshot: "
        f"Crit={summary['severity'].get('CRITICAL', 0)} "
        f"High={summary['severity'].get('HIGH', 0)} "
        f"KEV={summary['kev_count']} "
        f"NOW={summary['now_count']} "
        f"WAIT={summary['wait_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())