#!/usr/bin/env python3
"""Aegis command line: ingest, verify, triage, report.

    python -m aegis.cli ingest samples/nuclei.jsonl samples/zap.json --db aegis.json
    python -m aegis.cli verify --db aegis.json
    python -m aegis.cli triage --db aegis.json
    python -m aegis.cli report --db aegis.json --out report.md

Only run `verify` against systems you own or are authorised to test.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import ai, ingest, report, verify
from .store import FindingStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis", description="Aegis: verified security findings")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ingest = sub.add_parser("ingest", help="ingest scanner output files")
    p_ingest.add_argument("files", nargs="+")
    p_ingest.add_argument("--db", default="aegis.json")

    for name in ("verify", "triage"):
        p = sub.add_parser(name)
        p.add_argument("--db", default="aegis.json")

    p_report = sub.add_parser("report")
    p_report.add_argument("--db", default="aegis.json")
    p_report.add_argument("--out", default=None)

    args = parser.parse_args(argv)
    store = FindingStore.load(args.db)

    if args.cmd == "ingest":
        total = {"added": 0, "merged": 0}
        for file in args.files:
            result = store.add_many(ingest.parse(Path(file).read_text(encoding="utf-8")))
            total["added"] += result["added"]
            total["merged"] += result["merged"]
        store.save(args.db)
        print(f"ingested: {total['added']} new, {total['merged']} merged as duplicates, {len(store.findings)} total")
    elif args.cmd == "verify":
        counts = verify.run_verifications(store)
        store.save(args.db)
        print(f"verification: {counts}")
    elif args.cmd == "triage":
        count = ai.run_triages(store)
        store.save(args.db)
        print(f"triaged {count} findings (engine: {ai.detect_provider() if ai.detect_provider() != 'none' else 'heuristic'})")
    elif args.cmd == "report":
        text = report.markdown_report(store)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"report written to {args.out}")
        else:
            print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
