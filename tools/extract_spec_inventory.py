#!/usr/bin/env python3
"""Mine docs/spec/split/*.txt → docs/spec/case_inventory.json.

Scans the pdftotext-extracted spec splits in pagination order, tracks the
current §-section heading, and emits one record per headed test case body.
The headed-cases set is the canonical *active* TC8 set: deprecated cases
appear only in the spec-change deletion table (not in the body), so the
mine equals the active set without parsing the table. See
``claudedocs/infra_session14_prompt.md`` and the S14 Step-0 audit for the
rationale.

Usage:
    tools/extract_spec_inventory.py [--repo-root PATH] [--out PATH]

The output JSON has the shape::

    {
      "schema_version": 1,
      "generated_from": "docs/spec/split/*.txt (pdftotext -layout)",
      "case_count": 542,
      "cases": [
        {"case_id": "ARP_03", "section": "4.2.4.1",
         "split": "tc8_p041-p060", "line": 393},
        ...
      ]
    }

Case IDs are emitted verbatim (preserving spec capitalisation, e.g.
``IPv4_HEADER_05``). Consumers should canonicalise to upper case before
comparing against harness-registered IDs (the harness uses ``IPV4_*`` etc.).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


SECTION_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)+)\s+[A-Z]")
# Headings may be indented in the pdftotext -layout output: most chapter
# headings sit at column 0, but some (observed: "   5.1.6 Test Cases ETS")
# are indented. Anchoring at ^ with no leading-whitespace allowance made
# the miner skip the indented ones, so the cases beneath inherited the
# previous left-aligned section (the SOMEIP_ETS body picked up a stale
# 5.1.5.7 instead of 5.1.6). `^\s*` captures both.
# pdftotext occasionally bleeds a page-number digit into the indented
# case-id line (observed once at tc8_p481-p500.txt:326 — the spec line
# `0SOMEIPSRV_SD_MESSAGE_08:` instead of `SOMEIPSRV_SD_MESSAGE_08:`),
# so allow at most one leading digit before the case-id and discard it.
CASE_RE = re.compile(r"^\s+\d?([A-Z][A-Z0-9a-z_]+_[0-9]+):")


def mine(split_dir: Path) -> list[dict]:
    files = sorted(split_dir.glob("tc8_p*.txt"))
    if not files:
        raise SystemExit(f"no spec split .txt files under {split_dir}")
    cases: list[dict] = []
    seen: set[str] = set()
    current_section = ""
    for split_file in files:
        split_label = split_file.stem
        with split_file.open(encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                m = SECTION_RE.match(raw)
                if m:
                    current_section = m.group(1)
                    continue
                m = CASE_RE.match(raw)
                if m:
                    case_id = m.group(1)
                    if case_id in seen:
                        continue
                    seen.add(case_id)
                    cases.append(
                        {
                            "case_id": case_id,
                            "section": current_section,
                            "split": split_label,
                            "line": lineno,
                        }
                    )
    cases.sort(key=lambda c: c["case_id"])
    return cases


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repo root (default: parent of tools/)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output JSON path (default: <repo>/docs/spec/case_inventory.json)",
    )
    args = parser.parse_args(argv)

    split_dir = args.repo_root / "docs" / "spec" / "split"
    out_path = args.out or args.repo_root / "docs" / "spec" / "case_inventory.json"

    cases = mine(split_dir)
    payload = {
        "schema_version": 1,
        "generated_from": "docs/spec/split/*.txt (pdftotext -layout)",
        "case_count": len(cases),
        "cases": cases,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} cases → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
