#!/usr/bin/env python3
"""Scaffold a per-case translation override file.

Creates ``site/src/locales/cases/<locale>/<CASE_ID>.json`` with the right
shape and verdict states prefilled from the case manifest, so the
translator just fills in the strings.

Usage:
    python3 site/scripts/scaffold_translation.py ARP_04
    python3 site/scripts/scaffold_translation.py TCP_BASICS_11 --locale en
    python3 site/scripts/scaffold_translation.py ARP_05 --force      # overwrite

Recommended self-contained ``approach`` structure (also documented in
``site/src/lib/overrides.ts``):

    [검증 목적]      What is being verified, in 1–3 sentences
    [시나리오]       Step-by-step, who sends what to whom
    [통과 조건]      What constitutes a PASS
    [실패 조건]      What triggers each fail verdict and why
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = REPO_ROOT / "site" / "src" / "data" / "cases"
LOCALES_DIR = REPO_ROOT / "site" / "src" / "locales" / "cases"


KO_APPROACH_TEMPLATE = (
    "[검증 목적]\n"
    "\n"
    "[시나리오 — 시간순]\n"
    "1. 테스터 → DUT: \n"
    "2. \n"
    "3. 관찰: \n"
    "\n"
    "[통과 조건]\n"
    "\n"
    "[실패 조건]\n"
)
EN_APPROACH_TEMPLATE = (
    "[Objective]\n"
    "\n"
    "[Scenario — chronological]\n"
    "1. Tester → DUT: \n"
    "2. \n"
    "3. Observation: \n"
    "\n"
    "[Pass condition]\n"
    "\n"
    "[Fail condition]\n"
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("case_id")
    ap.add_argument("--locale", default="ko", choices=["en", "ko"])
    ap.add_argument("--force", action="store_true",
                    help="Overwrite an existing override file")
    args = ap.parse_args(argv)

    cid = args.case_id.upper()
    out_dir = LOCALES_DIR / args.locale
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{cid}.json"

    if out_path.exists() and not args.force:
        print(f"skipped: {out_path} already exists (--force to overwrite)",
              file=sys.stderr)
        return 1

    case_path = CASES_DIR / f"{cid}.json"
    if not case_path.exists():
        print(f"no case manifest at {case_path} — run build_manifest.py first",
              file=sys.stderr)
        return 1

    rec = json.loads(case_path.read_text(encoding="utf-8"))
    verdicts: dict[str, str] = {
        v["state"]: "" for v in rec.get("trait", {}).get("verdicts", [])
    }

    template = {
        "description": "",
        "approach": KO_APPROACH_TEMPLATE if args.locale == "ko" else EN_APPROACH_TEMPLATE,
        "verdicts": verdicts,
        "messages": [],
    }
    out_path.write_text(json.dumps(template, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(f"created: {out_path}")
    print(f"  verdict states prefilled: {len(verdicts)}")
    print(f"  fill in description, approach, verdict meanings, then rebuild")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
