#!/usr/bin/env python3
"""Parse a Surefire JUnit XML and emit TAB-delimited "case_id<TAB>outcome".

Used by `.github/workflows/pcap-refresh.yml` to derive the per-case pass/fail
badge for the site's packet timeline section. Negative-only suffixed rows
(_NEG) are skipped because pcap files are keyed by the positive case_id.

Usage:
    python3 site/scripts/junit_outcomes.py <junit.xml>
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <junit.xml>", file=sys.stderr)
        return 2
    tree = ET.parse(argv[1])
    for tc in tree.iter("testcase"):
        name = tc.attrib.get("name", "").upper()
        if name.endswith("_NEG"):
            continue
        outcome = "fail" if tc.find("failure") is not None else "pass"
        print(f"{name}\t{outcome}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
