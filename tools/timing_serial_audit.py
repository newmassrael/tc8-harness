#!/usr/bin/env python3
"""Drift guard for the `timing_serial` inventory axis.

Every case whose SCXML measures a sub-second inter-frame cadence (a
`*_within_us(...)` predicate) MUST be classified for the smoke serial lane:
either marked `timing_serial:true` in docs/spec/inventory_overrides.json (run
UNCONTENDED at --workers 1, so a CPU-starved DUT does not skew the window) OR
listed in EXEMPT below (a window wide enough that contention-induced emit
latency cannot push the interval past the bound). A new cadence case that is
neither fails this gate.

This closes the "class selection drifts" hole: routing is automatic once a case
is classified, but the original 4-case set was picked by the predicate NAME
(`frame_delta_within_us`) and silently missed siblings using other cadence
predicates (`ack_to_request_within_us`). This audit makes CLASSIFICATION
mandatory for the whole `*_within_us` family, by the timing PROPERTY not the
predicate name. See memory/reference_timing_serial_cadence.md.

Run with no args (or --check); prints offenders and exits non-zero on failure.
"""
from __future__ import annotations

import glob
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OVERRIDES = ROOT / "docs/spec/inventory_overrides.json"

# Cadence cases whose window is wide enough that the DUT's timing jitter sits far
# from both edges, so scheduling latency under --workers 4 cannot cross the bound
# — exempt from the serial lane, WITH the reason. Keep short and justified.
EXEMPT = {
    # nak_to_discover_within_us(1_000_000, 11_000_000) — a 10 s window; the DUT's
    # ±1 s retx jitter leaves ~9 s of margin, so emit latency is irrelevant.
    "DHCPV4_CLIENT_INITIALIZATION_ALLOCATION_01",
}

_PRED = re.compile(r"[a-z_]+_within_us\(")


def cadence_cases() -> set[str]:
    out: set[str] = set()
    for scxml in glob.glob(str(ROOT / "tests/*/*.scxml")):
        if _PRED.search(Path(scxml).read_text(encoding="utf-8")):
            out.add(Path(scxml).parent.name.upper())
    return out


def timing_serial_ids() -> set[str]:
    data = json.loads(OVERRIDES.read_text(encoding="utf-8"))
    return {k.upper() for k, v in data["overrides"].items() if v.get("timing_serial")}


def main() -> int:
    cadence = cadence_cases()
    if not cadence:
        sys.exit("timing_serial_audit: found 0 cadence (*_within_us) cases — bad scan")
    serial = timing_serial_ids()
    unclassified = sorted(cadence - serial - EXEMPT)
    stale = sorted(serial - cadence)  # timing_serial on a non-cadence case
    rc = 0
    if unclassified:
        print("timing_serial_audit: cadence (*_within_us) case(s) NOT routed to a "
              "serial lane — add timing_serial:true in inventory_overrides.json, or "
              "to EXEMPT (this file) with a window-margin reason:")
        for c in unclassified:
            print(f"  {c}")
        rc = 1
    if stale:
        print("timing_serial_audit: timing_serial entr(ies) on non-cadence case(s) "
              "— stale, remove from inventory_overrides.json:")
        for c in stale:
            print(f"  {c}")
        rc = 1
    if rc == 0:
        print(f"timing_serial_audit: OK — {len(cadence)} cadence case(s): "
              f"{len(cadence & serial)} serial + {len(cadence & EXEMPT)} exempt")
    return rc


if __name__ == "__main__":
    sys.exit(main())
