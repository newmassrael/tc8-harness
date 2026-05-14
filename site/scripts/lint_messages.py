#!/usr/bin/env python3
"""Sanity-check hand-written ``messages[]`` overrides against the decoded
pcap manifests.

Runs as a build prestep so a stale ``idx`` (e.g. pcap re-captured with a
different packet count) fails the deploy before publishing rather than
silently rendering nothing in the timeline. Auto-generated outputs at
``site/src/data/auto_messages/*.json`` are NOT checked — the generator
controls those, and re-runs every refresh anyway.

Behaviour:
- Out-of-range idx → ERROR, exit code 1
- Duplicate idx within a single locale's messages[] → WARNING
- Missing pcap → SKIP (the overlay may land later in CI)
- Missing case manifest → SKIP (case may be deprecated)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
LOCALES_DIR = REPO_ROOT / "site" / "src" / "locales" / "cases"
PCAP_DIR = REPO_ROOT / "site" / "src" / "data" / "pcap"
CASES_DIR = REPO_ROOT / "site" / "src" / "data" / "cases"


def _load_messages(path: Path) -> list[dict]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"  ERROR: cannot read {path}: {exc}", file=sys.stderr)
        return []
    msgs = doc.get("messages")
    if not isinstance(msgs, list):
        return []
    return msgs


def _packet_count(case_id: str) -> int | None:
    pcap_path = PCAP_DIR / f"{case_id}.json"
    if not pcap_path.exists():
        return None
    try:
        doc = json.loads(pcap_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    pkts = doc.get("packets") or []
    return len(pkts)


def lint_locale(locale: str) -> tuple[int, int]:
    locale_dir = LOCALES_DIR / locale
    errors = 0
    warnings = 0
    if not locale_dir.exists():
        return 0, 0
    for path in sorted(locale_dir.glob("*.json")):
        case_id = path.stem.upper()
        msgs = _load_messages(path)
        if not msgs:
            continue
        pcount = _packet_count(case_id)
        seen: set[int] = set()
        for m in msgs:
            idx = m.get("idx")
            if not isinstance(idx, int):
                print(f"  ERROR {locale}/{case_id}: non-integer idx {idx!r}",
                      file=sys.stderr)
                errors += 1
                continue
            if idx in seen:
                print(f"  WARN  {locale}/{case_id}: duplicate idx {idx}",
                      file=sys.stderr)
                warnings += 1
            seen.add(idx)
            if pcount is not None and not (0 <= idx < pcount):
                print(f"  ERROR {locale}/{case_id}: idx {idx} out of range "
                      f"[0, {pcount})", file=sys.stderr)
                errors += 1
    return errors, warnings


def lint_captured_trace_invariant() -> tuple[int, int]:
    """Verify ``captured_trace.final_state``'s verdict bucket matches the
    pcap JSON's ``outcome``. The harness's transition trace is the single
    source of truth (Evidence Export — Option 3); a mismatch points at
    either a C++ trace-recording bug or a wire-verdict bug, both of
    which must block CI before the site walker labels timelines from
    drifting evidence.

    Skips cases without a ``captured_trace`` (backward compat for the
    pre-Phase-B pcaps still living in the pcap-data branch); those cases
    fall through to the walker's cond-loop fallback path. Once every
    case in pcap-data carries a trace, this lint can be flipped to
    require ``captured_trace`` presence directly.
    """
    errors = 0
    warnings = 0
    if not PCAP_DIR.exists():
        return 0, 0
    # Match harness state ids to verdict buckets — the SCXML convention
    # is ``pass`` for success terminals and ``fail*`` (often
    # ``fail_<reason>``) for failure terminals. ``running`` is the only
    # non-final harness state that could appear here on a deadline-
    # exceeded run that didn't reach any final — counts as "fail" for
    # invariant purposes (we never emit ``outcome: running``).
    def _bucket(state_name: str) -> str:
        s = (state_name or "").lower()
        if s == "pass":
            return "pass"
        if s.startswith("fail"):
            return "fail"
        return "fail"

    for pcap_path in sorted(PCAP_DIR.glob("*.json")):
        try:
            doc = json.loads(pcap_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"  ERROR: cannot read {pcap_path}: {exc}", file=sys.stderr)
            errors += 1
            continue
        trace = doc.get("captured_trace")
        if not isinstance(trace, dict):
            continue  # pre-trace pcap, walker falls back to cond loop
        final_state = trace.get("final_state") or ""
        outcome = doc.get("outcome") or ""
        bucket = _bucket(final_state)
        if outcome and bucket != outcome:
            case_id = pcap_path.stem
            print(
                f"  ERROR: {case_id}: trace.final_state={final_state!r} "
                f"(bucket={bucket!r}) disagrees with outcome={outcome!r}",
                file=sys.stderr,
            )
            errors += 1
    return errors, warnings


def main() -> int:
    total_err = 0
    total_warn = 0
    for locale in ("en", "ko"):
        e, w = lint_locale(locale)
        total_err += e
        total_warn += w
    trace_err, trace_warn = lint_captured_trace_invariant()
    total_err += trace_err
    total_warn += trace_warn
    if total_warn:
        print(f"messages[] lint: {total_warn} warning(s)", file=sys.stderr)
    if total_err:
        print(f"messages[] lint: {total_err} error(s)", file=sys.stderr)
        return 1
    print("messages[] lint: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
