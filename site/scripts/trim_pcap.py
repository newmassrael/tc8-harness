#!/usr/bin/env python3
"""Cap per-case pcap JSON file sizes for the pcap-data branch.

Some tests (e.g. SOMEIP_ETS_152 SD session_id wrap, which bursts ~100k
SubscribeEventgroup frames in ~150 s) produce decoded JSON over 100 MB
— the GitHub repo file-size hard limit. The site timeline can't render
that many rows usefully anyway. This trimmer:

* Walks every ``*.json`` in the given directory.
* If a file is over the byte budget, keeps the first ``--head`` packets
  and the last ``--tail`` packets, inserts a synthetic ``[truncated]``
  marker packet between them, and rewrites the file in place.
* Files under the budget are left alone.

Idempotent: a re-run on already-trimmed output is a no-op because the
remaining packet count is small.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _bytes_of(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def trim_file(path: Path, byte_budget: int, head: int, tail: int) -> tuple[bool, str]:
    """Returns (was_trimmed, message)."""
    size = _bytes_of(path)
    if size <= byte_budget:
        return False, ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, f"{path.name}: malformed JSON ({exc})"
    packets = data.get("packets") or []
    if len(packets) <= head + tail:
        return False, f"{path.name}: oversize but only {len(packets)} packets — won't trim"

    head_pkts = packets[:head]
    tail_pkts = packets[-tail:]
    dropped = len(packets) - head - tail

    last_head_idx = head_pkts[-1].get("idx", head - 1)
    first_tail_idx = tail_pkts[0].get("idx", len(packets) - tail)
    marker = {
        "idx": last_head_idx + 1,
        "ts_us": tail_pkts[0].get("ts_us", 0),
        "ts_delta_us": 0,
        "direction": "other",
        "protocol": "[truncated]",
        "summary": (
            f"… {dropped} packet(s) elided to stay under the "
            f"GitHub file-size limit; original idx span "
            f"[{last_head_idx + 1}, {first_tail_idx - 1}] not stored …"
        ),
        "fields": {"truncated_count": dropped},
    }

    data["packets"] = head_pkts + [marker] + tail_pkts
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                    encoding="utf-8")
    new_size = _bytes_of(path)
    return True, (f"{path.name}: {size//1024//1024} MB → {new_size//1024} KB "
                  f"({len(packets)} → {len(data['packets'])} packets)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dir", type=Path,
                    help="Directory containing pcap JSON files")
    ap.add_argument("--max-bytes", type=int, default=5 * 1024 * 1024,
                    help="Trim files larger than this (default 5 MB).")
    ap.add_argument("--head", type=int, default=200,
                    help="Packets to keep from the start (default 200).")
    ap.add_argument("--tail", type=int, default=200,
                    help="Packets to keep from the end (default 200).")
    args = ap.parse_args(argv)

    if not args.dir.exists():
        print(f"no such dir: {args.dir}", file=sys.stderr)
        return 1
    trimmed = 0
    for path in sorted(args.dir.glob("*.json")):
        ok, message = trim_file(path, args.max_bytes, args.head, args.tail)
        if message:
            print(message)
        if ok:
            trimmed += 1
    print(f"trimmed {trimmed} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
