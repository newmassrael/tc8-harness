#!/usr/bin/env python3
"""Keep what the NDA boundary bans out of commits as they are made.

The ban list lives in ONE place: cmake/check-nda-hygiene.cmake, the `nda_hygiene` CTest. It
scans tracked file CONTENTS, and only when ctest runs, which is after a push. That left two
ways in: a commit MESSAGE (no gate reads one), and a staged line that CI would reject only
once it had left the machine. This tool applies the same list at the two points where a
commit can still be stopped:

    --message FILE   a commit message (the commit-msg hook); `#` lines are git's own.
    --staged         the lines a commit adds (the pre-commit hook), in the roots the CTest
                     gate scans, never the gate file itself (it spells the list).
    --self-test      plant a token and watch the gate fail; plant none and watch it pass.

The list is READ from the CMake file, never copied here, so the hooks and the CI check cannot
disagree about what is banned (a second copy is the one that drifts). If the list cannot be
read the tool fails closed (exit 2): an unreadable ban list must not read as an empty one.

This file spells no banned token, so the CTest gate can scan tools/ without tripping on it;
the self-test builds its samples from fragments for the same reason.

Exit codes: 0 clean, 1 a banned token was found, 2 the ban list could not be read.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GATE_REL = "cmake/check-nda-hygiene.cmake"
GATE = REPO / GATE_REL
LIST_NAMES = ("_banners", "_oem_ids", "_site_ids")

# The CTest gate scans these roots plus the top-level CMakeLists.txt, and site/ through its own
# glob (generated site/src/data/ excluded). Roots come from the gate; the two extras are its
# own special cases, restated because they are not in its root list.
EXTRA_ROOTS = ("site",)
EXCLUDED_PREFIXES = ("site/src/data/",)


class DenylistUnreadable(Exception):
    pass


def _cmake_set(text: str, name: str) -> str:
    m = re.search(r"^\s*set\(\s*" + re.escape(name) + r"\s+(.*?)\)\s*$", text, re.M)
    if not m:
        raise DenylistUnreadable(f"set({name} ...) not found in {GATE_REL}")
    value = m.group(1).strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    if not value:
        raise DenylistUnreadable(f"set({name} ...) in {GATE_REL} is empty")
    return value


def load_denylist(gate_text: str | None = None) -> tuple[re.Pattern[str], list[str]]:
    """(pattern, roots) as the CTest gate holds them."""
    try:
        text = gate_text if gate_text is not None else GATE.read_text(encoding="utf-8")
    except OSError as exc:
        raise DenylistUnreadable(f"cannot read {GATE_REL}: {exc}") from exc
    parts = [_cmake_set(text, n) for n in LIST_NAMES]
    roots = _cmake_set(text, "_roots").split()
    try:
        return re.compile("|".join(parts)), roots
    except re.error as exc:
        raise DenylistUnreadable(f"{GATE_REL} holds a pattern Python cannot read: {exc}") from exc


def in_scope(path: str, roots: list[str]) -> bool:
    if path == GATE_REL or any(path.startswith(p) for p in EXCLUDED_PREFIXES):
        return False
    return path == "CMakeLists.txt" or path.split("/", 1)[0] in (*roots, *EXTRA_ROOTS)


def scan_message(pattern: re.Pattern[str], raw: str) -> list[str]:
    hits = []
    for no, line in enumerate(raw.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        m = pattern.search(line)
        if m:
            hits.append(f"commit message line {no}: {m.group(0)!r}")
    return hits


def scan_diff(pattern: re.Pattern[str], roots: list[str], diff: str) -> list[str]:
    """Hits on ADDED lines of a `git diff -U0` text, in scope only."""
    hits: list[str] = []
    path = ""
    new_line = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else ""
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            new_line = int(m.group(1)) if m else 0
        elif line.startswith("+") and not line.startswith("+++"):
            if path and in_scope(path, roots):
                m = pattern.search(line[1:])
                if m:
                    hits.append(f"{path}:{new_line}: {m.group(0)!r}")
            new_line += 1
    return hits


def staged_diff() -> str:
    return subprocess.run(
        ["git", "diff", "--cached", "-U0", "--no-color", "--diff-filter=ACMR"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout


def self_test() -> int:
    pattern, roots = load_denylist()
    j = "".join
    banned = {
        "site family": j(["h", "k", "l"]) + "9",
        "site family, upper case": j(["H", "K", "L"]),
        "machine alias": "build on " + j(["p", "c"]) + "7 now",
        "machine alias at line start": j(["P", "C"]) + "12",
        "oem name, mixed case": j(["H", "k", "M", "c"]),
        "oem requirement id": j(["D", "S", "_", "C", "N", "_", "1"]),
        "oem case family": j(["SOMEIPSRV", "_", "CAN", "_", "3"]),
        "banner": j(["CONFIDENT", "IAL"]),
    }
    clean = ["two build machines", "ipc2 and " + j(["x", "pc"]) + "9", "pc without a number", "RFC 6298 section 5", "a 15 GB build machine", "SOMEIPSRV_RPC_18",
             j(["h", "k", "m"]), j(["h", "k"]) + " " + j(["l", "ine"])]
    failures: list[str] = []
    checks = 0

    def expect(ok: bool, what: str) -> None:
        nonlocal checks
        checks += 1
        if not ok:
            failures.append(what)

    for name, token in banned.items():
        expect(bool(pattern.search(token)), f"list misses {name}")
        expect(bool(scan_message(pattern, f"feat: x\n\n- {token}")), f"message scan misses {name}")
        diff = f"+++ b/docs/sample.txt\n@@ -0,0 +1 @@\n+{token}\n"
        expect(len(scan_diff(pattern, roots, diff)) == 1, f"diff scan misses {name}")
    for text in clean:
        expect(not pattern.search(text), f"list flags clean text {text!r}")
    expect(not scan_message(pattern, "# " + j(["h", "k", "l"]) + " in a git comment\nfeat: x"),
           "message scan reads a # comment line")
    hit = j(["h", "k", "l"])
    expect(not scan_diff(pattern, roots, f"+++ b/{GATE_REL}\n@@ -0,0 +1 @@\n+{hit}\n"),
           "diff scan reads the gate file")
    expect(not scan_diff(pattern, roots, f"+++ b/claudedocs/sample.txt\n@@ -0,0 +1 @@\n+{hit}\n"),
           "diff scan reads a path outside the gate's roots")
    expect(not scan_diff(pattern, roots, f"+++ b/docs/sample.txt\n@@ -1 +1 @@\n-{hit}\n+fine\n"),
           "diff scan reads a REMOVED line")
    unreadable = False
    try:
        load_denylist("set(_banners \"x\")\n")
    except DenylistUnreadable:
        unreadable = True
    expect(unreadable, "an incomplete ban list reads as readable (must fail closed)")
    for f in failures:
        print(f"nda_boundary_audit self-test FAILED: {f}", file=sys.stderr)
    if not failures:
        print(f"nda_boundary_audit self-test: all {checks} checks passed")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--message", metavar="FILE")
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.self_test:
            return self_test()
        pattern, roots = load_denylist()
        if args.message:
            hits = scan_message(pattern, Path(args.message).read_text(encoding="utf-8"))
            where = "commit message"
        else:
            hits = scan_diff(pattern, roots, staged_diff())
            where = "staged change"
    except DenylistUnreadable as exc:
        print(f"nda_boundary_audit: the ban list cannot be read, so nothing is checked: {exc}",
              file=sys.stderr)
        return 2
    if not hits:
        return 0
    print(f"nda_boundary_audit: the {where} carries what the NDA boundary bans "
          f"(the list is in {GATE_REL}):", file=sys.stderr)
    for h in hits:
        print(f"  {h}", file=sys.stderr)
    print("  describe a machine by what it provides, not by its name; keep the rest out of this "
          "public repository.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
