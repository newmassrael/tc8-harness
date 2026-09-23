#!/usr/bin/env python3
"""Reject a pointer this repository cannot follow.

INVARIANT: no tracked file names a note or a document that the repository does
not hold. A comment, a doc page or a data field that says "see X" must name
something a reader of this public repository can open.

Why this exists (docs/tech-debt.md TD-34): comments in the case sources cited
rationale notes from a private note store -- `reference_<topic>.md`, "the
<topic> memory" -- and design notes under `claudedocs/`, which `.gitignore`
keeps out of the repository. By 2026-09-24, 45 comments and 14 data fields
pointed at them. The claims next to them had gone stale unseen: a TCP case said
Linux silently drops a segment that kernel 7.0 answers, and three comments
cited a CI grep filter that no longer existed. `platform_known_fail_ref`
already had a resolution check (tools/debt_census.py `ref_resolves`); nothing
else did. This is that check for everything else.

What it flags, per line of every tracked text file in scope:

    PRIVATE_NOTE   the name of a note from the private store: a
                   `reference_`, `project_` or `feedback_` slug of two or more
                   words, with or without `.md`. Those stores are never
                   published, so the name is a dead pointer wherever it sits.
    MEMORY_PATH    a `memory/<name>.md` path.
    UNRESOLVED_MD  a `<path>.md` token that resolves to no tracked file --
                   neither from the repository root, nor relative to the
                   citing file's directory, nor (for a bare file name) as the
                   name of any tracked file. This is what catches a
                   `claudedocs/` note: the directory is ignored, so nothing in
                   it is tracked.

Scope: every file `git ls-files` lists, except `third_party/` (vendored
upstream text, not this repository's claims), `docs/.atomic/` (the mnemosyne
store, machine-written), `.gitignore` (it names `claudedocs/` as a rule, not as
a pointer), binary files, and this file (its docstring and self-test carry
samples of what it rejects).

Exemptions are (file, token) PAIRS, each with a reason, never whole files: a
new pointer added to an exempt file is still caught.

Polarity is fail-CLOSED: the tree is scanned whole, not the staged diff, so a
pointer that slipped in by any route fails the next run anywhere.

Usage:
    tools/intree_pointer_audit.py [--check]   scan; rc 1 on any finding
    tools/intree_pointer_audit.py --self-test detector behaviour
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve().relative_to(ROOT).as_posix()

EXCLUDED_PREFIXES = ("third_party/", "docs/.atomic/")
EXCLUDED_FILES = {".gitignore", SELF}

# (file, token) -> reason. A token is exempt only in the file named.
EXEMPT: dict[tuple[str, str], str] = {
    ("tools/debt_census.py", "memory/x.md"):
        "self-test fixture: proves ref_resolves rejects an out-of-tree ref",
    ("tools/debt_census.py", "docs/x.md"):
        "self-test fixture: the in-tree path its fake file list holds",
    (".github/workflows/mnemosyne.yml", "GENERATED.md"):
        "names the render artifact upstream mnemosyne retired, not a document to read",
    ("mnemosyne.toml", "GENERATED.md"):
        "names the render artifact upstream mnemosyne retired, not a document to read",
    ("unit_tests/spec_inventory_test.cpp", "memory/some_note.md"):
        "loader fixture: an arbitrary ref string the parser must carry verbatim",
    ("docs/tech-debt.md", "reference_icmp_packet_host_gate.md"):
        "TD-34 records the defect by naming the notes it measured",
    ("docs/tech-debt.md", "reference_sce_captured_arg.md"):
        "TD-34 records the defect by naming the notes it measured",
    ("docs/tech-debt.md", "reference_active_open_port_quad_collision.md"):
        "TD-34 records the defect by naming the notes it measured",
}

PRIVATE_NOTE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:reference|project|feedback)_[a-z0-9]+(?:_[a-z0-9]+)+(?:\.md)?(?![A-Za-z0-9_])"
)
MEMORY_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])memory/[A-Za-z0-9_.-]+\.md\b")
MD_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_./-])[A-Za-z0-9_][A-Za-z0-9_./-]*\.md\b")


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode("utf-8", "replace")
    return [f for f in out.split("\0") if f]


def in_scope(path: str) -> bool:
    return not path.startswith(EXCLUDED_PREFIXES) and path not in EXCLUDED_FILES


def md_resolves(token: str, citing: str, files: set[str], basenames: set[str]) -> bool:
    if token in files:
        return True
    rel = os.path.normpath(os.path.join(os.path.dirname(citing), token))
    if rel in files:
        return True
    return "/" not in token and token in basenames


def scan_line(line: str, citing: str, files: set[str], basenames: set[str]) -> list[tuple[str, str]]:
    """(kind, token) for every unfollowable pointer on one line."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in PRIVATE_NOTE_RE.finditer(line):
        found.append(("PRIVATE_NOTE", m.group(0)))
        seen.add(m.group(0))
    for m in MEMORY_PATH_RE.finditer(line):
        found.append(("MEMORY_PATH", m.group(0)))
        seen.add(m.group(0))
        seen.add(m.group(0).split("/", 1)[1])
    for m in MD_TOKEN_RE.finditer(line):
        tok = m.group(0)
        if tok in seen or line[max(0, m.start() - 3):m.start()] == "://":
            continue
        if not md_resolves(tok, citing, files, basenames):
            found.append(("UNRESOLVED_MD", tok))
    return found


def scan() -> list[str]:
    all_files = tracked_files()
    files = set(all_files)
    basenames = {os.path.basename(f) for f in all_files}
    findings: list[str] = []
    for path in all_files:
        if not in_scope(path):
            continue
        try:
            data = (ROOT / path).read_bytes()
        except (FileNotFoundError, IsADirectoryError):
            continue  # a tracked path deleted in the work tree, or a submodule
        if b"\0" in data[:8192]:
            continue  # binary
        text = data.decode("utf-8", "replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            for kind, tok in scan_line(line, path, files, basenames):
                if (path, tok) in EXEMPT:
                    continue
                findings.append(f"{kind}: {path}:{lineno}: {tok}")
    return findings


def _check() -> int:
    findings = scan()
    for f in findings:
        print(f)
    if findings:
        print(
            f"intree_pointer_audit: {len(findings)} pointer(s) this repository cannot follow. "
            "Bring the fact the pointer stood for into the tree -- at the site, or in the "
            "in-tree doc or header that owns it -- and point there (docs/tech-debt.md TD-34).",
            file=sys.stderr,
        )
        return 1
    print("intree_pointer_audit: OK -- every pointer resolves in-tree")
    return 0


def _self_test() -> int:
    files = {"docs/tech-debt.md", "dut/env/negative_rows.md", "src/a/b.h", "README.md"}
    basenames = {os.path.basename(f) for f in files}
    cases = [
        ("see reference_icmp_packet_host_gate.md", "src/a/b.h", {"PRIVATE_NOTE"}),
        ("see reference_subscribe_sd_port memory.", "src/a/b.h", {"PRIVATE_NOTE"}),
        ("(`feedback_frozen_spec_is_evidence.md`)", "src/a/b.h", {"PRIVATE_NOTE"}),
        ("see project_someip_ets_seed_coverage.md", "src/a/b.h", {"PRIVATE_NOTE"}),
        ("See memory/reference_timing_serial_cadence.md.", "tools/x.py", {"MEMORY_PATH", "PRIVATE_NOTE"}),
        ("See claudedocs/testability_seam_tier2_design.md.", "src/a/b.h", {"UNRESOLVED_MD"}),
        ("see docs/tech-debt.md TD-34", "src/a/b.h", set()),
        ("\"neg_row_ref\": \"dut/env/negative_rows.md\"", "docs/spec/x.json", set()),
        ("see README.md", "src/a/b.h", set()),
        ("the user_data_len field", "src/a/b.h", set()),
        ("https://example.org/notes/design.md", "src/a/b.h", set()),
    ]
    failed = 0
    for line, citing, want in cases:
        got = {k for k, _ in scan_line(line, citing, files, basenames)}
        if got != want:
            print(f"self-test FAIL: {line!r} -> {sorted(got)}, want {sorted(want)}", file=sys.stderr)
            failed += 1
    for (path, tok), reason in EXEMPT.items():
        if not reason:
            print(f"self-test FAIL: exemption ({path}, {tok}) has no reason", file=sys.stderr)
            failed += 1
    if failed:
        return 1
    print(f"intree_pointer_audit self-test: all {len(cases)} checks passed")
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--self-test":
        return _self_test()
    if argv and argv[0] not in ("--check",):
        sys.exit("usage: intree_pointer_audit.py [--check | --self-test]")
    return _check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
