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
    REPO_PATH      a file path rooted at one of this repository's own top-level
                   directories (`src/...`, `dut/...`, `tests/...`) that the
                   tree does not hold NOW. A reader opens files, not history,
                   so a path retired three months ago leads nowhere even though
                   `git log -- <path>` still finds it.

WHY THIS RULE IS THE TREE AND NOT THE HISTORY, measured 2026-09-24. It was
history-aware at first: a path counted as held if `git log --all --name-only`
had ever listed it. That made the VERDICT depend on CLONE DEPTH. This
workstation has 5803 such paths and the gate was green; CI checks out with
`actions/checkout` and no `fetch-depth`, so its clone is shallow, its history is
one commit, and the same tree failed with 29 findings. A gate that answers
differently in two places teaches a green that means nothing -- the same defect
as the negative-coverage audit crediting a whole case for one proven final
(docs/tech-debt.md TD-42).

Both readings could have been made deterministic; this one was chosen because
the other left the gate unable to tell a deliberate historical mention from a
stale live pointer, and the 29 findings were nearly all the second kind
(`dut/env/smoke-test.sh`, retired at the orchestrator cutover;
`site/scripts/decode_pcap.py`, replaced by the C++ decoder at TD-05). A genuine
historical reference is still expressible -- as an exemption pair carrying its
reason, which is a line a reviewer sees.

Scope: every file `git ls-files` lists, except `third_party/` (vendored
upstream text, not this repository's claims), `docs/.atomic/` (the mnemosyne
store, machine-written), every `.gitignore` (it names paths as rules, not as
pointers), binary files, and this file (its docstring and self-test carry
samples of what it rejects). A path inside a submodule is held by that
submodule's repository.

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
    # REPO_PATH: paths inside the upstream lwIP and CommonAPI source trees, which
    # share a top-level name (src/, examples/, include/) with this repository.
    ("dut/lwip_dut/CMakeLists.txt", "src/Filelists.cmake"): "a path in the lwIP source tree",
    ("dut/lwip_dut/CMakeLists.txt", "src/netif/ppp/polarssl/md5.c"): "a path in the lwIP source tree",
    ("dut/lwip_dut/README.md", "src/core/ipv4/icmp.c"): "a path in the lwIP source tree",
    ("dut/lwip_dut/README.md", "src/core/ipv4/etharp.c"): "a path in the lwIP source tree",
    ("dut/lwip_dut/README.md", "src/core/udp.c"): "a path in the lwIP source tree",
    ("dut/lwip_dut/lwipopts.h", "src/include/lwip/opt.h"): "a path in the lwIP source tree",
    ("dut/lwip_dut/lwip_stack_bringup.cpp", "examples/example_app/default_netif.h"):
        "a path in the lwIP contrib tree",
    ("dut/ets/ets.fdepl", "include/CommonAPI/SomeIP/Deployment.hpp"):
        "a path in the CommonAPI-SomeIP source tree",
    ("docs/tech-debt.md", "src/CommonAPI/SomeIP/Connection.cpp"):
        "a path in the CommonAPI-SomeIP source tree",
    ("docs/tech-debt.md", "src/core/ipv4/etharp.c"): "a path in the lwIP source tree",
    ("examples/demo_middleware_module/README.md", "examples/example_app/default_netif.h"):
        "a path in the lwIP contrib tree",
    ("site/scripts/build_manifest.py", "site/src/data/index.json"):
        "the manifest this script generates at site build time",
    ("site/src/lib/cases.ts", "site/src/data/index.json"):
        "the manifest site/scripts/build_manifest.py generates at site build time",
    ("tools/workflow_runner_audit.py", "./.github/workflows/x.yml"):
        "a placeholder showing the shape of a local reusable-workflow call",
}

PRIVATE_NOTE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:reference|project|feedback)_[a-z0-9]+(?:_[a-z0-9]+)+(?:\.md)?(?![A-Za-z0-9_])"
)
MEMORY_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])memory/[A-Za-z0-9_.-]+\.md\b")
MD_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_./-])[A-Za-z0-9_][A-Za-z0-9_./-]*\.md\b")
# A relative file path with at least one directory and an extension. `$`, `{`
# and `}` in the look-behind skip shell expansions like `$ROOT/dut/...`.
PATH_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_./${}-])[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\.[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*\b"
)


class Tree:
    """What a pointer can resolve against: the tracked files NOW and the
    repository's own top-level directories. Deliberately not git history --
    the module docstring records what that cost."""

    def __init__(self, files: set[str], submodules: frozenset[str] = frozenset()):
        self.files = files
        self.submodules = submodules  # a path inside one is held by that repository
        self.basenames = {os.path.basename(f) for f in files}
        self.tops = {f.split("/", 1)[0] for f in files if "/" in f}


def git_lines(*args: str) -> list[str]:
    out = subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True)
    return out.stdout.decode("utf-8", "replace").splitlines()


def load_tree() -> Tree:
    files = set(git_lines("ls-files"))
    submodules = frozenset(
        line.split("\t", 1)[1] for line in git_lines("ls-files", "-s") if line.startswith("160000 ")
    )
    return Tree(files, submodules)


def in_scope(path: str) -> bool:
    if path.startswith(EXCLUDED_PREFIXES) or path in EXCLUDED_FILES:
        return False
    return os.path.basename(path) != ".gitignore"  # rules, not pointers


def md_resolves(token: str, citing: str, tree: Tree) -> bool:
    if token in tree.files:
        return True
    rel = os.path.normpath(os.path.join(os.path.dirname(citing), token))
    if rel in tree.files:
        return True
    return "/" not in token and token in tree.basenames


def repo_path_held(token: str, citing: str, tree: Tree) -> bool:
    """True unless the token is rooted at one of this repository's top-level
    directories and the tree does not hold it NOW. No history lookup: the
    verdict must not depend on how deep the clone is."""
    t = token[2:] if token.startswith("./") else token
    if t.split("/", 1)[0] not in tree.tops:
        return True  # a system header, a third-party tree, a path under a variable
    if any(t == s or t.startswith(s + "/") for s in tree.submodules):
        return True
    rel = os.path.normpath(os.path.join(os.path.dirname(citing), t))
    return any(p in tree.files for p in (t, rel))


def scan_line(line: str, citing: str, tree: Tree) -> list[tuple[str, str]]:
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
        seen.add(tok)
        if not md_resolves(tok, citing, tree):
            found.append(("UNRESOLVED_MD", tok))
    for m in PATH_TOKEN_RE.finditer(line):
        tok = m.group(0)
        if tok in seen or line[max(0, m.start() - 3):m.start()] == "://":
            continue
        if not repo_path_held(tok, citing, tree):
            found.append(("REPO_PATH", tok))
    return found


DEBT_REGISTER = "docs/tech-debt.md"
_TD_HEAD_RE = re.compile(r"^## TD-\d+\s")
_TD_RESOLVED_RE = re.compile(r"\*\*Status:\*\*\s*RESOLVED")


def settled_debt_entry(path: str, line: str, settled: bool) -> bool:
    """Whether this line of the debt register sits inside a RESOLVED entry.

    REPO_PATH is suppressed there, and ONLY there. A resolved entry's body is a
    DATED RECORD of a state that no longer exists -- TD-01 says the SD decode
    once lived in `src/sce_integration/someip_captured.h`, which was true when
    logged and is why the entry exists. Repointing it at today's path would make
    the record state something that never happened, and the register's own
    header forbids rewriting entries ("Append new entries; do not renumber").

    Measured before this was written, 2026-09-24: all 43 REPO_PATH occurrences
    in the register fell inside TD-01..TD-14, every one RESOLVED, and none in an
    OPEN entry. So this suppresses exactly the historical class and nothing
    live: an OPEN entry naming a dead path still fails, which is what keeps a
    Textbook fix or a Done when line honest.

    The other three classes are NOT suppressed here. A private-note name or an
    unresolvable .md is a dead pointer whatever its surrounding entry says.
    """
    if path != DEBT_REGISTER:
        return False
    if _TD_HEAD_RE.match(line):
        return False  # a new entry starts unsettled until its Status says so
    return settled or bool(_TD_RESOLVED_RE.search(line))


def scan() -> list[str]:
    tree = load_tree()
    findings: list[str] = []
    for path in sorted(tree.files):
        if not in_scope(path):
            continue
        try:
            data = (ROOT / path).read_bytes()
        except (FileNotFoundError, IsADirectoryError):
            continue  # a tracked path deleted in the work tree, or a submodule
        if b"\0" in data[:8192]:
            continue  # binary
        text = data.decode("utf-8", "replace")
        settled = False  # see settled_debt_entry()
        for lineno, line in enumerate(text.splitlines(), 1):
            settled = settled_debt_entry(path, line, settled)
            for kind, tok in scan_line(line, path, tree):
                if (path, tok) in EXEMPT:
                    continue
                if kind == "REPO_PATH" and settled:
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
    tree = Tree(
        files={"docs/tech-debt.md", "dut/env/negative_rows.md", "src/a/b.h", "README.md",
               "tests/x/x.scxml", "tools/x.py", "docs/spec/x.json"},
    )
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
        ("see src/a/b.h", "tests/x/x.scxml", set()),
        # A retired path is a finding even though git history still holds it.
        # These two cases are the clone-depth dependence, written as a test:
        # under the old history-aware rule they passed on a full clone and
        # failed on CI's shallow one, which is how the divergence shipped.
        ("the Rust successor to dut/env/smoke-test.sh", "src/a/b.h", {"REPO_PATH"}),
        ("formerly src/old/moved.h", "src/a/b.h", {"REPO_PATH"}),
        ("see mock_dut/env/smoke-test.sh", "tests/x/x.scxml", set()),
        ("see src/never/held.h", "tests/x/x.scxml", {"REPO_PATH"}),
        ("#include <sys/socket.h>", "src/a/b.h", set()),
        ("\"$ROOT/dut/env/wire.gen.sh\"", "tools/x.py", set()),
    ]
    failed = 0
    for line, citing, want in cases:
        got = {k for k, _ in scan_line(line, citing, tree)}
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
