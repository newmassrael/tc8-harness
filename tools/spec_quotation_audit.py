#!/usr/bin/env python3
"""Ratchet against re-quoting the TC8 spec body into this repository.

INVARIANT: a commit may not ADD comment text that reproduces eight or more
consecutive words of the TC8 spec body, unless the same hunk names the public
standard those words state.

The repository is public and the TC8 spec is not: its own notice restricts it
to OPEN Alliance members, and the download that carries it grants the right to
implement the specification, not to redistribute it. Transcribed test
procedures had accumulated in SCXML preambles and trait headers anyway -- 121
case files at the time this gate was written -- and were rewritten in this
repository's own words. This gate is what stops the next one.

What it reads, and why that and not the tree:

    Only the ADDED lines of the staged diff. The tree still carries deliberate
    overlap -- one-line statements of an RFC or AUTOSAR requirement, and case
    title lines -- which a whole-tree scan would report on every run until
    somebody waived it. Scanning what a commit adds keeps the gate quiet about
    what was already decided and loud about what is new.

The citation escape, and how far it reaches:

    Text that cites `RFC <number>` or an AUTOSAR requirement id
    (`TR_SOMEIP_00360`, `PRS_SOMEIP_00720`, `SWS_TCPIP_00060`, ...) may carry
    matching words. Both this repository and the TC8 spec restate the same
    public standards, so word runs converge there by construction; the citation
    is what makes the line a restatement of the public source rather than a
    copy of the spec's own writing.

    The escape is evaluated over a sliding SPAN of lines, not over the whole
    hunk, because a hunk can be an entire new file. Excusing every match in a
    file because one comment somewhere in it cites an RFC is how a gate passes
    the thing it was built to catch -- this module's first draft did exactly
    that to its own docstring.

Why eight words, measured on this tree (files whose comments match, of 1520):

    N=5 -> 840,  N=6 -> 619,  N=7 -> 423,  N=8 -> 349,  N=10 -> 203,  N=12 -> 127

    Below eight the window fires on protocol boilerplate that has one natural
    phrasing ("the ipv4 endpoint option shall be"). Above eight it starts
    missing single procedure steps, which run to about eight words once
    punctuation and case are dropped.

Polarity is fail-OPEN, and unlike the rest of this repo's gates that is not a
choice -- it is forced, and it is the gate's real limit:

    The corpus this compares against is `docs/spec/split/*.txt`, a local
    extraction of the spec PDF. Both are gitignored, because a members-only
    document does not belong in a public repository. So a fresh clone, CI, and
    every machine without the PDF cannot run this check at all, and the gate
    passes with a notice rather than blocking work it cannot judge.

    It is therefore a maintainer-side ratchet on the machine that holds the
    spec, not a repository-wide control. A commit made elsewhere, or with
    `--no-verify`, is not checked. Nothing here can be tightened without
    putting the spec text into the repository, which is the thing being
    avoided.

Usage:
    spec_quotation_audit.py --check        # staged diff (pre-commit hook)
    spec_quotation_audit.py --self-test    # detector behaviour, no corpus
"""

from __future__ import annotations

import glob
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_GLOB = str(REPO_ROOT / "docs" / "spec" / "split" / "*.txt")

WINDOW = 8

# Lines the citation escape reaches across. Wide enough to cover a comment
# block that states a requirement and cites it a line or two later; narrow
# enough that a citation elsewhere in a new file excuses nothing.
SPAN = 12

# Suffixes whose added lines are read. Comment-bearing sources plus SCXML,
# whose preamble is where the transcription collected.
SCANNED_SUFFIXES = (".scxml", ".h", ".hpp", ".c", ".cc", ".cpp", ".rs", ".py")

# A hunk naming one of these states a public requirement rather than copying
# the spec's prose. See "The citation escape" above.
CITATION_RE = re.compile(
    r"RFC\s?\d{3,5}"
    r"|(?:TR|PRS|SWS|ATS)_[A-Za-z0-9]+_\d{3,6}"
    r"|W3C\s+SCXML",
    re.IGNORECASE,
)


def normalise(text: str) -> str:
    """Letters, digits and single spaces -- punctuation and case carry no claim."""
    return re.sub(r"\s+", " ", re.sub(r"[^A-Za-z0-9 ]+", " ", text)).lower().strip()


def windows(text: str, size: int = WINDOW) -> set[str]:
    words = normalise(text).split()
    return {" ".join(words[i : i + size]) for i in range(len(words) - size + 1)}


def load_corpus() -> set[str] | None:
    """The spec's word windows, or None when the extraction is not present."""
    paths = sorted(glob.glob(CORPUS_GLOB))
    if not paths:
        return None
    words: list[str] = []
    for path in paths:
        words.extend(
            normalise(Path(path).read_text(encoding="utf-8", errors="replace")).split()
        )
    return {" ".join(words[i : i + WINDOW]) for i in range(len(words) - WINDOW + 1)}


def staged_hunks() -> list[tuple[str, str]]:
    """(path, added text) per staged hunk, for the scanned suffixes.

    Added lines of one hunk are joined, so a phrase split across comment lines
    is still one run of words.
    """
    diff = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "diff", "--cached", "-U0", "--no-color"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    hunks: list[tuple[str, str]] = []
    path = ""
    added: list[str] = []

    def flush() -> None:
        if path and added:
            hunks.append((path, "\n".join(added)))
        added.clear()

    for line in diff.split("\n"):
        if line.startswith("+++ b/"):
            flush()
            path = line[6:]
        elif line.startswith("@@"):
            flush()
        elif line.startswith("+") and not line.startswith("+++"):
            if path.endswith(SCANNED_SUFFIXES):
                added.append(line[1:])
    flush()
    return hunks


def scan(corpus: set[str], hunks: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """(path, longest matching run) for every span that quotes without citing.

    A span is SPAN consecutive added lines; every starting offset is tried, so
    a run straddling a boundary is still seen. One finding per path -- the
    longest run -- because a transcribed block reports as many spans.
    """
    findings: list[tuple[str, str]] = []
    for path, text in hunks:
        lines = text.split("\n")
        worst = ""
        for start in range(max(len(lines) - SPAN + 1, 1)):
            span = lines[start : start + SPAN]
            span_text = "\n".join(span)
            if CITATION_RE.search(span_text):
                continue
            matches = windows(span_text) & corpus
            if matches:
                candidate = max(matches, key=len)
                if len(candidate) > len(worst):
                    worst = candidate
        if worst:
            findings.append((path, worst))
    return findings


def _check() -> int:
    corpus = load_corpus()
    if corpus is None:
        print(
            "spec_quotation_audit: docs/spec/split/*.txt absent -- nothing to "
            "compare against, gate skipped (see the module docstring)"
        )
        return 0

    findings = scan(corpus, staged_hunks())
    if not findings:
        return 0

    print(
        f"spec_quotation_audit: {len(findings)} staged hunk(s) reproduce the "
        f"TC8 spec body:",
        file=sys.stderr,
    )
    for path, run in findings:
        print(f"  {path}", file=sys.stderr)
        print(f"    matched: {run}", file=sys.stderr)
    print(
        "\nWrite what the case does in this repository's own words, or cite the "
        "public standard the sentence states (RFC 793, TR_SOMEIP_00360, ...).",
        file=sys.stderr,
    )
    return 1


def _self_test() -> int:
    """Detector behaviour against a stand-in corpus -- no spec text needed."""
    source = (
        "the tester shall cause the device under test to move on to the "
        "established state and then send a data segment with an incorrect "
        "checksum value"
    )
    corpus = windows(source)

    cases = [
        ("verbatim run", "// cause the device under test to move on to the established state", True),
        ("our own words", "// a seam active open parks the DUT in ESTABLISHED", False),
        ("short overlap", "// send a data segment", False),
        ("cited restatement",
         "// send a data segment with an incorrect checksum value (RFC 1122 4.2.2.7)", False),
        ("cited by requirement id",
         "// cause the device under test to move on to the established state "
         "(TR_SOMEIP_00360)", False),
        ("split across lines",
         "// cause the device under test to move\n// on to the established state", True),
        ("citation too far to reach the quote",
         "// a note citing RFC 793 for something else entirely\n"
         + "\n".join(f"// filler line {i}" for i in range(SPAN))
         + "\n// cause the device under test to move on to the established state",
         True),
    ]

    failures = 0
    for label, added, expect in cases:
        fired = bool(scan(corpus, [("case.h", added)]))
        if fired != expect:
            verb = "did not fire" if expect else "false-fired"
            print(f"self-test FAIL: {label} -- detector {verb}", file=sys.stderr)
            failures += 1

    if failures:
        return 1
    print(f"spec_quotation_audit self-test: all {len(cases)} checks passed")
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--self-test":
        return _self_test()
    if argv and argv[0] != "--check":
        sys.exit("usage: spec_quotation_audit.py [--check | --self-test]")
    return _check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
