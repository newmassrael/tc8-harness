#!/usr/bin/env python3
"""Every `--log-dir` a workflow step passes must be pre-created as runner-owned.

WHY THIS EXISTS. The netns lanes run the orchestrator under `sudo`, so any
directory the orchestrator creates itself is owned by root. The runner user
cannot delete a root-owned directory's contents, so the NEXT run's
`actions/checkout` fails in `git clean` -- and it fails before anything builds,
which makes it look like an infrastructure drop rather than a repository defect.

The workflow already knows this. It says so above the `mkdir -p` that pre-creates
the log directories: "A root-owned dir here fails `git clean` (exit 128) and
blocks all future checkouts." What it did not have was anything CHECKING that the
list stayed complete. On 2026-09-25 a `--known-fail` step was added with
`--log-dir smoke-logs/known-fail`, the `mkdir` list was not extended, and the run
after the next successful one died exactly as the comment predicted (run
36123076966, checkout failed in 2 s with "허가 거부" on every file under
smoke-logs/known-fail).

⚠ The defect was invisible for a week because the lane was timing out BEFORE it
reached the new step. The step had to start succeeding for its leftovers to break
the next checkout, so repairing one thing exposed the other
(docs/tech-debt.md TD-43, TD-51).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"

LOG_DIR_RE = re.compile(r"--log-dir\s+(\S+)")


def strip_comments(text: str) -> str:
    """Drop whole comment lines, in both languages this file is written in.

    ⚠ Measured on the first run of this gate: without it, three findings came
    back and only ONE was real. The other two were prose -- a YAML comment
    describing "each step's `--log-dir smoke-logs/<step>`" and another ending
    "--log-dir to feed this." A gate that reports two parts noise teaches its
    reader to skim, which is how the real row gets skimmed too.

    Whole lines only: `#` is a comment opener in the YAML and in every `run: |`
    shell body here, but mid-line it can also be a fragment of a value, and this
    gate has no reason to guess.
    """
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def mkdir_targets(text: str) -> set[str]:
    """Every path any `mkdir -p` in this text creates, following continuations.

    A shell continuation splits one command over several YAML lines, and the
    directories this gate cares about are written that way -- reading only the
    `mkdir` line itself would see one of seven.
    """
    made: set[str] = set()
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if "mkdir " not in lines[i]:
            i += 1
            continue
        chunk = lines[i]
        while chunk.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            chunk = chunk.rstrip()[:-1] + " " + lines[i]
        # Drop everything up to and including the `mkdir`, plus its flags.
        args = chunk.split("mkdir", 1)[1]
        for tok in args.split():
            if tok.startswith("-") or tok in {"&&", "||", ";"}:
                continue
            made.add(tok.strip("'\""))
        i += 1
    return made


def audit(text: str) -> list[str]:
    """`--log-dir` paths this text uses but never pre-creates."""
    text = strip_comments(text)
    used = {m.group(1).strip("'\"") for m in LOG_DIR_RE.finditer(text)}
    made = mkdir_targets(text)
    return sorted(d for d in used if d not in made)


def _self_test() -> int:
    good = """
        run: |
          mkdir -p reports \\
            smoke-logs/positive smoke-logs/negative \\
            smoke-logs/known-fail
          sudo -n orch --log-dir smoke-logs/positive
          sudo -n orch --log-dir smoke-logs/negative
          sudo -n orch --log-dir smoke-logs/known-fail
    """
    bad = """
        run: |
          mkdir -p reports \\
            smoke-logs/positive smoke-logs/negative
          sudo -n orch --log-dir smoke-logs/positive
          sudo -n orch --log-dir smoke-logs/known-fail
    """
    # A continuation the naive single-line reader would miss entirely.
    cont_only = """
          mkdir -p reports \\
            smoke-logs/late
          orch --log-dir smoke-logs/late
    """
    checks = [
        ("complete list passes", audit(good) == []),
        ("missing dir is named", audit(bad) == ["smoke-logs/known-fail"]),
        ("only the missing one", len(audit(bad)) == 1),
        ("continuation lines are followed", audit(cont_only) == []),
        ("mkdir flags are not paths", "-p" not in mkdir_targets(good)),
        ("quotes stripped", audit('mkdir -p "a/b"\n--log-dir a/b') == []),
        ("no log-dir at all is clean", audit("mkdir -p x") == []),
        # Prose mentioning the flag is not a use of it. Both of these appear
        # verbatim in smoke-test.yml and both were reported before stripping.
        ("comment prose ignored",
         audit("  # each step's `--log-dir smoke-logs/<step>` captured") == []),
        ("comment at line end ignored",
         audit("          # --log-dir to feed this.)") == []),
        # The real file must be clean once repaired -- this is the check that
        # would have caught the defect, so it belongs in the self-test too.
        ("live workflows clean", not live_findings()),
    ]
    bad_names = [n for n, ok in checks if not ok]
    if bad_names:
        print("workflow_logdir_audit self-test FAILED: " + ", ".join(bad_names),
              file=sys.stderr)
        return 1
    print(f"workflow_logdir_audit self-test: all {len(checks)} checks passed")
    return 0


def live_findings() -> list[str]:
    out: list[str] = []
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        for d in audit(path.read_text(encoding="utf-8")):
            out.append(f"{path.name}: --log-dir {d} is never pre-created by mkdir")
    return out


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return _self_test()
    findings = live_findings()
    if findings:
        print("workflow_logdir_audit: %d log dir(s) the runner user cannot clean."
              % len(findings))
        print("A sudo-run step creates them root-owned, and the NEXT checkout dies")
        print("in `git clean`. Add each to the `mkdir -p` that runs before them.")
        for f in findings:
            print("  " + f)
        return 1
    n = len(list(WORKFLOW_DIR.glob("*.yml")))
    print(f"workflow_logdir_audit: OK -- {n} workflow(s), every --log-dir pre-created")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
