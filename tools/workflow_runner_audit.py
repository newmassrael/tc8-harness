#!/usr/bin/env python3
"""Trigger gate for workflows that can land on this repo's self-hosted runner.

INVARIANT: a workflow job that is not provably running on a GitHub-hosted
runner may only be triggered by events that require repository WRITE access to
raise (`push`, `workflow_dispatch`, `schedule`). The self-hosted `[netns]` host
runs the smoke suite as root with CAP_NET_ADMIN; an event an outsider can raise
(`pull_request` from a fork, `issue_comment`, `pull_request_target`, or a
`workflow_run` chained off one of those) would let a workflow patch submitted
from outside execute on that host.

That constraint was already the intent -- smoke-test.yml and lwip-sweep.yml
each carry a comment saying so -- but a comment stops nothing. This is the
enforcement: adding `pull_request:` to a self-hosted workflow now fails the
commit instead of quietly widening the runner's exposure.

Polarity is fail-CLOSED, and that is the design, not an accident:

  * A runner is treated as self-hosted unless its label set is a single, known
    GitHub-hosted image label (`ubuntu-22.04`, `macos-latest`, ...). A runner
    registered with only a custom label answers `runs-on: netns` with no
    `self-hosted` label present, so a `self-hosted`-literal scan would miss it.
  * A `runs-on:` the gate cannot resolve statically (`${{ inputs.runner }}`, a
    matrix built by `fromJSON`, a runner `group:`) is treated as self-hosted.
    Pin the label, or spell the matrix values out literally.
  * A job calling a REMOTE reusable workflow is treated as self-hosted: a called
    workflow runs in this repo's context, so its `runs-on` can select this
    runner and the gate cannot read it. Local (`./.github/workflows/x.yml`)
    calls are read instead, and the caller's events propagate to the callee.
  * A new GitHub-hosted image family absent from HOSTED_LABEL_RE fails this gate
    rather than passing it. Add the family here when GitHub ships one.

Scope (honest): this is a MAINTAINER-SIDE RATCHET against drift, not a defence
against a live attacker's first pull request. If a fork PR both adds the bad
trigger and is allowed to run, the self-hosted job runs in the same event that
turns this gate red -- and a red gate does not un-run code. The control for
that case is the repository's Actions setting "Require approval for all
external collaborators". This gate is what stops the maintainer, a
`--no-verify`, or a GitHub web-editor commit from dropping the constraint by
accident.

Usage:
    tools/workflow_runner_audit.py [--check]    scan .github/workflows/
    tools/workflow_runner_audit.py --self-test  prove the gate fires
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # environment gap, not a policy failure -- say which
    sys.exit("workflow_runner_audit: PyYAML is required "
             "(sudo apt-get install -y python3-yaml)")

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github/workflows"

# Events only an actor holding repository WRITE access can raise, so a workflow
# reacting to one of them cannot be steered from outside. Deliberately minimal:
# extend it only with an event whose raising is likewise gated on write access,
# and record why in a comment here.
#   push              - requires push access to a branch of THIS repo
#   workflow_dispatch - requires write access
#   schedule          - raised by GitHub itself, default branch only
MAINTAINER_ONLY_EVENTS = frozenset({"push", "workflow_dispatch", "schedule"})

# Label families GitHub itself provides. Anything else is somebody's machine.
HOSTED_LABEL_RE = re.compile(
    r"""^(
          ubuntu-(latest|\d{2}\.\d{2})(-arm)?
        | windows-(latest|\d{4}|11-arm)
        | macos-(latest|\d{1,2})(-xlarge|-large|-arm64)?
    )$""",
    re.VERBOSE,
)

_EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}", re.DOTALL)
_MATRIX_REF_RE = re.compile(r"^matrix\.([A-Za-z_][A-Za-z0-9_-]*)$")
_LOCAL_USES_PREFIX = "./.github/workflows/"

# Stands in for a runner selection the gate could not resolve. Never hosted.
UNRESOLVED = "<unresolved>"


def _as_list(value: Any) -> list[Any]:
    """Normalise YAML's scalar-or-sequence shorthand to a list."""
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _matrix_values(job: dict, key: str) -> list[str] | None:
    """Every literal value `matrix.<key>` can take, or None if not static."""
    matrix = (job.get("strategy") or {}).get("matrix")
    if not isinstance(matrix, dict):
        return None  # absent, or `matrix: ${{ fromJSON(...) }}`
    values: list[str] = []
    axis = matrix.get(key)
    if axis is not None:
        if not isinstance(axis, list) or not all(isinstance(v, str) for v in axis):
            return None
        values.extend(axis)
    for entry in _as_list(matrix.get("include")):
        if not isinstance(entry, dict):
            return None
        extra = entry.get(key)
        if extra is not None:
            if not isinstance(extra, str):
                return None
            values.append(extra)
    return values or None


def _expand(value: Any, job: dict) -> list[str] | None:
    """Resolve one `runs-on` element to its literal label(s), or None."""
    if not isinstance(value, str):
        return None
    if "${{" not in value:
        return [value]
    match = _EXPR_RE.fullmatch(value.strip())
    if not match:
        return None  # an expression spliced into a larger string
    ref = _MATRIX_REF_RE.match(match.group(1))
    if not ref:
        return None  # inputs.*, vars.*, env.*, a function call, ...
    return _matrix_values(job, ref.group(1))


def _label_sets(job: dict) -> list[list[str]]:
    """The label set(s) a job can run on. UNRESOLVED marks an opaque runner."""
    if "uses" in job:
        uses = job.get("uses")
        # A local reusable workflow is scanned in its own right; a remote one
        # runs in this repo's context with a `runs-on` the gate cannot read.
        if isinstance(uses, str) and uses.startswith(_LOCAL_USES_PREFIX):
            return []
        return [[UNRESOLVED]]

    runs_on = job.get("runs-on")
    if isinstance(runs_on, dict):
        # `group:` selects a runner group -- self-hosted, or a hosted runner
        # whose image the gate still cannot read. Either way, unproven.
        if "group" in runs_on:
            return [[UNRESOLVED]]
        runs_on = runs_on.get("labels")
    if runs_on is None:
        return [[UNRESOLVED]]

    resolved = [_expand(element, job) for element in _as_list(runs_on)]
    if not resolved or any(labels is None for labels in resolved):
        return [[UNRESOLVED]]
    # A single element may fan out over a matrix axis: the job can run on ANY
    # of those runners, so each candidate is its own label set. Several elements
    # are a label CONJUNCTION (self-hosted matching) and stay one set; a matrix
    # fan-out inside such a conjunction is not resolved further.
    if len(resolved) == 1:
        return [[label] for label in resolved[0]]
    if all(len(labels) == 1 for labels in resolved):
        return [[labels[0] for labels in resolved]]
    return [[UNRESOLVED]]


def _is_hosted(labels: list[str]) -> bool:
    """A GitHub-hosted runner is selected by exactly one known image label."""
    return len(labels) == 1 and HOSTED_LABEL_RE.match(labels[0]) is not None


def _unproven_jobs(workflow: dict) -> dict[str, str]:
    """job id -> the label set that is not provably GitHub-hosted."""
    out: dict[str, str] = {}
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return out
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for labels in _label_sets(job):
            if not _is_hosted(labels):
                out[str(job_id)] = ", ".join(labels)
                break
    return out


def _declared_events(workflow: dict) -> set[str]:
    # YAML 1.1 reads a bare `on:` key as the boolean True (PyYAML does this),
    # so the quoted and unquoted spellings both have to be accepted.
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, (list, dict)):
        return {str(event) for event in on}
    return set()


def _local_callees(workflow: dict) -> set[str]:
    """Basenames of the in-repo reusable workflows this workflow calls."""
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return set()
    out: set[str] = set()
    for job in jobs.values():
        uses = job.get("uses") if isinstance(job, dict) else None
        if isinstance(uses, str) and uses.startswith(_LOCAL_USES_PREFIX):
            out.add(uses[len(_LOCAL_USES_PREFIX):].split("@", 1)[0])
    return out


def _effective_events(
    name: str,
    workflows: dict[str, dict],
    callers: dict[str, set[str]],
    seen: frozenset[str] = frozenset(),
) -> set[str]:
    """Declared events, plus those of every caller of a reusable workflow.

    `workflow_call` is not itself a trigger: the callee runs under the CALLER's
    event, so a reusable workflow inherits every way its callers can be raised.
    `seen` breaks a call cycle rather than recursing on it.
    """
    events = _declared_events(workflows[name])
    if "workflow_call" not in events or name in seen:
        return events - {"workflow_call"}
    inherited: set[str] = set()
    for caller in callers.get(name, set()):
        if caller in workflows:
            inherited |= _effective_events(
                caller, workflows, callers, seen | {name})
    return (events - {"workflow_call"}) | inherited


def analyze(workflows: dict[str, dict]) -> list[str]:
    """One message per violation. Pure -- the self-test drives it directly."""
    callers: dict[str, set[str]] = {}
    for name, workflow in workflows.items():
        for callee in _local_callees(workflow):
            callers.setdefault(callee, set()).add(name)

    violations: list[str] = []
    for name in sorted(workflows):
        unproven = _unproven_jobs(workflows[name])
        if not unproven:
            continue
        outside = sorted(
            _effective_events(name, workflows, callers) - MAINTAINER_ONLY_EVENTS)
        if not outside:
            continue
        jobs = ", ".join(f"{job} (runs-on: {labels})"
                         for job, labels in sorted(unproven.items()))
        via = (" inherited from its caller(s)"
               if "workflow_call" in _declared_events(workflows[name]) else "")
        violations.append(
            f"{name}: job(s) not provably GitHub-hosted -- {jobs} -- reachable "
            f"from non-maintainer trigger(s){via}: {', '.join(outside)}")
    return violations


def _load() -> dict[str, dict]:
    workflows: dict[str, dict] = {}
    for path in sorted(WORKFLOW_DIR.glob("*.y*ml")):
        try:
            parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            sys.exit(f"workflow_runner_audit: {path.name} is not valid YAML: {exc}")
        if not isinstance(parsed, dict):
            sys.exit(f"workflow_runner_audit: {path.name} is not a workflow mapping")
        workflows[path.name] = parsed
    return workflows


def _scan() -> int:
    workflows = _load()
    if not workflows:
        sys.exit(f"workflow_runner_audit: found 0 workflows under {WORKFLOW_DIR} "
                 "-- bad scan")
    violations = analyze(workflows)
    if violations:
        print("workflow_runner_audit: a runner that is not provably GitHub-hosted "
              "is reachable from a trigger an outsider can raise. Allowed there: "
              f"{', '.join(sorted(MAINTAINER_ONLY_EVENTS))}.")
        for violation in violations:
            print(f"  {violation}")
        return 1
    unproven = sum(1 for workflow in workflows.values() if _unproven_jobs(workflow))
    print(f"workflow_runner_audit: OK -- {len(workflows)} workflow(s), {unproven} "
          "not provably GitHub-hosted, all restricted to maintainer-only triggers")
    return 0


def _self_test() -> int:
    """Prove the gate FIRES, not merely that it is green on today's tree."""
    hosted = {"runs-on": "ubuntu-22.04"}
    netns = {"runs-on": ["self-hosted", "netns"]}
    local_call = {"uses": _LOCAL_USES_PREFIX + "lib.yml"}
    cases: list[tuple[str, dict[str, dict], bool]] = [
        ("self-hosted + push/dispatch passes",
         {"a.yml": {"on": {"push": None, "workflow_dispatch": None},
                    "jobs": {"s": netns}}}, False),
        ("self-hosted + schedule passes",
         {"a.yml": {"on": {"schedule": [{"cron": "0 0 * * 0"}]},
                    "jobs": {"s": netns}}}, False),
        ("self-hosted + pull_request fails",
         {"a.yml": {"on": {"push": None, "pull_request": None},
                    "jobs": {"s": netns}}}, True),
        ("self-hosted + pull_request_target fails",
         {"a.yml": {"on": {"pull_request_target": None}, "jobs": {"s": netns}}},
         True),
        ("self-hosted + issue_comment fails",
         {"a.yml": {"on": {"issue_comment": None}, "jobs": {"s": netns}}}, True),
        ("self-hosted + workflow_run fails",
         {"a.yml": {"on": {"workflow_run": None}, "jobs": {"s": netns}}}, True),
        ("self-hosted + repository_dispatch fails",
         {"a.yml": {"on": {"repository_dispatch": None}, "jobs": {"s": netns}}},
         True),
        ("a hosted job beside a self-hosted one does not mask it",
         {"a.yml": {"on": {"pull_request": None},
                    "jobs": {"h": hosted, "s": netns}}}, True),
        ("hosted + pull_request passes",
         {"a.yml": {"on": {"pull_request": None}, "jobs": {"h": hosted}}}, False),
        ("bare `on:` parsed as the YAML boolean True is still read",
         {"a.yml": {True: {"pull_request": None}, "jobs": {"s": netns}}}, True),
        ("`on:` sequence shorthand is read",
         {"a.yml": {"on": ["push", "pull_request"], "jobs": {"s": netns}}}, True),
        ("`on:` scalar shorthand is read",
         {"a.yml": {"on": "pull_request", "jobs": {"s": netns}}}, True),
        ("a custom label WITHOUT the self-hosted label is caught",
         {"a.yml": {"on": {"pull_request": None},
                    "jobs": {"s": {"runs-on": "netns"}}}}, True),
        ("an unknown hosted-looking label is caught (fail closed)",
         {"a.yml": {"on": {"pull_request": None},
                    "jobs": {"s": {"runs-on": "ubuntu-22.04-gpu"}}}}, True),
        ("a single-element hosted list passes",
         {"a.yml": {"on": {"pull_request": None},
                    "jobs": {"h": {"runs-on": ["ubuntu-22.04"]}}}}, False),
        ("a runner group is not provably hosted",
         {"a.yml": {"on": {"pull_request": None}, "jobs": {"s": {
             "runs-on": {"group": "big", "labels": ["ubuntu-22.04"]}}}}}, True),
        ("a missing runs-on is not provably hosted",
         {"a.yml": {"on": {"pull_request": None}, "jobs": {"s": {"steps": []}}}},
         True),
        ("a matrix resolving only to hosted labels passes",
         {"a.yml": {"on": {"pull_request": None}, "jobs": {"h": {
             "runs-on": "${{ matrix.os }}",
             "strategy": {"matrix": {"os": ["ubuntu-22.04", "macos-latest"]}}}}}},
         False),
        ("a matrix with one self-hosted value fails",
         {"a.yml": {"on": {"pull_request": None}, "jobs": {"m": {
             "runs-on": "${{ matrix.os }}",
             "strategy": {"matrix": {"os": ["ubuntu-22.04", "netns"]}}}}}}, True),
        ("a matrix include adding a self-hosted value fails",
         {"a.yml": {"on": {"pull_request": None}, "jobs": {"m": {
             "runs-on": "${{ matrix.os }}",
             "strategy": {"matrix": {"os": ["ubuntu-22.04"],
                                     "include": [{"os": "netns"}]}}}}}}, True),
        ("an unresolvable expression is not provably hosted",
         {"a.yml": {"on": {"pull_request": None},
                    "jobs": {"s": {"runs-on": "${{ inputs.runner }}"}}}}, True),
        ("an expression spliced into a larger string is not provably hosted",
         {"a.yml": {"on": {"pull_request": None},
                    "jobs": {"s": {"runs-on": "ubuntu-${{ matrix.v }}"}}}}, True),
        ("a fromJSON matrix is not provably hosted",
         {"a.yml": {"on": {"pull_request": None}, "jobs": {"m": {
             "runs-on": "${{ matrix.os }}",
             "strategy": {"matrix": "${{ fromJSON(inputs.m) }}"}}}}}, True),
        ("a remote reusable workflow is not provably hosted",
         {"a.yml": {"on": {"pull_request": None},
                    "jobs": {"r": {"uses": "o/r/.github/workflows/w.yml@v1"}}}},
         True),
        ("a local reusable call inherits a bad caller trigger",
         {"caller.yml": {"on": {"pull_request": None}, "jobs": {"c": local_call}},
          "lib.yml": {"on": {"workflow_call": None}, "jobs": {"s": netns}}}, True),
        ("a local reusable call with only maintainer triggers passes",
         {"caller.yml": {"on": {"push": None}, "jobs": {"c": local_call}},
          "lib.yml": {"on": {"workflow_call": None}, "jobs": {"s": netns}}}, False),
        ("an uncalled reusable self-hosted workflow passes",
         {"lib.yml": {"on": {"workflow_call": None}, "jobs": {"s": netns}}}, False),
        ("a reusable call cycle terminates",
         {"lib.yml": {"on": {"workflow_call": None},
                      "jobs": {"c": local_call, "s": netns}}}, False),
    ]
    failures = 0
    for label, workflows, expect_violation in cases:
        if bool(analyze(workflows)) != expect_violation:
            verb = "did not fire" if expect_violation else "false-fired"
            print(f"self-test FAIL: {label} -- gate {verb}", file=sys.stderr)
            failures += 1
    if failures:
        return 1
    print(f"workflow_runner_audit self-test: all {len(cases)} checks passed")
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--self-test":
        return _self_test()
    if argv and argv[0] != "--check":
        sys.exit("usage: workflow_runner_audit.py [--check | --self-test]")
    return _scan()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
