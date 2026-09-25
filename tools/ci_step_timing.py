#!/usr/bin/env python3
"""Render a CI job's step timings as a Markdown table for the run summary.

WHY THIS EXISTS. A GitHub job that hits `timeout-minutes` reports only that it
did. The job goes orange, every step after the one holding the clock reads
"skipped", and the run page says nothing about where the time went. On
2026-09-24 two consecutive pushes died that way, and the register recorded a
cause -- "the lane outgrew its cap" -- that the step timings refute: the test
lanes cost about 28 minutes, and two compile-shaped steps had taken 110 of the
121. Nobody had looked, because looking meant reconstructing the timings from
the Actions API by hand (docs/tech-debt.md TD-43).

WHAT IT READS. The `/actions/runs/<id>/jobs` payload, saved to a file by the
caller so the token never reaches this process. Per step it prints the duration
and the conclusion, longest first, plus the share of job wall-clock each took.

⚠ A step that is STILL RUNNING has no `completed_at`. That is not missing data
to skip over -- on a cancelled run it names the step that was holding the clock
when the cap fired, which is the single most useful row in the table. It is
reported as `(running)` and placed first.

⚠ The durations are WALL-CLOCK on a shared runner, so a step that grew since
last week has not necessarily grown in work. That is the whole point of
printing them: the comparison between runs is what separates the two, and it
cannot be made from a number nobody records.
"""

from __future__ import annotations

import datetime
import json
import sys


def _parse(ts: str | None) -> datetime.datetime | None:
    if not ts:
        return None
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _hms(seconds: float) -> str:
    total = int(seconds)
    if total >= 3600:
        return f"{total // 3600}h{(total % 3600) // 60:02d}m"
    return f"{total // 60}m{total % 60:02d}s"


def render(payload: dict) -> str:
    out: list[str] = []
    for job in payload.get("jobs", []):
        job_start = _parse(job.get("started_at"))
        job_end = _parse(job.get("completed_at")) or datetime.datetime.now(
            datetime.timezone.utc
        )
        job_secs = (job_end - job_start).total_seconds() if job_start else 0.0

        out.append(f"### Step timings — {job.get('name', '?')}")
        out.append("")
        out.append(f"Job wall-clock: **{_hms(job_secs)}** "
                   f"(conclusion: `{job.get('conclusion') or 'running'}`)")
        out.append("")
        out.append("| step | duration | share | conclusion |")
        out.append("|---|---:|---:|---|")

        running: list[tuple[str, str]] = []
        finished: list[tuple[float, str, str]] = []
        for step in job.get("steps", []):
            name = str(step.get("name", "?"))
            concl = str(step.get("conclusion") or "running")
            start, end = _parse(step.get("started_at")), _parse(step.get("completed_at"))
            if start and not end:
                # Holding the clock when the job ended. Never dropped.
                running.append((name, concl))
            elif start and end:
                finished.append(((end - start).total_seconds(), name, concl))

        for name, concl in running:
            out.append(f"| {name} | **(running)** | — | `{concl}` |")
        for secs, name, concl in sorted(finished, reverse=True):
            share = f"{100.0 * secs / job_secs:.0f}%" if job_secs > 0 else "—"
            out.append(f"| {name} | {_hms(secs)} | {share} | `{concl}` |")
        out.append("")
    return "\n".join(out)


def _self_test() -> int:
    payload = {
        "jobs": [{
            "name": "demo",
            "started_at": "2026-09-24T00:00:00Z",
            "completed_at": "2026-09-24T02:01:00Z",
            "conclusion": "cancelled",
            "steps": [
                {"name": "build", "conclusion": "success",
                 "started_at": "2026-09-24T00:00:00Z",
                 "completed_at": "2026-09-24T00:59:03Z"},
                {"name": "ratchet", "conclusion": "success",
                 "started_at": "2026-09-24T00:59:03Z",
                 "completed_at": "2026-09-24T01:50:45Z"},
                {"name": "positive", "conclusion": None,
                 "started_at": "2026-09-24T01:50:45Z", "completed_at": None},
                {"name": "never-started", "conclusion": "skipped",
                 "started_at": None, "completed_at": None},
            ],
        }]
    }
    text = render(payload)
    checks = [
        # The running step is named rather than dropped, and comes first.
        ("running row present", "| positive | **(running)** |" in text),
        ("running row first", text.index("| positive |") < text.index("| ratchet |")),
        # Finished steps are ordered longest first.
        ("longest first", text.index("| build |") < text.index("| ratchet |")),
        ("build duration", "| 59m03s |" in text),
        ("ratchet duration", "| 51m42s |" in text),
        # A step that never started carries no timing and no row.
        ("never-started omitted", "never-started" not in text),
        ("job wall-clock", "**2h01m**" in text),
        ("share computed", "49%" in text),
    ]
    bad = [name for name, ok in checks if not ok]
    if bad:
        print("ci_step_timing self-test FAILED: " + ", ".join(bad), file=sys.stderr)
        print(text, file=sys.stderr)
        return 1
    print(f"ci_step_timing self-test: all {len(checks)} checks passed")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return _self_test()
    if len(argv) != 2:
        print("usage: ci_step_timing.py <jobs.json> | --self-test", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        payload = json.load(fh)
    print(render(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
