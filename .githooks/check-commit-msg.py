#!/usr/bin/env python3
"""Validate a commit message file against COMMIT_FORMAT.md.

Invoked by ``.githooks/commit-msg`` (which itself only runs when
``git config core.hooksPath .githooks`` has been applied to the clone).

Rules — distilled from COMMIT_FORMAT.md, in priority order:

  1. Subject line ``<type>(<scope>): <subject>`` — scope optional.
     - type ∈ {feat, refactor, fix, docs, test, chore, build, perf}
     - subject ≤ 72 chars, no trailing period
  2. If a body is present:
     - exactly one blank line separating it from the subject
     - top-level lines must start with ``- `` (bullets)
     - non-bullet continuation lines must start with whitespace
     - 1-3 top-level bullets recommended (warn at >3)
  3. Forbidden anywhere:
     - ``Generated with Claude Code`` footer
     - ``Co-Authored-By:`` tag
     - emoji code points (broad heuristic)

Exits 0 on a clean message, non-zero on any rule violation. The hook is
intended to keep messages consistent across this repo's history without
requiring contributors to re-read COMMIT_FORMAT.md every time.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ALLOWED_TYPES = {"feat", "refactor", "fix", "docs", "test", "chore", "build", "perf"}

SUBJECT_RE = re.compile(
    r"^(?P<type>\w+)(?:\((?P<scope>[\w./-]+)\))?:\s+(?P<subject>\S.*?)\s*$"
)

FORBIDDEN_PATTERNS = [
    (re.compile(r"Generated with Claude Code", re.IGNORECASE),
     "'Generated with Claude Code' footer 금지"),
    (re.compile(r"Co-Authored-By:", re.IGNORECASE),
     "'Co-Authored-By' 태그 금지"),
]

EMOJI_RANGES = [
    (0x1F300, 0x1FAFF),
    (0x2600, 0x27BF),
    (0x1F1E6, 0x1F1FF),
]


def _is_emoji(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in EMOJI_RANGES)


def validate(raw: str) -> list[str]:
    issues: list[str] = []
    lines = [ln for ln in raw.splitlines() if not ln.lstrip().startswith("#")]
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return ["empty commit message"]

    subject = lines[0]
    if len(subject) > 72:
        issues.append(f"subject 72자 초과 ({len(subject)}자)")
    if subject.endswith("."):
        issues.append("subject 끝의 마침표 금지")

    m = SUBJECT_RE.match(subject)
    if not m:
        issues.append(
            "subject 형식 오류 — 'type(scope): 설명' 또는 'type: 설명' 이어야 함\n"
            f"  현재: {subject}"
        )
    elif m.group("type") not in ALLOWED_TYPES:
        allowed = ", ".join(sorted(ALLOWED_TYPES))
        issues.append(f"허용되지 않은 type: {m.group('type')} (허용: {allowed})")

    if len(lines) >= 2:
        if lines[1].strip() != "":
            issues.append("subject와 body 사이에 빈 줄 1개 필요")
        body = lines[2:]
        bullet_count = 0
        for ln_no, ln in enumerate(body, start=3):
            if not ln.strip():
                continue
            if ln.startswith((" ", "\t")):
                continue
            if not ln.lstrip().startswith("- "):
                issues.append(
                    f"body line {ln_no}: 불릿(- prefix)만 허용\n  '{ln[:60]}'"
                )
            else:
                bullet_count += 1
        if bullet_count > 3:
            issues.append(
                f"body 불릿 {bullet_count}개 — 1-3개 권장 (핵심 변경에 응축)"
            )

    text = "\n".join(lines)
    for pat, why in FORBIDDEN_PATTERNS:
        if pat.search(text):
            issues.append(f"금지 패턴: {why}")

    emojis = sorted({ch for ln in lines for ch in ln if _is_emoji(ch)})
    if emojis:
        issues.append(f"이모지 금지 — 발견: {' '.join(emojis)}")

    return issues


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        return 0
    msg_file = Path(argv[1])
    raw = msg_file.read_text(encoding="utf-8")
    issues = validate(raw)
    if not issues:
        return 0
    bar = "-" * 60
    print(bar, file=sys.stderr)
    print("Commit message 형식 위반 (COMMIT_FORMAT.md 참고):", file=sys.stderr)
    for issue in issues:
        print(f"  - {issue}", file=sys.stderr)
    print(bar, file=sys.stderr)
    print("commit aborted. message saved to .git/COMMIT_EDITMSG; fix and re-try.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
