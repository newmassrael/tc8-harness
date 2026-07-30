#!/usr/bin/env python3
"""Validate a commit message file against COMMIT_FORMAT.md.

Invoked by ``.githooks/commit-msg`` (which itself only runs when
``git config core.hooksPath .githooks`` has been applied to the clone).

Rules — distilled from COMMIT_FORMAT.md, in priority order:

  1. Subject line ``<type>(<scope>): <subject>`` — scope optional.
     - type ∈ {feat, refactor, fix, docs, test, chore, build, perf}
     - subject ≤ 72 chars, no trailing period
  2. If a body is present (pinion-style concise bullets):
     - exactly one blank line separating it from the subject
     - every body line is a single ``- `` bullet — NO blank line
       between bullets (contiguous), NO indented continuation / wrap
       line, NO prose lead paragraph
     - each bullet line ≤ 72 BYTES total (including the ``- `` prefix)
     - 1-3 bullets (a 4th is rejected, not just warned)
  3. Forbidden anywhere:
     - ``Generated with Claude Code`` footer
     - ``Co-Authored-By:`` tag
     - emoji code points (broad heuristic)
  4. A round label in the SUBJECT — ``(R807)`` / ``(Round 807)`` — must
     name a round this workspace's atomic store has a changelog entry
     for. Mnemosyne's commit-ledger drift gate reads commit subjects and
     rejects a cited round with no entry, and it can only see the subject
     once the commit object exists — so pre-commit passes and the push
     then fails. Checking it here is the only place it is catchable
     before the fact. Cite an upstream project's round in the body.

Exits 0 on a clean message, non-zero on any rule violation. The hook is
intended to keep messages consistent across this repo's history without
requiring contributors to re-read COMMIT_FORMAT.md every time.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ATOMIC_STORE = REPO_ROOT / "docs" / ".atomic" / "workspace.atomic.json"

ALLOWED_TYPES = {"feat", "refactor", "fix", "docs", "test", "chore", "build", "perf"}

# Deliberately byte-identical in meaning to the upstream gate's own pattern
# (`\((?:R|Round )(\d+)\)`): the two must agree on what counts as a citation,
# or this hook either blocks a subject the gate would accept or waves through
# one it will reject. Unparenthesized text — "RFC 826", "R24-11" — is not a
# citation to either of them.
ROUND_LABEL_RE = re.compile(r"\((?:R|Round )(\d+)\)")
LEDGER_ROUND_RE = re.compile(r"^Round (\d+)\b")

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


def _ledger_rounds() -> set[int] | None:
    """Round numbers the atomic store has a changelog entry for.

    ``None`` means the store could not be read, and the round-label rule is
    then skipped rather than guessed at: an unreadable store is the Mnemosyne
    gate's business (it validates store integrity directly), and blocking
    every commit in this repo over it would be the wrong failure.
    """
    try:
        entries = json.loads(ATOMIC_STORE.read_text(encoding="utf-8"))["changelog_entries"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(entries, dict):
        return None
    rounds = set()
    for key in entries:
        m = LEDGER_ROUND_RE.match(key)
        if m:
            rounds.add(int(m.group(1)))
    return rounds


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

    cited = {int(n) for n in ROUND_LABEL_RE.findall(subject)}
    if cited:
        ledger = _ledger_rounds()
        unbacked = sorted(cited - ledger) if ledger is not None else []
        for n in unbacked:
            issues.append(
                f"subject의 라운드 라벨 (R{n}) — atomic store 에 'Round {n}' "
                "changelog 항목이 없음\n"
                "  mnemosyne commit↔ledger drift 게이트는 commit SUBJECT 를 "
                "스캔하므로, 커밋이 만들어진 뒤에야 실패한다\n"
                "  (pre-commit 은 커밋 전에 돌아 이를 볼 수 없고, push 에서 막힌다)\n"
                "  upstream 프로젝트의 라운드 인용이면 body 로 내릴 것; 이 "
                "워크스페이스의 라운드면 append-changelog-entry 로 항목을 먼저 만들 것"
            )

    if len(lines) >= 2:
        if lines[1].strip() != "":
            issues.append("subject와 body 사이에 빈 줄 1개 필요")
        body = lines[2:]  # trailing blank lines already stripped above
        bullet_count = 0
        for ln_no, ln in enumerate(body, start=3):
            if ln.strip() == "":
                issues.append(
                    f"body line {ln_no}: 불릿 사이 빈 줄 금지 (불릿은 연속)"
                )
                continue
            if not ln.startswith("- "):
                issues.append(
                    f"body line {ln_no}: 불릿만 허용 — '- '로 시작하는 단일 줄 "
                    f"(들여쓰기 연속/wrap 줄·산문 금지)\n  '{ln[:60]}'"
                )
                continue
            bullet_count += 1
            nbytes = len(ln.encode("utf-8"))
            if nbytes > 72:
                issues.append(
                    f"body line {ln_no}: 불릿 1줄 ≤72 bytes 초과 ({nbytes} bytes) "
                    f"— 더 짧게 쓰거나 별도 불릿으로 분리\n  '{ln[:60]}'"
                )
        if bullet_count == 0:
            issues.append("body가 있으면 불릿(- ) 1개 이상 필요")
        if bullet_count > 3:
            issues.append(
                f"body 불릿 {bullet_count}개 — 최대 3개 (핵심 변경에 응축)"
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
