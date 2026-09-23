#!/usr/bin/env python3
"""Census of OPEN WORK, and the ending condition of a debt-repayment run.

The question "is there debt left?" has been answered from recall in this repo and
got a different answer each time, because the answer is a UNION of registers that
live in four different files and no single command read all four. This is that
command. It reads only files already tracked in the tree -- it runs no regex over
prose, so it cannot invent an item and cannot be silenced by rewording a comment.

The four registers it unions:

  docs/tech-debt.md                     deliberate deferrals, `## TD-NN` entries.
  tools/deferred_negatives.json         positive cases whose verdict guard is
                                        expect-flippable but has no sound negative
                                        yet (vacuity unproven).
  tools/negative_coverage_undisposed.txt  positive cases with NO disposition at all
                                        (negative_coverage_audit.py owns it).
  */inventory_overrides.json            `platform_known_fail` -- cases withheld from
                                        grading because a specific DUT is known to
                                        fail them.

An item is REPAYABLE unless something in the tree accounts for it. Accounting is
deliberately narrow, because a wide one is how open work becomes invisible:

  * a TD entry is accounted for when its Status is RESOLVED, or when it is OPEN and
    its id stands in tools/debt_accepted.txt -- the ratchet of debts argued to be
    immovable. Adding a line there is a visible, reviewable act; rewording the
    entry is not. That asymmetry is the point.
  * a platform_known_fail is accounted for when its justification resolves INSIDE
    this repository: a `platform_known_fail_ref` naming a tracked path or a TD id.
    A ref pointing outside the tree justifies nothing a reader of this repo can
    check, so it counts as repayable rather than passing silently.
  * a deferred negative and an undisposed case are never accounted for here. Both
    already carry their own reason strings, and both are backlogs their owning
    audit exists to drain.

THE RC AND THE LAST LINE ANSWER DIFFERENT QUESTIONS. Do not collapse them.

    rc         is this register WELL-FORMED -- can it be trusted at all?
    last line  is the open work EMPTY -- `north star: REACHED` / `NOT REACHED`.

A register can be malformed while showing zero open items (an entry whose Status
does not parse is counted nowhere), and it can be well-formed while showing many.
A run that ends on the last line alone can end on a register that has quietly
stopped reading one of its four sources. Both, or neither.

What this does NOT measure, stated so nobody reads more into a green line than is
there: it measures the REGISTERS, not the tree. Work that was never written down
is not open work as far as this command is concerned. Keeping the registers
complete is a discipline this cannot enforce -- it can only make the registers
countable once the discipline has been kept.

Usage:
    tools/debt_census.py              print the census and the north-star line
    tools/debt_census.py --check      also enforce well-formedness (gates
                                      pre-commit + build-test.yml); rc is the
                                      well-formedness verdict, not the count
    tools/debt_census.py --self-test  prove each invariant fires
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REGISTER = ROOT / "docs" / "tech-debt.md"
ACCEPTED = ROOT / "tools" / "debt_accepted.txt"
DEFERRED_NEGATIVES = ROOT / "tools" / "deferred_negatives.json"
UNDISPOSED = ROOT / "tools" / "negative_coverage_undisposed.txt"
OVERRIDES = [
    ROOT / "docs" / "spec" / "inventory_overrides.json",
    ROOT / "dut" / "lwip_dut" / "inventory_overrides.json",
]

ENTRY_RE = re.compile(r"^## TD-(\d+)\s+(?:---?|—)\s+(.*)$")
STATUS_RE = re.compile(r"\*\*Status:\*\*\s*([A-Z][A-Z-]*)")
ACCEPTED_RE = re.compile(r"\*\*Status:\*\*\s*OPEN\s*\(accepted")
DONE_WHEN_RE = re.compile(r"\*\*Done when:\*\*\s*(\S)")
POINTER_RE = re.compile(r"docs/tech-debt\.md TD-(\d+)")


class Entry:
    def __init__(self, num, title, body):
        self.num = num
        self.title = title
        self.body = body
        m = STATUS_RE.search(body)
        self.status = m.group(1) if m else None
        self.accepted_in_prose = bool(ACCEPTED_RE.search(body))
        self.has_done_when = bool(DONE_WHEN_RE.search(body))

    @property
    def id(self):
        return "TD-%02d" % self.num

    @property
    def is_open(self):
        return self.status == "OPEN"


def parse_register(text):
    """Split the register into entries. Returns [Entry] in file order."""
    entries = []
    cur_num = cur_title = None
    cur_body = []
    for line in text.splitlines():
        m = ENTRY_RE.match(line)
        if m:
            if cur_num is not None:
                entries.append(Entry(cur_num, cur_title, "\n".join(cur_body)))
            cur_num, cur_title, cur_body = int(m.group(1)), m.group(2), []
        elif cur_num is not None:
            cur_body.append(line)
    if cur_num is not None:
        entries.append(Entry(cur_num, cur_title, "\n".join(cur_body)))
    return entries


def parse_ratchet(text):
    """Ratchet lines are `TD-NN` optionally followed by whitespace + a note."""
    ids = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ids.append(line.split()[0])
    return ids


def tracked_files():
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files"],
                         capture_output=True, text=True, check=True).stdout
    return set(out.splitlines())


def register_pointers(files):
    """Every `docs/tech-debt.md TD-NN` pointer in a tracked text file."""
    found = {}
    for rel in sorted(files):
        p = ROOT / rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for m in POINTER_RE.finditer(text):
            found.setdefault(int(m.group(1)), []).append(rel)
    return found


def load_overrides():
    """[(case_id, source_rel, ref_or_None, reason_or_None)] for each known-fail."""
    items = []
    for path in OVERRIDES:
        if not path.is_file():
            continue
        rel = str(path.relative_to(ROOT))
        data = json.loads(path.read_text(encoding="utf-8"))
        for cid, over in sorted(data.get("overrides", {}).items()):
            if not over.get("platform_known_fail"):
                continue
            items.append((cid, rel,
                          over.get("platform_known_fail_ref"),
                          over.get("reason")))
    return items


def ref_resolves(ref, files, all_ids):
    """A justification resolves when a reader of THIS repo can follow it."""
    if not ref:
        return False
    m = POINTER_RE.search(ref) or re.fullmatch(r"TD-(\d+)", ref.strip())
    if m:
        return "TD-%02d" % int(m.group(1)) in all_ids
    return ref.split("#")[0].strip() in files


def collect(files):
    """Read all four registers. Returns (entries, ratchet, repayable, problems)."""
    problems = []

    entries = parse_register(REGISTER.read_text(encoding="utf-8"))
    all_ids = {e.id for e in entries}

    seen = {}
    for e in entries:
        if e.num in seen:
            problems.append("%s appears twice in %s" % (e.id, REGISTER.name))
        seen[e.num] = e
    if entries:
        missing = [n for n in range(1, max(seen) + 1) if n not in seen]
        if missing:
            problems.append("register is not contiguous: no entry for %s"
                            % ", ".join("TD-%02d" % n for n in missing))

    for e in entries:
        if e.status is None:
            problems.append("%s has no parseable **Status:** line" % e.id)
        elif e.status not in ("RESOLVED", "OPEN"):
            problems.append("%s status %r is neither RESOLVED nor OPEN" % (e.id, e.status))
        if e.is_open and not e.has_done_when:
            problems.append("%s is OPEN but carries no **Done when:** line -- an open "
                            "debt with no measurable closing condition cannot be closed"
                            % e.id)

    ratchet = parse_ratchet(ACCEPTED.read_text(encoding="utf-8")) if ACCEPTED.is_file() else []
    accepted_ids = set(ratchet)
    for rid in ratchet:
        e = next((x for x in entries if x.id == rid), None)
        if e is None:
            problems.append("%s stands in %s but has no register entry"
                            % (rid, ACCEPTED.name))
        elif not e.is_open:
            problems.append("%s stands in %s but its status is %s -- a settled debt "
                            "needs no acceptance" % (rid, ACCEPTED.name, e.status))
    for e in entries:
        if e.accepted_in_prose and e.id not in accepted_ids:
            problems.append("%s says OPEN (accepted) but is absent from %s"
                            % (e.id, ACCEPTED.name))

    for num, sites in sorted(register_pointers(files).items()):
        if "TD-%02d" % num not in all_ids:
            problems.append("TD-%02d is pointed at by %s but has no register entry"
                            % (num, ", ".join(sorted(set(sites)))))

    repayable = []
    for e in entries:
        if e.is_open and e.id not in accepted_ids:
            repayable.append(("tech-debt", e.id, e.title))

    if DEFERRED_NEGATIVES.is_file():
        cases = json.loads(DEFERRED_NEGATIVES.read_text(encoding="utf-8")).get("cases", {})
        for cid, reason in sorted(cases.items()):
            if not (reason or "").strip():
                problems.append("deferred negative %s carries an empty reason" % cid)
            repayable.append(("deferred-negative", cid, (reason or "").split(":")[0]))

    if UNDISPOSED.is_file():
        for line in UNDISPOSED.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                repayable.append(("undisposed", line.split()[0], "no disposition"))

    for cid, src, ref, reason in load_overrides():
        if not (ref or "").strip() and not (reason or "").strip():
            problems.append("known-fail %s in %s carries neither a ref nor a reason"
                            % (cid, src))
        if not ref_resolves(ref, files, all_ids):
            repayable.append(("known-fail", "%s (%s)" % (cid, src),
                              "justification does not resolve in-tree"))

    return entries, sorted(accepted_ids), repayable, problems


def render(entries, accepted_ids, repayable, problems):
    resolved = [e for e in entries if e.status == "RESOLVED"]
    open_entries = [e for e in entries if e.is_open]
    print("tech-debt register: %d entries -- %d resolved, %d open (%d accepted)"
          % (len(entries), len(resolved), len(open_entries), len(accepted_ids)))
    for e in open_entries:
        mark = "accepted" if e.id in accepted_ids else "REPAYABLE"
        print("  %-7s %-9s %s" % (e.id, mark, e.title[:88]))

    by_source = {}
    for source, ident, note in repayable:
        by_source.setdefault(source, []).append((ident, note))
    print()
    print("open work by register:")
    for source in ("tech-debt", "deferred-negative", "undisposed", "known-fail"):
        rows = by_source.get(source, [])
        print("  %-18s %d" % (source, len(rows)))
        for ident, note in rows:
            print("      %-44s %s" % (ident, (note or "")[:70]))

    if problems:
        print()
        print("register is MALFORMED -- %d problem(s):" % len(problems), file=sys.stderr)
        for p in problems:
            print("  %s" % p, file=sys.stderr)

    print()
    if repayable:
        print("north star: NOT REACHED -- %d repayable item(s)" % len(repayable))
    else:
        print("north star: REACHED")


def _self_test():
    """Prove each invariant fires. Operates on parsed structures, not the tree."""
    cases = []

    e_ok = parse_register("## TD-01 -- t\n\n**Status:** RESOLVED (2026-01-01).\n")
    cases.append(("a resolved entry parses", e_ok[0].status == "RESOLVED"))
    cases.append(("a resolved entry is not open", not e_ok[0].is_open))

    e_open = parse_register(
        "## TD-01 -- t\n\n**Status:** OPEN (accepted).\n\n**Done when:** x.\n")
    cases.append(("an accepted entry is open", e_open[0].is_open))
    cases.append(("an accepted entry is seen as accepted", e_open[0].accepted_in_prose))
    cases.append(("a done-when line is seen", e_open[0].has_done_when))

    e_plain = parse_register("## TD-01 -- t\n\n**Status:** OPEN.\n")
    cases.append(("a plain OPEN entry is not accepted", not e_plain[0].accepted_in_prose))
    cases.append(("a missing done-when is seen", not e_plain[0].has_done_when))
    cases.append(("an empty done-when does not count",
                  not parse_register("## TD-01 -- t\n\n**Status:** OPEN.\n\n"
                                     "**Done when:**\n")[0].has_done_when))

    e_bad = parse_register("## TD-01 -- t\n\nno status here\n")
    cases.append(("a statusless entry is caught", e_bad[0].status is None))

    two = parse_register(
        "## TD-01 -- a\n\n**Status:** OPEN.\n\n## TD-02 -- b\n\n**Status:** OPEN.\n")
    cases.append(("entries split on the heading", len(two) == 2))
    cases.append(("the second entry keeps its own status",
                  two[1].num == 2 and two[1].status == "OPEN"))
    cases.append(("an em-dash heading parses",
                  len(parse_register("## TD-07 — t\n\n**Status:** OPEN.\n")) == 1))
    cases.append(("a non-entry heading is ignored",
                  parse_register("## Notes\n\n**Status:** OPEN.\n") == []))

    cases.append(("a ratchet comment is ignored",
                  parse_ratchet("# note\n\nTD-16 why\nTD-17\n") == ["TD-16", "TD-17"]))

    files = {"docs/x.md"}
    ids = {"TD-16"}
    cases.append(("an in-tree path resolves", ref_resolves("docs/x.md", files, ids)))
    cases.append(("an out-of-tree path does not",
                  not ref_resolves("memory/x.md", files, ids)))
    cases.append(("a TD id resolves", ref_resolves("TD-16", files, ids)))
    cases.append(("a dangling TD id does not", not ref_resolves("TD-99", files, ids)))
    cases.append(("an empty ref does not", not ref_resolves(None, files, ids)))
    cases.append(("a path with an anchor resolves",
                  ref_resolves("docs/x.md#section", files, ids)))

    cases.append(("a pointer is found in prose",
                  POINTER_RE.search("see docs/tech-debt.md TD-18 for why") is not None))

    failures = [label for label, ok in cases if not ok]
    for label in failures:
        print("self-test FAIL: %s" % label, file=sys.stderr)
    if failures:
        return 1
    print("debt_census self-test: all %d checks passed" % len(cases))
    return 0


def main(argv):
    if argv and argv[0] == "--self-test":
        return _self_test()
    check = bool(argv) and argv[0] == "--check"
    if argv and not check:
        sys.exit("usage: debt_census.py [--check | --self-test]")
    entries, accepted_ids, repayable, problems = collect(tracked_files())
    render(entries, accepted_ids, repayable, problems)
    return 1 if (check and problems) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
