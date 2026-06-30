#!/usr/bin/env python3
"""Auto-generate per-packet ``messages[]`` annotations from the harness trace.

Reads ``site/src/data/cases/<CASE>.json`` for the inlined SCXML (state /
transition shape) and ``site/src/data/pcap/<CASE>.json`` for the per-case
packet list plus the harness transition trace, and emits a labelled JSON
file at ``site/src/data/auto_messages/<CASE>.json``. The site's
``localizedMessages`` helper merges these auto labels with hand-written
locale overrides at idx granularity (manual wins).

Usage:
    site/scripts/generate_messages.py                # all cases with pcap
    site/scripts/generate_messages.py --only ARP_03  # one case

Design notes:
- Single evidence base. Labels come straight from the harness-recorded
  transition trace (the ``captured_trace`` block that ``tc8-harness
  decode-pcap`` merges into each pcap JSON): every step names the frame it
  fired on (``pcap_frame_idx``) and the from/to states, so the timeline is
  rendered from harness ground truth, not a re-simulation of the SCXML over
  re-decoded packet fields. See ``_label_via_trace``. The SCXML is parsed
  only to recover the cond source text and pass/fail verdict of each
  transition for the label cosmetics.
- No second wire decoder and no cond evaluation. The harness owns the only
  wire decoder; this generator never re-decodes packets or re-evaluates
  guard expressions (the dual-evidence cond-walker was retired with
  TD-05 — see docs/tech-debt.md).
- Output is locale-neutral English. Localised override files keep
  responsibility for translation; this generator never writes Korean.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CASES_DIR = REPO_ROOT / "site" / "src" / "data" / "cases"
DEFAULT_PCAP_DIR = REPO_ROOT / "site" / "src" / "data" / "pcap"
DEFAULT_OUT_DIR = REPO_ROOT / "site" / "src" / "data" / "auto_messages"

# Runtime-overridable paths; the pcap-refresh workflow points these at
# the orphan pcap-data branch checkout so generator output sits next to
# decoded pcap JSON in the same commit.
CASES_DIR = DEFAULT_CASES_DIR
PCAP_DIR = DEFAULT_PCAP_DIR
OUT_DIR = DEFAULT_OUT_DIR

GENERATOR_VERSION = "2"


SCXML_NS = "http://www.w3.org/2005/07/scxml"


@dataclass
class TransitionDef:
    event: str
    cond_src: str           # original cond source (for label cosmetics)
    target: str             # target state id


@dataclass
class StateDef:
    id: str
    is_final: bool
    final_kind: str         # "pass" / "fail" / "" (non-final)
    transitions: list[TransitionDef] = field(default_factory=list)


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


SCE_USE_TAG = "use"
TESTS_DIR = REPO_ROOT / "tests"

# ``{$name}`` placeholders the SCE codegen substitutes when expanding a
# template. The consumer's ``<sce:use ... name="value" .../>`` attribute
# block provides the values — we mirror the substitution before parsing
# so cond strings tokenise cleanly.
_TEMPLATE_PARAM_RE = re.compile(r"\{\$([A-Za-z_][A-Za-z0-9_]*)\}")


def _load_template(rel_path: str, case_id: str, params: dict[str, str]):
    """Resolve a ``../_templates/foo.sce-template.xml`` path against the
    consumer case's directory and return the parsed ``<sce:template>``
    root element with ``{$name}`` placeholders substituted from the
    consumer's ``<sce:use>`` attribute block. Returns ``None`` if the
    file isn't there or substitution leaves an unresolved placeholder.
    """
    case_dir = TESTS_DIR / case_id.lower()
    tpath = (case_dir / rel_path).resolve()
    if not tpath.exists():
        return None
    try:
        raw = tpath.read_text(encoding="utf-8")
    except OSError:
        return None
    if params:
        def _sub(m: re.Match) -> str:
            name = m.group(1)
            if name in params:
                return params[name]
            # Leave unresolved placeholders alone so a missing param
            # surfaces visibly in the cond string; the cond parser
            # will degrade those clauses to Opaque.
            return m.group(0)
        raw = _TEMPLATE_PARAM_RE.sub(_sub, raw)
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        return None


def _parse_states_from(elem, states: list[StateDef], seen: set[str]) -> None:
    """Append ``<state>`` and ``<final>`` direct children of ``elem`` to
    ``states``. Skips ids already in ``seen`` so a consumer SCXML's
    inline state (rare) wins over a template's same-id state."""
    for child in elem:
        tag = _strip_ns(child.tag)
        if tag == "state":
            sid = child.attrib.get("id", "")
            if sid in seen:
                continue
            trs: list[TransitionDef] = []
            for tchild in child:
                if _strip_ns(tchild.tag) != "transition":
                    continue
                cond_src = tchild.attrib.get("cond", "")
                target = tchild.attrib.get("target", "")
                event = tchild.attrib.get("event", "")
                if not cond_src or not target:
                    # Deadline / no-cond transitions are time-driven — they
                    # never match against a packet, so they are not stored in
                    # the matcher's transition list.
                    continue
                trs.append(TransitionDef(
                    event=event,
                    cond_src=cond_src,
                    target=target,
                ))
            states.append(StateDef(
                id=sid, is_final=False, final_kind="", transitions=trs,
            ))
            seen.add(sid)
        elif tag == "final":
            sid = child.attrib.get("id", "")
            if sid in seen:
                continue
            kind = "pass" if sid.lower() == "pass" else "fail" \
                if sid.lower().startswith("fail") else ""
            states.append(StateDef(
                id=sid, is_final=True, final_kind=kind, transitions=[],
            ))
            seen.add(sid)


def parse_scxml(content: str, case_id: str = "") -> tuple[list[StateDef], str]:
    """Return (states-in-document-order, initial-state-id).

    Parses both ``<state>`` (with transitions) and ``<final>`` (verdict
    sinks) so the walker can detect when the SM has reached pass/fail.
    Resolves ``<sce:use template="..."/>`` directives by reading the
    referenced template and parsing its states as if they were inline
    children of the consumer SCXML — that's how the SCE codegen treats
    them (see tests/_templates/*.sce-template.xml for the body shared
    by Group C ARP / TCP basics / SOMEIPSRV OPTIONS family cases).
    """
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return [], ""

    template_root = None
    for child in root:
        if _strip_ns(child.tag) == SCE_USE_TAG:
            tpath = child.attrib.get("template", "")
            if tpath and case_id:
                # Every other attribute on <sce:use> is a substitution
                # value for the template's ``{$name}`` placeholders.
                params = {k: v for k, v in child.attrib.items() if k != "template"}
                template_root = _load_template(tpath, case_id, params)
                break

    initial = root.attrib.get("initial", "")
    states: list[StateDef] = []
    seen: set[str] = set()
    _parse_states_from(root, states, seen)
    if template_root is not None:
        _parse_states_from(template_root, states, seen)
    return states, initial


# ---------------------------------------------------------------------------
# Cond-label cosmetics
# ---------------------------------------------------------------------------


def _short_cond(cond_src: str, limit: int = 140) -> str:
    """Tidy a cond for inline display: drop ``cpp:`` and ``captured.``
    noise, collapse whitespace, cap length."""
    s = cond_src.strip()
    if s.startswith("cpp:"):
        s = s[4:]
    s = re.sub(r"\s+", " ", s)
    s = s.replace("captured.", "")
    if len(s) > limit:
        s = s[: limit - 1].rstrip() + "…"
    return s


# ---------------------------------------------------------------------------
# Walker — assigns role + label per packet idx
# ---------------------------------------------------------------------------


@dataclass
class AutoMessage:
    idx: int
    role: str
    label: str


def _lookup_transition_cond_src(states_by_id: dict, step: dict) -> str:
    """Return the SCXML cond source for a trace step.

    The C++ harness records (from_state, to_state, event) per transition
    but not the cond text — the SCXML is the authoritative source for
    the cond, so the walker re-resolves it here. Falls back to whatever
    ``transition_cond_text`` the trace carried (if any) when the SCXML
    lookup misses (e.g. a synthetic step whose target state isn't in
    states_by_id).
    """
    explicit = step.get("transition_cond_text")
    if explicit:
        return explicit
    src = states_by_id.get(step.get("from_state", ""))
    if not src:
        return ""
    target = step.get("to_state")
    event = step.get("event") or ""
    for t in src.transitions:
        if t.target != target:
            continue
        if event and t.event and t.event != event:
            continue
        return t.cond_src
    return ""


def _label_via_trace(
    states: list[StateDef], packets: list[dict],
    trace: dict,
) -> list[AutoMessage]:
    """Option 3 SSOT path: render timeline directly from the harness's
    recorded transition trace, bypassing the cond-evaluation loop entirely.

    Each ``trace.steps[i]`` represents one SCXML transition the live
    state machine fired, with the Captured fields it observed at that
    moment plus a ``pcap_frame_idx`` linking back to the saved pcap.
    Steps with ``pcap_frame_idx == null`` correspond to wire events the
    harness's libpcap observed but the saved pcap did not retain (the
    Mode B "capture-scope shortfall" pattern documented in
    [[feedback-design-lightweight-bias]]). They surface as case-level
    notes so the reader sees the verdict-decider evidence even though
    the frame itself is absent below.

    Walker drift is structurally impossible under this path: the walker
    consumes harness ground truth, not a frame-by-frame simulation. The
    Phase E lint (``trace.final_state === outcome``) closes the loop.
    """
    states_by_id = {s.id: s for s in states}

    step_by_frame: dict[int, dict] = {}
    synthetic_steps: list[dict] = []
    for step in trace.get("steps") or []:
        if not isinstance(step, dict):
            continue
        pfi = step.get("pcap_frame_idx")
        if isinstance(pfi, int):
            step_by_frame[pfi] = step
        else:
            synthetic_steps.append(step)

    final_state_id = trace.get("final_state") or ""
    final_state = states_by_id.get(final_state_id)
    final_kind = final_state.final_kind if final_state and final_state.is_final else ""

    msgs: list[AutoMessage] = []

    # Synthetic (non-retained-frame) steps surface as case-level notes
    # pinned at the top of the timeline so the reader sees verdict-decider
    # evidence before the per-frame stream. Ordered by ``step`` so a case
    # with multiple non-retained events preserves harness wall-time order.
    #
    # Two flavours after the 2026-05-15 onCaptured idx-attribution fix
    # (test_runner.h removes the spurious "clear-on-first-sub-event" path):
    # tick-driven timer fires (event=deadline_exceeded) — no physical
    # frame ever caused them, so the saved pcap legitimately doesn't
    # contain one — and any residual "Captured but not dumped" cases
    # (BPF reject, dropped pre-dump). The label split keeps the reader
    # from hunting a phantom wire packet for the timer flavour.
    for step in sorted(synthetic_steps, key=lambda s: s.get("step", 0)):
        from_s = step.get("from_state", "?")
        to_s = step.get("to_state", "?")
        cond_text = _short_cond(_lookup_transition_cond_src(states_by_id, step))
        target_state = states_by_id.get(to_s)
        verdict = (target_state.final_kind
                   if target_state and target_state.is_final else "")
        delta = step.get("captured_delta") or {}
        delta_text = ", ".join(f"{k}={v}" for k, v in delta.items()) or "(no delta)"
        verdict_tag = verdict or "progress"
        event = step.get("event", "")
        if event == "deadline_exceeded":
            label = (
                f"Timer-driven phase advance "
                f"(step {step.get('step', '?')}, {from_s} → {to_s}, "
                f"{verdict_tag}). SCXML <send delay/> fired between "
                f"physical frames — no wire packet caused this step. "
                f"Harness Captured at trace time: {delta_text}. "
                f"Cond: {cond_text}"
            )
        else:
            label = (
                f"Verdict-decider not retained in saved pcap "
                f"(step {step.get('step', '?')}, {from_s} → {to_s}, "
                f"{verdict_tag}). Harness Captured at trace time: "
                f"{delta_text}. Cond: {cond_text}"
            )
        msgs.append(AutoMessage(idx=-1, role="case-note", label=label))

    reached_final = False
    for p in packets:
        idx = p.get("idx", 0)
        direction = p.get("direction", "other")
        step = step_by_frame.get(idx)

        if step is None:
            if reached_final:
                msgs.append(AutoMessage(
                    idx=idx, role="note",
                    label=(
                        f"Post-{final_kind or 'verdict'} teardown "
                        f"(state machine already at {final_state_id or 'final'})"
                    ),
                ))
            elif direction == "tester_to_dut":
                msgs.append(AutoMessage(
                    idx=idx, role="stimulus",
                    label="Tester stimulus (no transition fired)",
                ))
            elif direction == "dut_to_tester":
                msgs.append(AutoMessage(
                    idx=idx, role="note",
                    label="DUT frame (no transition fired)",
                ))
            else:
                msgs.append(AutoMessage(
                    idx=idx, role="note",
                    label="Observed frame (no transition fired)",
                ))
            continue

        from_s = step.get("from_state", "?")
        to_s = step.get("to_state", "?")
        cond_text = _short_cond(_lookup_transition_cond_src(states_by_id, step))
        target_state = states_by_id.get(to_s)
        verdict = (target_state.final_kind
                   if target_state and target_state.is_final else "")
        if verdict == "pass":
            role = "expected"
            label = (f"Step {step.get('step', '?')} ({from_s}) pass trigger — "
                     f"transitions to {to_s}. Cond: {cond_text}")
        elif verdict == "fail":
            role = "fail-trigger"
            label = (f"Step {step.get('step', '?')} ({from_s}) fail trigger — "
                     f"transitions to {to_s}. Cond: {cond_text}")
        else:
            role = "expected"
            label = (f"Step {step.get('step', '?')} ({from_s}) progress trigger — "
                     f"advances to {to_s}. Cond: {cond_text}")
        msgs.append(AutoMessage(idx=idx, role=role, label=label))
        if target_state and target_state.is_final:
            reached_final = True

    return msgs


def label_packets(
    states: list[StateDef], packets: list[dict],
    captured_trace: dict | None = None,
) -> list[AutoMessage]:
    """Render per-packet timeline labels from the harness transition trace.

    The ``captured_trace`` block — recorded by the live state machine and
    merged into the pcap JSON by ``tc8-harness decode-pcap`` — is the single
    source of truth for which frame fired which transition (see
    ``_label_via_trace``). Every ``tc8-harness test --pcap-dump`` run emits the
    ``<pcap>.trace.json`` sidecar, so the live corpus always takes that path.
    A capture with no trace degrades to neutral direction-only notes.
    """
    if not states:
        return []
    if isinstance(captured_trace, dict) and captured_trace.get("steps") is not None:
        return _label_via_trace(states, packets, captured_trace)
    return _label_by_direction(packets)


def _label_by_direction(packets: list[dict]) -> list[AutoMessage]:
    """Fallback for a capture with no harness trace (not expected for the
    live corpus): a neutral per-frame note keyed on direction."""
    msgs: list[AutoMessage] = []
    for p in packets:
        direction = p.get("direction", "other")
        if direction == "tester_to_dut":
            label = "Tester stimulus"
        elif direction == "dut_to_tester":
            label = "DUT frame"
        else:
            label = "Observed frame"
        msgs.append(AutoMessage(idx=p.get("idx", 0), role="note", label=label))
    return msgs


def _iter_case_ids(only: Iterable[str]) -> list[str]:
    only_set = {c.upper() for c in only}
    if only_set:
        return sorted(only_set)
    return sorted(p.stem for p in PCAP_DIR.glob("*.json"))


def generate_for(case_id: str) -> tuple[bool, str]:
    """Returns (wrote, message)."""
    cid = case_id.upper()
    case_path = CASES_DIR / f"{cid}.json"
    pcap_path = PCAP_DIR / f"{cid}.json"
    if not case_path.exists():
        return False, f"{cid}: case manifest missing"
    if not pcap_path.exists():
        return False, f"{cid}: pcap JSON missing"

    case_doc = json.loads(case_path.read_text(encoding="utf-8"))
    pcap_doc = json.loads(pcap_path.read_text(encoding="utf-8"))
    scxml_src = (case_doc.get("scxml") or {}).get("content") or ""
    if not scxml_src:
        return False, f"{cid}: no inlined SCXML"

    packets = pcap_doc.get("packets") or []
    if not packets:
        return False, f"{cid}: no packets"

    states, _initial = parse_scxml(scxml_src, case_id=cid)
    msgs = label_packets(
        states, packets,
        captured_trace=pcap_doc.get("captured_trace"),
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / f"{cid}.json"
    out_path.write_text(json.dumps({
        "case_id": cid,
        "generator_version": GENERATOR_VERSION,
        "messages": [
            {"idx": m.idx, "role": m.role, "label": m.label}
            for m in msgs
        ],
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    return True, f"{cid}: wrote {len(msgs)} message(s)"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", action="append", default=[],
                    help="case_id (canonical) to generate; repeatable. "
                         "Default: every case with a pcap JSON.")
    ap.add_argument("--clean", action="store_true",
                    help="Remove OUT_DIR before generating (full runs only).")
    ap.add_argument("--cases-dir", type=Path, default=DEFAULT_CASES_DIR,
                    help="Directory of per-case manifests (default: main checkout).")
    ap.add_argument("--pcap-dir", type=Path, default=DEFAULT_PCAP_DIR,
                    help="Directory of decoded pcap JSON (default: site/src/data/pcap).")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR,
                    help="Directory to write auto_messages JSON.")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    global CASES_DIR, PCAP_DIR, OUT_DIR
    CASES_DIR = args.cases_dir
    PCAP_DIR = args.pcap_dir
    OUT_DIR = args.out_dir

    if args.clean and not args.only:
        if OUT_DIR.exists():
            for old in OUT_DIR.glob("*.json"):
                old.unlink()

    ids = _iter_case_ids(args.only)
    if not ids:
        print("no cases to generate (pcap JSONs missing?)", file=sys.stderr)
        return 0

    wrote = 0
    skipped = 0
    for cid in ids:
        ok, message = generate_for(cid)
        if ok:
            wrote += 1
            if args.verbose:
                print(message)
        else:
            skipped += 1
            if args.verbose:
                print(message, file=sys.stderr)
    print(f"generated {wrote} message file(s); skipped {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
