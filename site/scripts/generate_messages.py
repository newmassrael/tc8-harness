#!/usr/bin/env python3
"""Auto-generate per-packet ``messages[]`` annotations from SCXML cond rules.

Reads ``site/src/data/cases/<CASE>.json`` for the inlined SCXML and
``site/src/data/pcap/<CASE>.json`` for the per-case packet list, walks
the SCXML state machine packet-by-packet, and emits a labelled JSON file
at ``site/src/data/auto_messages/<CASE>.json``. The site's
``localizedMessages`` helper merges these auto labels with hand-written
locale overrides at idx granularity (manual wins).

Usage:
    site/scripts/generate_messages.py                # all cases with pcap
    site/scripts/generate_messages.py --only ARP_03  # one case

Design notes:
- No ``eval`` and no external dependencies. Cond expressions use a small
  hand-written tokenizer + recursive-descent parser tied to the cond
  grammar tc8-harness actually writes (captured.X / expected.Y member
  access, indexed sd_entries, bitwise & + comparisons, ``and`` / ``or`` /
  ``not`` joins). Anything outside that surface (function calls,
  initializer lists, namespaced constants) is treated as UNKNOWN under
  Kleene three-valued logic, so opaque sub-clauses don't force a
  conservative match into a false-positive.
- ``expected.X`` evaluates to UNKNOWN by design. The trait-header values
  aren't available here; we still want the rest of the cond to do the
  filtering. AND chains drop UNKNOWN clauses when there's at least one
  concrete TRUE; OR chains drop UNKNOWN clauses when there's at least
  one concrete TRUE/FALSE that decides the result.
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
from typing import Any, Iterable


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

GENERATOR_VERSION = "1"


# ---------------------------------------------------------------------------
# Cond tokenizer
# ---------------------------------------------------------------------------


TOKEN_SPEC = [
    ("WS",      r"\s+"),
    ("HEX",     r"0[xX][0-9A-Fa-f]+[Uu]?[Ll]?[Ll]?"),
    ("INT",     r"\d+[Uu]?[Ll]?[Ll]?"),
    ("CMP",     r"==|!=|<=|>="),
    ("LE",      r"<"),
    ("GE",      r">"),
    ("ANDAND",  r"&&"),
    ("OROR",    r"\|\|"),
    ("AMP",     r"&"),
    ("PIPE",    r"\|"),
    ("PLUS",    r"\+"),
    ("MINUS",   r"-"),
    ("STAR",    r"\*"),
    ("SLASH",   r"/"),
    ("BANG",    r"!"),
    ("LPAREN",  r"\("),
    ("RPAREN",  r"\)"),
    ("LBRACK",  r"\["),
    ("RBRACK",  r"\]"),
    ("LBRACE",  r"\{"),
    ("RBRACE",  r"\}"),
    ("DOT",     r"\."),
    ("COMMA",   r","),
    ("SCOPE",   r"::"),
    ("IDENT",   r"[A-Za-z_][A-Za-z0-9_]*"),
]
TOKEN_RE = re.compile("|".join(f"(?P<{n}>{p})" for n, p in TOKEN_SPEC))

KEYWORDS = {"and", "or", "not", "true", "false"}


@dataclass
class Token:
    kind: str
    text: str


def tokenize(src: str) -> list[Token]:
    out: list[Token] = []
    pos = 0
    while pos < len(src):
        m = TOKEN_RE.match(src, pos)
        if not m:
            raise ValueError(f"unexpected char at pos {pos}: {src[pos]!r}")
        kind = m.lastgroup
        text = m.group()
        pos = m.end()
        if kind == "WS":
            continue
        if kind == "IDENT" and text in KEYWORDS:
            kind = text.upper()  # AND / OR / NOT / TRUE / FALSE
        out.append(Token(kind, text))  # type: ignore[arg-type]
    return out


# ---------------------------------------------------------------------------
# Cond AST
# ---------------------------------------------------------------------------


@dataclass
class IntLit:
    value: int


@dataclass
class BoolLit:
    value: bool


@dataclass
class Ident:
    """Dotted/indexed name. Parts are str (member) or int (index)."""
    parts: tuple


@dataclass
class BinOp:
    op: str
    lhs: Any
    rhs: Any


@dataclass
class UnOp:
    op: str
    operand: Any


@dataclass
class Call:
    """Opaque function/method call — always evaluates to UNKNOWN."""
    target: Any
    args: list


@dataclass
class InitList:
    """``{ a, b, c }`` — opaque, used only as an argument to opaque calls."""
    items: list


@dataclass
class Opaque:
    """Anything else we couldn't classify — evaluates to UNKNOWN."""
    note: str = ""


# ---------------------------------------------------------------------------
# Cond parser (recursive descent)
# ---------------------------------------------------------------------------


class Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.toks = tokens
        self.pos = 0

    def peek(self, k: int = 0) -> Token | None:
        i = self.pos + k
        return self.toks[i] if i < len(self.toks) else None

    def take(self) -> Token:
        tok = self.toks[self.pos]
        self.pos += 1
        return tok

    def accept(self, *kinds: str) -> Token | None:
        t = self.peek()
        if t and t.kind in kinds:
            return self.take()
        return None

    def expect(self, kind: str) -> Token:
        t = self.peek()
        if not t or t.kind != kind:
            raise ValueError(f"expected {kind} at pos {self.pos}, got {t}")
        return self.take()

    def parse(self) -> Any:
        expr = self.or_expr()
        if self.peek() is not None:
            # Trailing garbage — wrap whole expression as opaque to keep
            # the generator from crashing on edge-case grammar.
            return Opaque(note="trailing tokens")
        return expr

    def or_expr(self) -> Any:
        lhs = self.and_expr()
        while self.accept("OR", "OROR"):
            rhs = self.and_expr()
            lhs = BinOp("or", lhs, rhs)
        return lhs

    def and_expr(self) -> Any:
        lhs = self.not_expr()
        while self.accept("AND", "ANDAND"):
            rhs = self.not_expr()
            lhs = BinOp("and", lhs, rhs)
        return lhs

    def not_expr(self) -> Any:
        if self.accept("NOT", "BANG"):
            return UnOp("not", self.not_expr())
        return self.cmp_expr()

    def cmp_expr(self) -> Any:
        lhs = self.bitor()
        t = self.peek()
        if t and t.kind in ("CMP", "LE", "GE"):
            op_text = self.take().text
            rhs = self.bitor()
            return BinOp(op_text, lhs, rhs)
        return lhs

    def bitor(self) -> Any:
        lhs = self.bitand()
        while self.accept("PIPE"):
            rhs = self.bitand()
            lhs = BinOp("|", lhs, rhs)
        return lhs

    def bitand(self) -> Any:
        lhs = self.add()
        while self.accept("AMP"):
            rhs = self.add()
            lhs = BinOp("&", lhs, rhs)
        return lhs

    def add(self) -> Any:
        lhs = self.mul()
        while True:
            t = self.peek()
            if t and t.kind == "PLUS":
                self.take()
                lhs = BinOp("+", lhs, self.mul())
            elif t and t.kind == "MINUS":
                self.take()
                lhs = BinOp("-", lhs, self.mul())
            else:
                break
        return lhs

    def mul(self) -> Any:
        lhs = self.unary()
        while True:
            t = self.peek()
            if t and t.kind == "STAR":
                self.take()
                lhs = BinOp("*", lhs, self.unary())
            elif t and t.kind == "SLASH":
                self.take()
                lhs = BinOp("/", lhs, self.unary())
            else:
                break
        return lhs

    def unary(self) -> Any:
        if self.accept("MINUS"):
            return UnOp("-", self.unary())
        return self.atom()

    def atom(self) -> Any:
        t = self.peek()
        if t is None:
            raise ValueError("unexpected end of expression")
        if t.kind == "HEX":
            self.take()
            return IntLit(int(t.text.rstrip("uUlL"), 16))
        if t.kind == "INT":
            self.take()
            return IntLit(int(t.text.rstrip("uUlL")))
        if t.kind == "TRUE":
            self.take()
            return BoolLit(True)
        if t.kind == "FALSE":
            self.take()
            return BoolLit(False)
        if t.kind == "LPAREN":
            self.take()
            inner = self.or_expr()
            self.expect("RPAREN")
            return inner
        if t.kind == "LBRACE":
            return self.init_list()
        if t.kind == "SCOPE" or t.kind == "IDENT":
            return self.primary()
        # Unknown atom shape — opaque so we don't blow up
        self.take()
        return Opaque(note=f"unexpected atom {t.text!r}")

    def init_list(self) -> InitList:
        self.expect("LBRACE")
        items: list[Any] = []
        while self.peek() and self.peek().kind != "RBRACE":  # type: ignore[union-attr]
            items.append(self.or_expr())
            if not self.accept("COMMA"):
                break
        self.expect("RBRACE")
        return InitList(items=items)

    def primary(self) -> Any:
        """Identifier chain: optional ``::`` prefix, dots, [index], (args)."""
        parts: list = []

        # Leading or interior scope (``::tc8::sce::tcp::kFoo``). We collapse
        # the entire scoped name into one Opaque token — callers don't
        # know symbolic constant values.
        had_scope = False
        if self.peek() and self.peek().kind == "SCOPE":  # type: ignore[union-attr]
            had_scope = True
            self.take()
        ident = self.expect("IDENT")
        parts.append(ident.text)

        while True:
            t = self.peek()
            if t and t.kind == "SCOPE":
                had_scope = True
                self.take()
                self.expect("IDENT")  # consume — keep entire scoped name opaque
                continue
            break

        if had_scope:
            # Opaque named constant; may still be followed by member access etc
            base: Any = Opaque(note="scoped-constant")
        else:
            base = Ident(parts=tuple(parts))

        while True:
            t = self.peek()
            if t and t.kind == "DOT":
                self.take()
                next_id = self.expect("IDENT")
                if isinstance(base, Ident):
                    base = Ident(parts=base.parts + (next_id.text,))
                else:
                    base = Opaque(note="member-of-opaque")
            elif t and t.kind == "LBRACK":
                self.take()
                idx_expr = self.or_expr()
                self.expect("RBRACK")
                if isinstance(base, Ident) and isinstance(idx_expr, IntLit):
                    base = Ident(parts=base.parts + (idx_expr.value,))
                else:
                    base = Opaque(note="dynamic-index")
            elif t and t.kind == "LPAREN":
                # Function or method call — opaque.
                self.take()
                args: list[Any] = []
                while self.peek() and self.peek().kind != "RPAREN":  # type: ignore[union-attr]
                    args.append(self.or_expr())
                    if not self.accept("COMMA"):
                        break
                self.expect("RPAREN")
                base = Call(target=base, args=args)
            else:
                break
        return base


def parse_cond(src: str) -> Any:
    """Tokenize + parse a SCXML cond into the small AST. Strips the leading
    ``cpp:`` prefix the harness puts on every SCE-evaluated cond."""
    s = src.strip()
    if s.startswith("cpp:"):
        s = s[4:]
    try:
        toks = tokenize(s)
        return Parser(toks).parse()
    except ValueError:
        return Opaque(note="parse-error")


# ---------------------------------------------------------------------------
# Kleene three-valued evaluator
# ---------------------------------------------------------------------------


# Sentinel for "we couldn't evaluate this sub-clause". The Kleene rules
# in _eval_bool let UNKNOWN drop out of AND chains when at least one
# concrete TRUE is present, and out of OR chains when a concrete TRUE/FALSE
# decides the result — so expected.X comparisons don't kill matches.
UNKNOWN = object()


# Map ``captured.NAME`` field aliases onto pcap-decoder field names. The
# generator can only see what decode_pcap.py writes; the SCXML grammar
# names the same observation under harness-side capture-struct fields.
CAPTURED_ALIASES = {
    "eth_src":          "src_mac",
    "eth_dst":          "dst_mac",
    "src_ip":           "src_ip",
    "dst_ip":           "dst_ip",
    "sender_hw":        "sender_mac",
    "target_hw":        "target_mac",
    "sender_proto_ip":  "sender_ip",
    "target_proto_ip":  "target_ip",
}

# TCP flag-name → bit, used to materialise an integer when SCXML asks
# ``captured.flags & 0xNN`` and the decoder stored flags as a "|"-joined
# string.
TCP_FLAG_BITS = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
    "ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80,
}


def _flags_to_int(s: str) -> int:
    total = 0
    for f in s.split("|"):
        total |= TCP_FLAG_BITS.get(f.strip(), 0)
    return total


def _packet_view(packet: dict) -> dict:
    """Promote a few fields the SCXML uses by name. Direction / protocol
    aren't in fields{} but the cond grammar never references them, so we
    don't bother synthesizing those — wrong names cleanly resolve to
    UNKNOWN."""
    fields = dict(packet.get("fields") or {})
    # Eth + IP basics live on the top-level packet, not inside fields{}.
    for k in ("src_mac", "dst_mac", "src_ip", "dst_ip"):
        v = packet.get(k)
        if v is not None and k not in fields:
            fields[k] = v
    # Convenience aliases for SOME/IP-SD entry counts (the SCXML uses
    # ``captured.sd_entry_count`` and ``captured.sd_ipv4_endpoint_count``
    # as scalars; the decoder gives us the underlying lists).
    sd_entries = fields.get("sd_entries")
    if isinstance(sd_entries, list):
        fields.setdefault("sd_entry_count", len(sd_entries))
    sd_options = fields.get("sd_options")
    if isinstance(sd_options, list):
        fields.setdefault(
            "sd_ipv4_endpoint_count",
            sum(1 for o in sd_options if (o.get("type") == 0x04)),
        )
    # Materialise TCP flags as int when present as the "|"-joined string.
    flags = fields.get("flags")
    if isinstance(flags, str) and flags and flags != "—":
        fields["flags"] = _flags_to_int(flags)
    return fields


def _resolve_ident(parts: tuple, packet_view: dict) -> Any:
    """Walk a dotted/indexed name through (captured / expected) namespaces.

    Returns ``UNKNOWN`` if any segment can't be resolved — including any
    access into ``expected``, since trait-side constants aren't loaded
    here. Returns the value when fully resolved against captured data.
    """
    if not parts:
        return UNKNOWN
    head = parts[0]
    if head == "expected":
        return UNKNOWN
    if head != "captured":
        return UNKNOWN
    if len(parts) < 2:
        return UNKNOWN
    name = parts[1]
    name = CAPTURED_ALIASES.get(name, name)
    cur: Any = packet_view.get(name, UNKNOWN)
    for seg in parts[2:]:
        if cur is UNKNOWN or cur is None:
            return UNKNOWN
        if isinstance(seg, int):
            if isinstance(cur, list) and 0 <= seg < len(cur):
                cur = cur[seg]
            else:
                return UNKNOWN
        elif isinstance(seg, str):
            if isinstance(cur, dict) and seg in cur:
                cur = cur[seg]
            else:
                return UNKNOWN
        else:
            return UNKNOWN
    return cur


def _eval(expr: Any, packet_view: dict, strict: bool) -> Any:
    """Returns int / bool / UNKNOWN.

    ``strict=False`` is the lenient pass-trigger mode: UNKNOWN clauses
    drop out of AND chains as long as at least one concrete TRUE clause
    decides the result. That lets ``service_id == expected.X`` act as a
    wildcard so the *other* discriminating clauses can still fire the
    transition.

    ``strict=True`` is the fail-trigger mode: UNKNOWN poisons AND/OR
    chains. A fail cond must evaluate to concrete TRUE end-to-end. This
    prevents the asymmetric ``X != expected.Y`` clause from rescuing a
    fail transition into a false positive when the actual ``expected.Y``
    value isn't loaded.
    """
    if isinstance(expr, IntLit):
        return expr.value
    if isinstance(expr, BoolLit):
        return expr.value
    if isinstance(expr, Ident):
        return _resolve_ident(expr.parts, packet_view)
    if isinstance(expr, (Opaque, Call, InitList)):
        return UNKNOWN
    if isinstance(expr, UnOp):
        v = _eval(expr.operand, packet_view, strict)
        if v is UNKNOWN:
            return UNKNOWN
        if expr.op == "not":
            return not bool(v)
        if expr.op == "-":
            return -v if isinstance(v, int) else UNKNOWN
        return UNKNOWN
    if isinstance(expr, BinOp):
        if expr.op == "and":
            return _bool_and(
                _eval(expr.lhs, packet_view, strict),
                _eval(expr.rhs, packet_view, strict),
                strict,
            )
        if expr.op == "or":
            return _bool_or(
                _eval(expr.lhs, packet_view, strict),
                _eval(expr.rhs, packet_view, strict),
                strict,
            )
        lhs = _eval(expr.lhs, packet_view, strict)
        rhs = _eval(expr.rhs, packet_view, strict)
        if lhs is UNKNOWN or rhs is UNKNOWN:
            return UNKNOWN
        try:
            if expr.op == "==": return lhs == rhs
            if expr.op == "!=": return lhs != rhs
            if expr.op == "<":  return lhs < rhs
            if expr.op == ">":  return lhs > rhs
            if expr.op == "<=": return lhs <= rhs
            if expr.op == ">=": return lhs >= rhs
            if expr.op == "&":  return lhs & rhs
            if expr.op == "|":  return lhs | rhs
            if expr.op == "+":  return lhs + rhs
            if expr.op == "-":  return lhs - rhs
            if expr.op == "*":  return lhs * rhs
            if expr.op == "/":  return lhs // rhs if rhs else UNKNOWN
        except (TypeError, ValueError):
            return UNKNOWN
    return UNKNOWN


def _bool_and(a: Any, b: Any, strict: bool) -> Any:
    if a is False or b is False:
        return False
    if strict:
        if a is UNKNOWN or b is UNKNOWN:
            return UNKNOWN
        return bool(a) and bool(b)
    # Lenient Kleene: UNKNOWN drops if something concrete decides.
    if a is UNKNOWN and b is UNKNOWN:
        return UNKNOWN
    if a is UNKNOWN:
        return bool(b)
    if b is UNKNOWN:
        return bool(a)
    return bool(a) and bool(b)


def _bool_or(a: Any, b: Any, strict: bool) -> Any:
    if a is True or b is True:
        return True
    if strict:
        if a is UNKNOWN or b is UNKNOWN:
            return UNKNOWN
        return bool(a) or bool(b)
    if a is UNKNOWN and b is UNKNOWN:
        return UNKNOWN
    if a is UNKNOWN:
        return UNKNOWN if not b else True
    if b is UNKNOWN:
        return UNKNOWN if not a else True
    return bool(a) or bool(b)


def cond_matches(expr: Any, packet_view: dict, strict: bool = False) -> bool:
    """A transition matches when its cond evaluates to concrete TRUE.
    Caller controls strict vs lenient handling of UNKNOWN clauses."""
    return _eval(expr, packet_view, strict) is True


# ---------------------------------------------------------------------------
# SCXML parser
# ---------------------------------------------------------------------------


SCXML_NS = "http://www.w3.org/2005/07/scxml"


@dataclass
class TransitionDef:
    event: str
    cond_src: str           # original cond source (for label cosmetics)
    cond_ast: Any           # parsed AST or Opaque
    target: str             # target state id


@dataclass
class StateDef:
    id: str
    phase_index: int        # 1-based, derived from order of non-final states
    is_final: bool
    final_kind: str         # "pass" / "fail" / "" (non-final)
    transitions: list[TransitionDef] = field(default_factory=list)


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def parse_scxml(content: str) -> tuple[list[StateDef], str]:
    """Return (states-in-document-order, initial-state-id).

    Parses both ``<state>`` (with transitions) and ``<final>`` (verdict
    sinks) so the walker can detect when the SM has reached pass/fail.
    """
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return [], ""

    initial = root.attrib.get("initial", "")
    states: list[StateDef] = []
    phase_idx = 0
    for child in root:
        tag = _strip_ns(child.tag)
        if tag == "state":
            sid = child.attrib.get("id", "")
            phase_idx += 1
            trs: list[TransitionDef] = []
            for tchild in child:
                if _strip_ns(tchild.tag) != "transition":
                    continue
                cond_src = tchild.attrib.get("cond", "")
                target = tchild.attrib.get("target", "")
                event = tchild.attrib.get("event", "")
                if not cond_src or not target:
                    # Deadline / no-cond transitions are time-driven —
                    # they never match against a packet, so we don't
                    # store them in the matcher's transition list.
                    continue
                trs.append(TransitionDef(
                    event=event,
                    cond_src=cond_src,
                    cond_ast=parse_cond(cond_src),
                    target=target,
                ))
            states.append(StateDef(
                id=sid, phase_index=phase_idx, is_final=False,
                final_kind="", transitions=trs,
            ))
        elif tag == "final":
            sid = child.attrib.get("id", "")
            kind = "pass" if sid.lower() == "pass" else "fail" \
                if sid.lower().startswith("fail") else ""
            states.append(StateDef(
                id=sid, phase_index=0, is_final=True,
                final_kind=kind, transitions=[],
            ))
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


def _verdict_for_target(target: str, states_by_id: dict) -> str:
    """Return "pass" / "fail" / "" depending on what kind of state the
    target is."""
    st = states_by_id.get(target)
    if st and st.is_final:
        return st.final_kind
    return ""


# ---------------------------------------------------------------------------
# Walker — assigns role + label per packet idx
# ---------------------------------------------------------------------------


@dataclass
class AutoMessage:
    idx: int
    role: str
    label: str


def label_packets(
    states: list[StateDef], initial: str, packets: list[dict],
) -> list[AutoMessage]:
    if not states:
        return []
    states_by_id = {s.id: s for s in states}
    current_id = initial or (states[0].id if not states[0].is_final else "")
    if current_id and current_id not in states_by_id:
        current_id = states[0].id
    cur = states_by_id.get(current_id) if current_id else None
    final_outcome = ""  # "pass" / "fail" once the SM lands in a final

    msgs: list[AutoMessage] = []
    for p in packets:
        idx = p.get("idx", 0)
        direction = p.get("direction", "other")
        view = _packet_view(p)

        if final_outcome:
            # SM already at a final — post-verdict frames are teardown.
            msgs.append(AutoMessage(
                idx=idx, role="note",
                label=f"Post-{final_outcome} teardown (state machine already at final)",
            ))
            continue

        if cur is None or cur.is_final:
            msgs.append(AutoMessage(idx=idx, role="note", label="(no active state)"))
            continue

        # Try every non-deadline transition this state can fire. Order:
        # SCXML evaluation is document order — first matching transition
        # wins. We match the same way, with two guards:
        #   * Pass- and progress-target transitions only fire on
        #     DUT-emitted packets (the conds typically observe DUT
        #     behaviour and the ``expected.*`` constants we can't see
        #     often disambiguate DUT vs Tester frames that share
        #     captured-side fields).
        #   * Fail-target transitions require *strict* cond evaluation —
        #     UNKNOWN clauses don't get the lenient Kleene rescue. This
        #     stops ``captured.X != expected.Y`` from claiming a fail on
        #     every Tester frame just because we don't know the
        #     expected value.
        matched: TransitionDef | None = None
        for t in cur.transitions:
            verdict = _verdict_for_target(t.target, states_by_id)
            if verdict == "fail":
                if not cond_matches(t.cond_ast, view, strict=True):
                    continue
            else:
                if direction == "tester_to_dut":
                    continue
                if not cond_matches(t.cond_ast, view, strict=False):
                    continue
            matched = t
            break

        phase_tag = f"Phase {cur.phase_index} ({cur.id})"
        if matched is not None:
            verdict = _verdict_for_target(matched.target, states_by_id)
            cond_text = _short_cond(matched.cond_src)
            if verdict == "pass":
                role = "expected"
                label = (
                    f"{phase_tag} pass trigger — transitions to "
                    f"{matched.target}. Cond: {cond_text}"
                )
                msgs.append(AutoMessage(idx=idx, role=role, label=label))
                cur = states_by_id.get(matched.target, cur)
                if cur and cur.is_final:
                    final_outcome = cur.final_kind or "pass"
            elif verdict == "fail":
                role = "fail-trigger"
                label = (
                    f"{phase_tag} fail trigger — transitions to "
                    f"{matched.target}. Cond: {cond_text}"
                )
                msgs.append(AutoMessage(idx=idx, role=role, label=label))
                cur = states_by_id.get(matched.target, cur)
                if cur and cur.is_final:
                    final_outcome = cur.final_kind or "fail"
            else:
                # Forward transition into another non-final phase.
                next_st = states_by_id.get(matched.target)
                next_label = matched.target if next_st else "?"
                label = (
                    f"{phase_tag} progress trigger — advances to "
                    f"{next_label}. Cond: {cond_text}"
                )
                # DUT-emitted packet → "expected"; tester-emitted → "stimulus".
                role = "expected" if direction == "dut_to_tester" else "stimulus"
                msgs.append(AutoMessage(idx=idx, role=role, label=label))
                cur = next_st or cur
            continue

        # No transition fired on this packet — classify by direction so
        # the reader still sees which phase the frame fell into.
        if direction == "tester_to_dut":
            msgs.append(AutoMessage(
                idx=idx, role="stimulus",
                label=f"{phase_tag} — Tester stimulus (no transition matched)",
            ))
        elif direction == "dut_to_tester":
            msgs.append(AutoMessage(
                idx=idx, role="note",
                label=f"{phase_tag} — DUT frame (no transition matched)",
            ))
        else:
            msgs.append(AutoMessage(
                idx=idx, role="note",
                label=f"{phase_tag} — observed frame",
            ))
    return msgs


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


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

    states, initial = parse_scxml(scxml_src)
    msgs = label_packets(states, initial, packets)

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
