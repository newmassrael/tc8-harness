#!/usr/bin/env python3
"""Join the three sides of a capability bit, which nothing else does.

INVARIANT (docs/tech-debt.md TD-22): for a `kCap*` bit to mean anything, three
independent things must agree -- a case DECLARES it in `kRequiredCapabilities`,
a backend ADVERTISES it, and some code path DEMANDS the sub-interface it stands
for. Each side is readable on its own; nothing checked that they line up, and
every pair-without-the-third fails silently:

  declared, never demanded   the case skips on a backend that could have run it.
  demanded, never declared   the case drives a sub-interface the gate never
                             checked for. On the TCP seam `seamTcpControl`
                             ASSERTS, so that is an abort in a debug build and
                             undefined behaviour under NDEBUG.
  advertised, never demanded the bit is decoration: a backend that starts
                             declining it changes nothing, so the decline cannot
                             be tested.

WHY A GATE AND NOT A REVIEW. Both hand passes that asked this question got a
wrong number before a right one. One credited ten cases with a capability
because its detector read a mention in a COMMENT -- on a declining backend that
turns ten sound passes into skips. The other missed every case reaching the seam
through a pilot helper, because it had no transitive closure, and undercounted
by nearly half. A reviewer caught one; the over-declaration check caught the
other. Neither is a mechanism.

HOW IT RESOLVES EACH SIDE.

  DECLARED   `kRequiredCapabilities` is written in eight traits bases and in 54
             case headers directly. A case inherits through its base chain
             (`TcpDutDrivenBase : TcpAnyBase`), so the chain is walked and the
             sets unioned.
  DEMANDED   the demand vocabulary is the table below: the sub-interface
             accessors, the seam wrappers, the drive helpers and the fault-arm
             emitters. A case demands a bit if a token for it appears in the
             case body, or in the body of a helper the case NAMES -- resolved
             transitively over helper bodies, which is how a case reaching the
             seam through `driveSeamSynSentOpen` is counted.
  ADVERTISED a backend names the bit where it builds its capability word.

Comments are stripped before any of this. That is not tidiness: reading a
comment as code is the exact defect that produced the first wrong number.

WHAT IT CANNOT SEE, stated rather than hidden. Demand resolution is by NAME, not
by a compiler's call graph: a helper that reaches a seam through a function
pointer, a lambda stored in a member, or a template parameter is invisible here.
The table below is therefore the thing to review when a new seam operation is
added -- an operation absent from it is demanded by nothing as far as this gate
is concerned, and CHECK_UNDEMANDED is what makes that absence loud rather than
silent.

Fail-closed: a case header whose base chain cannot be resolved is a finding, not
a pass.

Usage:
    tools/capability_gate_audit.py            print the census
    tools/capability_gate_audit.py --check    enforce; rc 1 on any finding
    tools/capability_gate_audit.py --self-test prove each direction fires
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPS_HEADER = ROOT / "src/sce_integration/include/sce_integration/dut_capabilities.h"
CASES_DIR = ROOT / "src/sce_integration/include/sce_integration/cases"
SEAM_DIRS = [ROOT / "src/sce_integration/include/sce_integration"]
RATCHET = ROOT / "tools" / "capability_gate_reserved.txt"

# Backends that build a capability word. A bit named by none of these is
# advertised by nothing.
BACKEND_FILES = [
    ROOT / "src/sce_integration/include/sce_integration/dut_control.h",
]

# bit -> the tokens whose presence means "this code demands that sub-interface".
# Reviewed by hand; see WHAT IT CANNOT SEE above. A new seam operation belongs
# here the day it is added.
BIT_DEMANDS = {
    "kCapTcpControl": {
        "tcpControl", "seamTcpControl", "seamConnectTcp", "seamSendTcp",
        "seamSendTcpPattern", "driveSeamActiveOpen", "driveSeamPassiveOpen",
        "driveSeamListen", "driveSeamCloseToClosing",
        "driveSeamCloseToTimeWaitClosing", "driveSeamRawPassiveAccept",
    },
    "kCapTcpSynSentOpen": {"driveSeamSynSentOpen"},
    "kCapTcpStateProbe": {"tcpStateProbe"},
    "kCapTcpRecvOob": {"tcpRecvOob", "seamTcpRecvOob"},
    "kCapUdpControl": {"udpControl"},
    "kCapUdpReceiveControl": {"udpReceiveControl"},
    "kCapArpConditioning": {"arpControl"},
    "kCapLinkLocalControl": {"linkLocalControl"},
    "kCapDhcpClientControl": {"dhcpClientControl"},
    "kCapEgressFault": {"emitEgressFlavorArm", "emitEgressFlavorArmMidStream"},
    "kCapIngressFault": {"emitIngressFlavorArm", "emitIngressFlavorArmMidStream"},
    "kCapAppFault": {"emitAppFlavorArm"},
    "kCapEtsFault": {"emitEtsFlavorArm"},
}

BIT_RE = re.compile(r"\b(kCap[A-Za-z]+)\b")
DECL_RE = re.compile(r"kRequiredCapabilities\s*=\s*([^;]+);", re.S)
# A case writes `struct TestCaseTraits<cases::Arp03SM>\n    : ArpDutProvokedBase<...> {`
# -- the specialisation argument sits between the name and the base list, and the
# base list is usually on the next line. A base writes `struct TcpDutDrivenBase :
# TcpAnyBase<StateMachine> {` with no argument on its own name.
# The base list is OPTIONAL: a root traits base is written `struct
# LinklocalAutoconfBase {` with no parent, and requiring the `:` made the gate
# miss its declarations entirely and then report every case under it as
# demanding a bit it did not declare -- 8 false UNDECLARED findings.
STRUCT_RE = re.compile(
    r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>{]*>)?\s*(?::\s*([^{;]+))?\{")
BASE_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*<")
FUNC_DEF_RE = re.compile(
    r"^[ \t]*(?:inline\s+|static\s+|constexpr\s+|template\s*<[^>]*>\s*)*"
    r"[A-Za-z_][A-Za-z0-9_:<>,\s\*&]*?\b([a-z][A-Za-z0-9_]*)\s*\([^;{]*\)\s*(?:const\s*)?\{",
    re.M,
)


def strip_comments(text: str) -> str:
    """Remove // and /* */ comments. Reading a comment as code is the defect
    that produced the first wrong capability count (TD-22)."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c in "\"'":
            q, j = c, i + 1
            while j < n and text[j] != q:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def brace_body(text: str, open_idx: int) -> str:
    """The text between the brace at open_idx and its match."""
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return text[open_idx + 1:]


def defined_bits() -> list[str]:
    src = strip_comments(CAPS_HEADER.read_text(encoding="utf-8"))
    return [m.group(1) for m in re.finditer(r"\b(kCap[A-Za-z]+)\s*=\s*1u\s*<<", src)]


def advertised_bits() -> set[str]:
    found = set()
    for path in BACKEND_FILES:
        if path.is_file():
            found |= set(BIT_RE.findall(strip_comments(path.read_text(encoding="utf-8"))))
    return found


def helper_bodies() -> dict[str, str]:
    """name -> comment-stripped body, for every function defined in the seam and
    pilot-helper headers. These are what a case reaches the seam THROUGH."""
    bodies: dict[str, str] = {}
    # The traits-base files hold FREE FUNCTIONS as well as structs -- the ARP
    # base's shared stimulus calls `dut.arpControl()` from a helper beside the
    # struct, not from inside it. Scanning only the parent directory missed
    # those and reported 33 ARP cases as declaring a bit they never demand.
    paths = [p for d in SEAM_DIRS for p in sorted(d.glob("*.h"))]
    paths += sorted(CASES_DIR.glob("_*.h"))
    for path in paths:
        src = strip_comments(path.read_text(encoding="utf-8"))
        for m in FUNC_DEF_RE.finditer(src):
            open_idx = src.index("{", m.end() - 1)
            bodies.setdefault(m.group(1), "")
            bodies[m.group(1)] += brace_body(src, open_idx)
    return bodies


def demands_of(text: str, bodies: dict[str, str], seen: set[str] | None = None) -> set[str]:
    """Bits this text demands, following helpers it NAMES, transitively."""
    seen = set() if seen is None else seen
    names = set(re.findall(r"\b([a-zA-Z_][A-Za-z0-9_]*)\b", text))
    bits = {bit for bit, toks in BIT_DEMANDS.items() if toks & names}
    for name in sorted(names & set(bodies)):
        if name in seen:
            continue
        seen.add(name)
        bits |= demands_of(bodies[name], bodies, seen)
    return bits


BASE_BODIES: dict[str, str] = {}


def resolve_base_bodies(name: str, table, seen=None) -> str:
    """The struct bodies of a base and everything it inherits, concatenated.

    A case inherits its base's SHARED DISPATCH, and that dispatch is what
    demands the bit on the case's behalf. Reading only the case file made 95
    such cases look like they declared a bit they never used."""
    seen = set() if seen is None else seen
    if name in seen or name not in table:
        return ""
    seen.add(name)
    out = BASE_BODIES.get(name, "")
    for b in table[name][1]:
        out += resolve_base_bodies(b, table, seen)
    return out


def base_declarations() -> dict[str, tuple[set[str], list[str]]]:
    """Base struct name -> (bits it declares itself, the base names it inherits).

    Only the `_*.h` traits bases are keyed by name. A CASE specialises
    `TestCaseTraits<...>`, so every case would collide on one key -- cases are
    resolved per file instead, by `case_declarations`."""
    out: dict[str, tuple[set[str], list[str]]] = {}
    for path in sorted(CASES_DIR.glob("_*.h")):
        src = strip_comments(path.read_text(encoding="utf-8"))
        for m in STRUCT_RE.finditer(src):
            name, bases = m.group(1), BASE_NAME_RE.findall(m.group(2) or "")
            body = brace_body(src, src.index("{", m.end() - 1))
            decl = DECL_RE.search(body)
            bits = set(BIT_RE.findall(decl.group(1))) if decl else set()
            prev_bits, prev_bases = out.get(name, (set(), []))
            out[name] = (prev_bits | bits, prev_bases + bases)
            BASE_BODIES[name] = BASE_BODIES.get(name, "") + body
    return out


def resolve_declared(name: str, table, seen=None) -> set[str]:
    seen = set() if seen is None else seen
    if name in seen or name not in table:
        return set()
    seen.add(name)
    bits, bases = table[name]
    for b in bases:
        bits = bits | resolve_declared(b, table, seen)
    return bits


def read_ratchet() -> dict[str, str]:
    if not RATCHET.is_file():
        return {}
    out = {}
    for line in RATCHET.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            k, _, why = line.partition(" ")
            out[k] = why.strip()
    return out


def audit() -> tuple[list[str], list[str]]:
    findings: list[str] = []
    census: list[str] = []

    bits = defined_bits()
    adv = advertised_bits()
    bodies = helper_bodies()
    table = base_declarations()
    reserved = read_ratchet()

    undeclared: list[str] = []
    undemanded: list[str] = []
    for path in sorted(CASES_DIR.glob("*.h")):
        if path.name.startswith("_"):
            continue  # a base, not a case
        src = strip_comments(path.read_text(encoding="utf-8"))
        structs = list(STRUCT_RE.finditer(src))
        if not structs:
            findings.append(f"UNRESOLVED: {path.name} declares no traits struct; the gate "
                            f"cannot resolve its capabilities, so it is a finding, not a pass")
            continue
        declared: set[str] = set()
        for m in structs:
            body = brace_body(src, src.index("{", m.end() - 1))
            decl = DECL_RE.search(body)
            if decl:
                declared |= set(BIT_RE.findall(decl.group(1)))
            for base in BASE_NAME_RE.findall(m.group(2) or ""):
                declared |= resolve_declared(base, table)
        inherited = "".join(
            resolve_base_bodies(b, table)
            for m in structs for b in BASE_NAME_RE.findall(m.group(2) or "")
        )
        demanded = demands_of(src + inherited, bodies)
        for bit in sorted(demanded - declared):
            undeclared.append(f"{path.name}: demands {bit} but does not declare it")
        for bit in sorted(declared - demanded):
            undemanded.append(f"{path.name}: declares {bit} but demands it nowhere")

    findings += [f"UNDECLARED: {x}" for x in undeclared]
    findings += [f"OVERDECLARED: {x}" for x in undemanded]

    for bit in bits:
        if bit not in adv and bit not in reserved:
            findings.append(f"UNADVERTISED: {bit} is defined but no backend advertises it")
        if bit not in BIT_DEMANDS and bit not in reserved:
            findings.append(f"UNDEMANDED: {bit} has no entry in BIT_DEMANDS, so nothing in "
                            f"this repository is known to demand it")
    for bit in reserved:
        if bit in adv and bit in BIT_DEMANDS:
            findings.append(f"STALE_RESERVED: {bit} stands in {RATCHET.name} but is both "
                            f"advertised and demanded; remove the line")

    census.append(f"bits defined: {len(bits)} · advertised: {len(adv & set(bits))} · "
                  f"with a demand vocabulary: {len(set(BIT_DEMANDS) & set(bits))} · "
                  f"reserved: {len(reserved)}")
    census.append(f"case headers: {len(list(CASES_DIR.glob('*.h')))} · "
                  f"traits structs resolved: {len(table)} · helper bodies: {len(bodies)}")
    census.append(f"undeclared demands: {len(undeclared)} · "
                  f"declarations with no demand: {len(undemanded)}")
    return findings, census


def _self_test() -> int:
    bodies = {"driveSeamSynSentOpen": " seamTcpControl(dut); ",
              "helperCallsHelper": " driveSeamSynSentOpen(dut); "}
    cases = [
        ("a direct accessor is a demand",
         demands_of("udpControl();", {}) == {"kCapUdpControl"}),
        ("a comment is NOT a demand",
         demands_of(strip_comments("// udpControl() would go here\n"), {}) == set()),
        ("a helper is followed one level",
         "kCapTcpControl" in demands_of("driveSeamSynSentOpen(d);", bodies)),
        ("the helper keeps its own bit too",
         "kCapTcpSynSentOpen" in demands_of("driveSeamSynSentOpen(d);", bodies)),
        ("helpers are followed transitively",
         "kCapTcpControl" in demands_of("helperCallsHelper(d);", bodies)),
        ("recursion terminates",
         demands_of("a();", {"a": "a();"}) == set()),
        ("an unrelated token demands nothing",
         demands_of("somethingElse();", bodies) == set()),
        ("a block comment is stripped",
         "udpControl" not in strip_comments("/* udpControl() */ x;")),
        ("a string literal survives stripping",
         "udpControl" in strip_comments('const char *s = "udpControl";')),
        ("inheritance unions the sets",
         resolve_declared("Child", {"Child": (set(), ["Parent"]),
                                    "Parent": ({"kCapTcpControl"}, [])}) == {"kCapTcpControl"}),
        ("an inheritance cycle terminates",
         resolve_declared("A", {"A": (set(), ["B"]), "B": (set(), ["A"])}) == set()),
        ("an unknown base resolves empty, not crash",
         resolve_declared("X", {"X": ({"kCapUdpControl"}, ["Missing"])}) == {"kCapUdpControl"}),
        ("every defined bit has a demand vocabulary",
         set(defined_bits()) - set(BIT_DEMANDS) - set(read_ratchet()) == set()),
    ]
    failed = [label for label, ok in cases if not ok]
    for label in failed:
        print(f"self-test FAIL: {label}", file=sys.stderr)
    if failed:
        return 1
    print(f"capability_gate_audit self-test: all {len(cases)} checks passed")
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--self-test":
        return _self_test()
    check = bool(argv) and argv[0] == "--check"
    if argv and not check:
        sys.exit("usage: capability_gate_audit.py [--check | --self-test]")
    findings, census = audit()
    for line in census:
        print(line)
    if findings:
        print(f"\n{len(findings)} finding(s):", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
    return 1 if (check and findings) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
