#!/usr/bin/env python3
"""Rewrite the eventgroup membership of chosen events in an ETS .fdepl.

The public ETS deployment (dut/ets/ets.fdepl) places each event and field notifier
in the eventgroups OA TC8 v3.0 Table 2 gives it. A consumer whose reference DUT
deploys some of them differently selects its own membership at configure time with
the TC8_ETS_EVENTGROUPS cache variable (dut/ets/CMakeLists.txt), which runs this
tool to write an overlaid copy of the selected .fdepl into the build tree. The
CommonAPI code generator then reads the copy, so the change reaches the generated
StubAdapter's registerEvent calls. It cannot be made at run time: vsomeip only ever
adds eventgroups to an event already registered, never removes one.

An override names an event by the ID the deployment gives it, the SomeIpEventID of
a broadcast or the SomeIpNotifierID of an attribute, and replaces the block's
`SomeIpEventGroups = { ... }` line. Everything else in the file is copied
unchanged, except that a relative `import "x.fidl"` becomes an absolute path, since
the copy no longer sits beside the file it imports.

Usage:
  ets_eventgroup_overlay.py --in ets.fdepl --out overlay.fdepl \
      --override 0x8001=0x0002,0x0005 --override 0x800B=0x0006
  ets_eventgroup_overlay.py --self-test
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile

_BLOCK_OPEN = re.compile(r"^\s*(broadcast|attribute)\s+\w+\s*\{\s*(//.*)?$")
_EVENT_ID = re.compile(r"^\s*SomeIp(?:Event|Notifier)ID\s*=\s*(0[xX][0-9A-Fa-f]+|\d+)\s*(//.*)?$")
_EVENTGROUPS = re.compile(r"^(\s*)SomeIpEventGroups\s*=\s*\{[^}]*\}\s*(//.*)?$")
_RELATIVE_IMPORT = re.compile(r'^(\s*import\s+")([^":]+)(".*)$')
_ID16 = re.compile(r"^(0[xX][0-9A-Fa-f]{1,4}|\d+)$")


class OverlayError(Exception):
    pass


def _parse_id(text: str, what: str) -> int:
    if not _ID16.match(text):
        raise OverlayError(f"{what} '{text}' is not a 16-bit ID (write it as 0x8001 or 32769)")
    value = int(text, 0)
    if value > 0xFFFF:
        raise OverlayError(f"{what} '{text}' does not fit 16 bits")
    return value


def parse_override(spec: str) -> tuple[int, list[int]]:
    """'0x8001=0x0002,0x0005' -> (0x8001, [0x0002, 0x0005])."""
    event, sep, groups = spec.partition("=")
    if not sep:
        raise OverlayError(f"override '{spec}' has no '=' (write <event-id>=<eventgroup>[,<eventgroup>...])")
    event_id = _parse_id(event.strip(), "event ID")
    names = [g.strip() for g in groups.split(",") if g.strip()]
    if not names:
        raise OverlayError(f"override '{spec}' names no eventgroup; an event needs at least one")
    group_ids = [_parse_id(g, "eventgroup ID") for g in names]
    if len(set(group_ids)) != len(group_ids):
        raise OverlayError(f"override '{spec}' names an eventgroup twice")
    return event_id, group_ids


def overlay(text: str, overrides: dict[int, list[int]], import_dir: str) -> str:
    """Return `text` with each overridden block's SomeIpEventGroups line replaced."""
    out: list[str] = []
    applied: set[int] = set()
    seen: set[int] = set()
    in_block = False
    block_id: int | None = None
    groups_line: int | None = None  # index in `out` of the block's SomeIpEventGroups line

    def close_block(line_no: int) -> None:
        if block_id is None or block_id not in overrides:
            return
        if groups_line is None:
            raise OverlayError(
                f"event 0x{block_id:04X} (block ending at line {line_no}) has no "
                "SomeIpEventGroups line to replace")
        indent = _EVENTGROUPS.match(out[groups_line]).group(1)
        listed = ", ".join(f"0x{g:04X}" for g in overrides[block_id])
        out[groups_line] = f"{indent}SomeIpEventGroups = {{ {listed} }}"
        applied.add(block_id)

    for line_no, line in enumerate(text.split("\n"), start=1):
        m = _RELATIVE_IMPORT.match(line)
        if m and not os.path.isabs(m.group(2)):
            line = f"{m.group(1)}{os.path.join(import_dir, m.group(2))}{m.group(3)}"
        if not in_block:
            if _BLOCK_OPEN.match(line):
                in_block, block_id, groups_line = True, None, None
            out.append(line)
            continue
        if line.strip() == "}":
            close_block(line_no)
            in_block = False
            out.append(line)
            continue
        m = _EVENT_ID.match(line)
        if m:
            found = int(m.group(1), 0)
            if found in overrides and found in seen:
                raise OverlayError(f"event 0x{found:04X} is deployed twice")
            seen.add(found)
            block_id = found
        elif _EVENTGROUPS.match(line):
            groups_line = len(out)
        out.append(line)

    if in_block:
        raise OverlayError("the file ends inside an unclosed broadcast/attribute block")
    missing = sorted(set(overrides) - applied)
    if missing:
        raise OverlayError(
            "no broadcast or attribute deploys event ID(s) "
            + ", ".join(f"0x{e:04X}" for e in missing))
    return "\n".join(out)


_SAMPLE = """\
import "platform:/plugin/org.genivi.commonapi.someip/deployment/CommonAPI-SOMEIP_deployment_spec.fdepl"
import "ets.fidl"

define org.genivi.commonapi.someip.deployment for interface org.tc8.ets.EnhancedTestability {
    broadcast TestEventUINT8 {
        SomeIpEventID = 0x8001
        // a comment inside the block
        SomeIpEventGroups = { 0x0002, 0x0005, 0x0006, 0x0008 }
        SomeIpReliable = false
    }

    attribute TestFieldUINT8 {
        SomeIpGetterID   = 0x26
        SomeIpNotifierID = 0x8006
        SomeIpEventGroups = { 0x0002, 0x0005 }
    }

    method getFieldA {
        SomeIpMethodID = 0x40
        in {
            data {
                SomeIpArrayLengthWidth = 4
            }
        }
    }
}
"""


def self_test() -> int:
    failures: list[str] = []

    def expect(cond: bool, what: str) -> None:
        if not cond:
            failures.append(what)

    got = overlay(_SAMPLE, {0x8001: [0x0002, 0x0005]}, "/abs/dir")
    expect("        SomeIpEventGroups = { 0x0002, 0x0005 }\n        SomeIpReliable" in got,
           "0x8001 membership not replaced in place")
    expect("SomeIpNotifierID = 0x8006\n        SomeIpEventGroups = { 0x0002, 0x0005 }" in got,
           "an attribute the override did not name was changed")
    expect('import "/abs/dir/ets.fidl"' in got, "relative import not made absolute")
    expect('import "platform:/plugin/' in got, "platform: import was rewritten")
    expect(overlay(_SAMPLE, {}, "/abs/dir").replace('/abs/dir/', '') == _SAMPLE,
           "an empty override set changed more than the import")

    got = overlay(_SAMPLE, {0x8006: [0x0002]}, "/d")
    expect("SomeIpNotifierID = 0x8006\n        SomeIpEventGroups = { 0x0002 }" in got,
           "an attribute notifier was not addressable by its notifier ID")

    try:
        overlay(_SAMPLE, {0x8099: [0x0002]}, "/d")
        failures.append("an unknown event ID was accepted")
    except OverlayError:
        pass
    twice = _SAMPLE.replace("SomeIpNotifierID = 0x8006", "SomeIpNotifierID = 0x8001")
    try:
        overlay(twice, {0x8001: [0x0002]}, "/d")
        failures.append("an event deployed twice was accepted")
    except OverlayError:
        pass
    no_groups = _SAMPLE.replace("        SomeIpEventGroups = { 0x0002, 0x0005 }\n    }",
                                "    }")
    try:
        overlay(no_groups, {0x8006: [0x0002]}, "/d")
        failures.append("a block without SomeIpEventGroups was accepted")
    except OverlayError:
        pass
    for spec in ("0x8001", "0x8001=", "0x8001=0x2,0x2", "0x18001=0x2", "x=0x2", "0x8001=nope"):
        try:
            parse_override(spec)
            failures.append(f"override '{spec}' was accepted")
        except OverlayError:
            pass
    expect(parse_override(" 0x800B = 0x0006 ") == (0x800B, [0x0006]), "spaced override misread")

    # The CLI writes the file it is asked for and refuses a duplicate override.
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "in.fdepl")
        dst = os.path.join(tmp, "out.fdepl")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(_SAMPLE)
        expect(main(["--in", src, "--out", dst, "--override", "0x8001=0x0006"]) == 0, "CLI failed")
        with open(dst, encoding="utf-8") as fh:
            expect("SomeIpEventGroups = { 0x0006 }" in fh.read(), "CLI output lacks the override")
        expect(main(["--in", src, "--out", dst, "--override", "0x8001=0x2",
                     "--override", "0x8001=0x5"]) == 2, "duplicate override accepted")

    for failure in failures:
        print(f"ets_eventgroup_overlay self-test: FAIL: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("ets_eventgroup_overlay self-test: OK")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--in", dest="src")
    parser.add_argument("--out", dest="dst")
    parser.add_argument("--override", action="append", default=[],
                        help="<event-id>=<eventgroup>[,<eventgroup>...], repeatable")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.src or not args.dst or not args.override:
        parser.error("--in, --out and at least one --override are required")
    try:
        overrides: dict[int, list[int]] = {}
        for spec in args.override:
            event_id, groups = parse_override(spec)
            if event_id in overrides:
                raise OverlayError(f"event 0x{event_id:04X} is overridden twice")
            overrides[event_id] = groups
        with open(args.src, encoding="utf-8") as fh:
            text = fh.read()
        result = overlay(text, overrides, os.path.dirname(os.path.abspath(args.src)))
    except (OverlayError, OSError) as exc:
        print(f"ets_eventgroup_overlay: {exc}", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(os.path.abspath(args.dst)), exist_ok=True)
    with open(args.dst, "w", encoding="utf-8") as fh:
        fh.write(result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
