#!/usr/bin/env python3
"""Generate the Rust mirror of the base `--expect` identity surface from the
single source tools/expect_surface.def (docs/tech-debt.md TD-12). The Rust
tc8-orchestrator is the sole test driver; the retired bash smoke driver's Bash
mirror was dropped, leaving the .def as the structured single source for the gen.

Run with no args to (re)write the generated files; run with --check to verify
they are up to date (CI / pre-commit freshness gate, mirrors
gen_wire_manifest.py).

Outputs:
  dut/env/orchestrator/src/expect_surface.gen.rs   include!-d into dispatch.rs;
                                                   append_someip_identity /
                                                   append_l2l3_identity + RUNTIME_MAC_KEYS
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEF = ROOT / "tools/expect_surface.def"
RS_OUT = ROOT / "dut/env/orchestrator/src/expect_surface.gen.rs"

_DOC_RE = re.compile(r"^\s*///\s?(.*)$")
_BUCKET_RE = re.compile(
    r"^TC8_EXPECT_BUCKET\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(someip|l2l3)\s*,"
    r"\s*(static|runtime)\s*\)\s*$"
)
_ROW_RE = re.compile(
    r"^TC8_EXPECT_ROW\(\s*(\w+)\s*,\s*([\w.]+)\s*,\s*(\w+)\s*,\s*([\w-]+)\s*\)\s*$"
)

# source kinds that name a vsomeip field / wire constant in `ref`; the rest carry
# `-` (their value expression is fixed per language).
_REF_SOURCES = {"vs_id", "vs_sd", "wire", "wire_alias"}
_NOREF_SOURCES = {"dut_ip", "tester_ip", "dut_mac"}
_SOURCES = _REF_SOURCES | _NOREF_SOURCES


class Bucket:
    __slots__ = ("id", "bash_array", "rust_fn", "kind")

    def __init__(self, id_, bash_array, rust_fn, kind):
        self.id = id_
        self.bash_array = bash_array
        self.rust_fn = rust_fn
        self.kind = kind


class Row:
    __slots__ = ("bucket", "key", "source", "ref", "docs")

    def __init__(self, bucket, key, source, ref, docs):
        self.bucket = bucket
        self.key = key
        self.source = source
        self.ref = ref
        self.docs = docs  # list[str], the `///` lines preceding this row


def parse() -> tuple[list[Bucket], list[Row]]:
    buckets: list[Bucket] = []
    rows: list[Row] = []
    pending: list[str] = []
    for line in DEF.read_text(encoding="utf-8").splitlines():
        m = _DOC_RE.match(line)
        if m is not None:
            pending.append(m.group(1).rstrip())
            continue
        m = _BUCKET_RE.match(line)
        if m is not None:
            buckets.append(Bucket(m.group(1), m.group(2), m.group(3), m.group(4)))
            pending = []
            continue
        m = _ROW_RE.match(line)
        if m is not None:
            rows.append(Row(m.group(1), m.group(2), m.group(3), m.group(4), pending))
            pending = []
            continue
        # A line INTENDING to be a directive but unparseable is a fat-fingered SSOT
        # line — fail loud, never silently drop it (a dropped row vanishes from both
        # generated drivers while the `if not rows` guard stays green).
        stripped = line.lstrip()
        if stripped.startswith("TC8_EXPECT_"):
            sys.exit(f"gen_expect_surface: malformed directive: {line!r}")
        # Any other line (blank, '//' prose, separator) breaks doc adjacency.
        pending = []
    if not buckets or not rows:
        sys.exit("gen_expect_surface: parsed 0 buckets or 0 rows — bad expect_surface.def")
    _validate(buckets, rows)
    return buckets, rows


def _validate(buckets: list[Bucket], rows: list[Row]) -> None:
    bucket_ids = {b.id for b in buckets}
    for r in rows:
        if r.bucket not in bucket_ids:
            sys.exit(f"gen_expect_surface: row key '{r.key}' names unknown bucket "
                     f"'{r.bucket}'")
        if r.source not in _SOURCES:
            sys.exit(f"gen_expect_surface: row key '{r.key}' has unknown source "
                     f"'{r.source}' (want {sorted(_SOURCES)})")
        has_ref = r.ref != "-"
        if r.source in _REF_SOURCES and not has_ref:
            sys.exit(f"gen_expect_surface: source '{r.source}' on key '{r.key}' "
                     f"needs a ref, got '-'")
        if r.source in _NOREF_SOURCES and has_ref:
            sys.exit(f"gen_expect_surface: source '{r.source}' on key '{r.key}' "
                     f"takes no ref, got '{r.ref}'")


# --- Rust render ------------------------------------------------------------
def _rust_value(r: Row) -> str:
    if r.source == "vs_id":
        return f"&id.{r.ref}"
    if r.source == "vs_sd":
        return f"&t.{r.ref}"
    if r.source == "wire":
        return f"wire::{r.ref}"
    if r.source == "wire_alias":
        # An alias the SITE may override, so it reads a Config field rather than
        # the wire constant directly. `Config` seeds that field FROM the same
        # wire constant, so a run with no override emits the identical value and
        # the --print-expect parity dump is unchanged. Field name is derived, not
        # listed: DUT_ALIAS_IP -> cfg.dut_alias_ip4, matching the dut_ip4 /
        # tester_ip4 spelling of the other site-overridable addresses.
        return f"&cfg.{r.ref.lower()}4"
    if r.source == "dut_ip":
        return "&cfg.dut_ip4"
    if r.source == "tester_ip":
        return "&cfg.tester_ip4"
    if r.source == "dut_mac":
        return "dut_mac"
    raise AssertionError(r.source)


def _rust_fn(name: str, params: str, rows: list[Row]) -> list[str]:
    body = [f"fn {name}({params}) {{"]
    if any(r.source == "vs_id" for r in rows):
        body.append("    let id = &cfg.identity;")
    if any(r.source == "vs_sd" for r in rows):
        body.append("    let t = &cfg.sd_timing;")
    for r in rows:
        for d in r.docs:
            body.append(("    // " + d).rstrip())
        body.append(f'    ex(e, "{r.key}", {_rust_value(r)});')
    body.append("}")
    return body


def render_rs(buckets: list[Bucket], rows: list[Row]) -> str:
    lines = [
        "// GENERATED by tools/gen_expect_surface.py from",
        "// tools/expect_surface.def — DO NOT EDIT.",
        "// Regenerate: python3 tools/gen_expect_surface.py",
        "//",
        "// include!-d into dispatch.rs (uses its `ex` helper, the `wire` module, and",
        "// `Config`). The base --expect identity surface, single-sourced with bash's",
        "// tc8_expect_<bucket> functions so the two drivers cannot drift (TD-12). The",
        "// --topology-conf extra_expect fold is spliced by expect_args BETWEEN these",
        "// two appenders; the runtime DUT-MAC rows are filtered from the parity dump",
        "// via RUNTIME_MAC_KEYS.",
        "",
    ]
    someip_rows = [r for r in rows if _bucket_of(buckets, r.bucket).rust_fn == "someip"]
    l2l3_rows = [r for r in rows if _bucket_of(buckets, r.bucket).rust_fn == "l2l3"]

    lines.extend(_rust_fn("append_someip_identity",
                          "e: &mut Vec<String>, cfg: &Config", someip_rows))
    lines.append("")
    lines.extend(_rust_fn("append_l2l3_identity",
                          "e: &mut Vec<String>, cfg: &Config, dut_mac: &str", l2l3_rows))
    lines.append("")

    mac_keys = [r.key for r in rows
                if _bucket_of(buckets, r.bucket).kind == "runtime"]
    lines.append("/// The per-worker DUT-MAC `--expect` keys (kernel-assigned veth MAC,")
    lines.append("/// different per run and per driver) — filtered from the static")
    lines.append("/// `--print-expect` parity dump by `print_static_identity`.")
    keys = ", ".join(f'"{k}"' for k in mac_keys)
    lines.append(f"const RUNTIME_MAC_KEYS: [&str; {len(mac_keys)}] = [{keys}];")
    lines.append("")
    return "\n".join(lines)


def _bucket_of(buckets: list[Bucket], bid: str) -> Bucket:
    for b in buckets:
        if b.id == bid:
            return b
    raise AssertionError(bid)


def main() -> int:
    check = "--check" in sys.argv[1:]
    buckets, rows = parse()
    outputs = {RS_OUT: render_rs(buckets, rows)}
    rel = lambda p: p.relative_to(ROOT)

    stale = []
    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current != content:
            stale.append(path)
            if not check:
                path.write_text(content, encoding="utf-8")

    if check:
        if stale:
            print("STALE generated files (run: python3 tools/gen_expect_surface.py):")
            for p in stale:
                print(f"  {rel(p)}")
            return 1
        print("expect surface generated files are up to date")
        return 0

    for p in outputs:
        print(f"wrote {rel(p)}" if p in stale else f"unchanged {rel(p)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
