#!/usr/bin/env python3
"""Validate that every `--expect` key the producers emit is present in the
schema SSOT src/cli/tc8_expect_keys.def.

The C++ consumer (src/cli/expect_parser.cpp) is GENERATED from that .def, so it
structurally accepts exactly the registry's key set — it cannot drift from nor
omit a key. The producers stay hand-written (they map keys to deployment
values — vsomeip.json paths, bash vars — which is not the schema's concern), so
this gate is their static guard: a producer that emits a key ABSENT from the
registry would have that field silently dropped by the consumer to its zero
sentinel, a false-pass. CI runs it as a freshness gate. See docs/tech-debt.md
TD-03.

Scope (honest): this is a STATIC key-literal scan. It catches a producer
emitting an out-of-registry key; it does NOT catch a producer FORGETTING to
emit a key a guard needs (that producer-side omission leaves the field at 0 and
stays a per-scenario test-authoring concern). The actual emitted key SETS are
additionally diffed at runtime by dut/env/parity-check.sh.

Producers checked (key NAMES only; their values/parity are checked elsewhere by
config_test.rs and parity-check.sh):
  * Rust orchestrator  dut/env/orchestrator/src/dispatch.rs   (ex(&mut e, "k", v))
  * bash smoke driver  dut/env/smoke-test.sh                  (--expect "k=...")
  * Python identity    tools/dut_identity.py                  ("k": _require(...))

Exits non-zero listing any producer key not in the registry.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEF = ROOT / "src/cli/tc8_expect_keys.def"
RUST = ROOT / "dut/env/orchestrator/src/dispatch.rs"
BASH = ROOT / "dut/env/smoke-test.sh"
PYID = ROOT / "tools/dut_identity.py"

_GROUP_RE = re.compile(r"^TC8_EXPECT_GROUP\(\s*(\w+)\s*,\s*\"([^\"]*)\"\s*\)$")
_KEY_RE = re.compile(r"^TC8_EXPECT_KEY\(\s*(\w+)\s*,\s*\w+\s*,\s*(\w+)\s*\)$")
_PAYLOAD_RE = re.compile(r"^TC8_EXPECT_PAYLOAD\(\s*(\w+)\s*,\s*(\w+)\s*\)$")

# Producer key-literal patterns. A producer key is always written as a string
# LITERAL somewhere, even when its value is interpolated — so these capture the
# producer's key SET regardless of the surrounding call shape. The Rust side
# emits via both ex(&mut e, "k", v) and .push(format!("k={v}")); both forms are
# matched. Runtime-flipped tokens (the --negative harness's `--expect "$tok"`)
# reuse keys already present as literals, and the actual emitted sets are
# additionally diffed at runtime by parity-check.sh, so this static scan is not
# the only producer guard.
_RUST_EX_RE = re.compile(r'ex\(&mut e,\s*"([a-z0-9_.]+)"')
_RUST_FMT_RE = re.compile(r'push\(format!\("([a-z0-9_.]+)=')
_BASH_RE = re.compile(r'--expect\s+"([a-z0-9_.]+)=')
_PYID_RE = re.compile(r'"([a-z0-9_.]+)":\s*_require\(')


def parse_registry() -> set[str]:
    """Return the flat set of valid `--expect` key tokens (prefix + key)."""
    prefixes: dict[str, str] = {}
    keys: list[tuple[str, str]] = []  # (group, name)
    for raw in DEF.read_text(encoding="utf-8").splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line or line.startswith("#") or not line.startswith("TC8_EXPECT_"):
            continue
        m = _GROUP_RE.match(line)
        if m is not None:
            prefixes[m.group(1)] = m.group(2)
            continue
        m = _KEY_RE.match(line)
        if m is not None:
            keys.append((m.group(1), m.group(2)))
            continue
        m = _PAYLOAD_RE.match(line)
        if m is not None:
            keys.append((m.group(1), m.group(2)))
            continue
        sys.exit(f"check_expect_keys: malformed .def row: {raw!r}")
    if not prefixes or not keys:
        sys.exit("check_expect_keys: parsed an incomplete schema — bad .def")
    flat: set[str] = set()
    for group, name in keys:
        if group not in prefixes:
            sys.exit(f"check_expect_keys: key group '{group}' has no TC8_EXPECT_GROUP")
        flat.add(prefixes[group] + name)
    return flat


def extract(path: Path, patterns: list[re.Pattern], label: str) -> set[str]:
    text = path.read_text(encoding="utf-8")
    found: set[str] = set()
    for pat in patterns:
        found |= set(pat.findall(text))
    if not found:
        sys.exit(f"check_expect_keys: extracted 0 keys from {label} ({path.name}) "
                 f"— the emit pattern changed; fix this checker before trusting it")
    return found


def main() -> int:
    registry = parse_registry()
    producers = {
        "Rust (dispatch.rs)": extract(RUST, [_RUST_EX_RE, _RUST_FMT_RE], "Rust"),
        "bash (smoke-test.sh)": extract(BASH, [_BASH_RE], "bash"),
        "Python (dut_identity.py)": extract(PYID, [_PYID_RE], "Python"),
    }
    rc = 0
    for label, keys in producers.items():
        stray = sorted(keys - registry)
        if stray:
            rc = 1
            print(f"{label}: emits key(s) absent from tc8_expect_keys.def "
                  f"(the consumer would silently drop them):")
            for k in stray:
                print(f"  {k}")
    if rc == 0:
        total = sum(len(k) for k in producers.values())
        print(f"check_expect_keys: {total} producer keys all present in the "
              f"{len(registry)}-key registry")
    return rc


if __name__ == "__main__":
    sys.exit(main())
