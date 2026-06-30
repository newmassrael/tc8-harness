#!/usr/bin/env python3
"""Validate that every `--expect` key the producers emit is present in the
schema SSOT src/cli/tc8_expect_keys.def.

The C++ consumer (src/cli/expect_parser.cpp) is GENERATED from that .def, so it
accepts exactly the registry's key set and cannot drift or omit. The producers
stay hand-written — they map keys to deployment values (vsomeip.json paths, bash
vars), which is not the schema's concern — so this gate is their guard: a
producer that emits a key absent from the registry would have that field
silently dropped by the consumer to its zero sentinel, a false-pass risk. CI
runs this as a freshness gate. See docs/tech-debt.md TD-03.

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

# Producer emit patterns.
_RUST_RE = re.compile(r'ex\(&mut e,\s*"([a-z0-9_.]+)"')
_BASH_RE = re.compile(r'--expect\s+"([a-z0-9_.]+)=')
_PYID_RE = re.compile(r'"([a-z0-9_]+)":\s*_require\(')


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


def extract(path: Path, pattern: re.Pattern, label: str) -> set[str]:
    found = set(pattern.findall(path.read_text(encoding="utf-8")))
    if not found:
        sys.exit(f"check_expect_keys: extracted 0 keys from {label} ({path.name}) "
                 f"— the emit pattern changed; fix this checker before trusting it")
    return found


def main() -> int:
    registry = parse_registry()
    producers = {
        "Rust (dispatch.rs)": extract(RUST, _RUST_RE, "Rust"),
        "bash (smoke-test.sh)": extract(BASH, _BASH_RE, "bash"),
        "Python (dut_identity.py)": extract(PYID, _PYID_RE, "Python"),
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
