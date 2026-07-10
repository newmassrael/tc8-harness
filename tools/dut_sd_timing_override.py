#!/usr/bin/env python3
"""Derive a per-case DUT vsomeip.json by PATCHING its service-discovery timers.

A conformance case may declare a DUT-configuration precondition: a specific
`service-discovery` start-up timer value the case needs (e.g. a case may require a
particular initial_delay the global config does not set). The DUT is brought up with
one vsomeip config per invocation, so a set of mutually-incompatible per-case timer
preconditions cannot all be honoured by a single global config. This tool lets the
runner provision the DUT with the precondition config FOR THAT CASE's run: it reads
the ACTIVE base config and writes a copy with only the named `service-discovery`
fields overridden.

It PATCHES the active base (composition), it does not swap to a fixed file. So it
composes with whatever base the caller resolved — the plain reference vsomeip.json, a
services[] variant (vsomeip-multi-*.json), or a deployment-DERIVED config — WITHOUT
dropping anything else the base declared (services, events, eventgroups). And the set
of overridable fields is DERIVED from the base too: a field is overridable iff the
base's `service-discovery` block already declares it, so the tool hard-codes no field
list to drift from the base or from the identity deriver (tools/dut_identity.py). A
non-negative integer value is required, so the block's string fields (enable,
multicast, protocol) cannot be set this way; the intended targets are the start-up
timers (initial_delay_min/max, repetitions_base_delay, repetitions_max,
cyclic_offer_delay, ttl), though any integer-valued field the base declares (e.g. the
SD port) is reachable — the map is deployment-owned config, not a silent capability.

The override DATA is not owned here — a deployment declares it (which case gets which
timers). This tool is the pure transform the runner calls; the case->timers map is
supplied by the caller (smoke-test.sh reads it from the sourced --topology-conf
overlay's TC8_TOPOLOGY_DUT_SD_TIMING array). Keeping the map with the deployment keeps
case-specific config out of the shared harness.

Usage:
    dut_sd_timing_override.py <base.json> <out.json> KEY=VALUE [KEY=VALUE ...]
        Write <out.json> = <base.json> with the named service-discovery fields set.
    dut_sd_timing_override.py --validate <base.json> KEY=VALUE [KEY=VALUE ...]
        Validate the overrides against the base WITHOUT writing (dry-run apply);
        exit non-zero on any malformed/unknown/bad-value token. Used by the runner
        to fail-fast at overlay load instead of per-case.
    dut_sd_timing_override.py --self-test
        Run the built-in unit checks (CI gate) and exit.

VALUE is a non-negative integer (vsomeip stores these as JSON strings, so it is
written as a string, matching the base's own encoding). A malformed token, a KEY the
base's service-discovery block does not declare, a non-integer VALUE, or a base with
no service-discovery block is a fail-loud error (a precondition typo must not silently
no-op).
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path

SD_BLOCK = "service-discovery"


class OverrideError(ValueError):
    """A malformed override request (bad token, unknown field, or unusable base)."""


def parse_override(token: str) -> tuple[str, str]:
    """Split one `KEY=VALUE` token, validating the value is a non-negative integer.

    Returns (key, value_as_string). Raises OverrideError on a token without '=', an
    empty key, or a value that is not a non-negative integer. Whether KEY is an
    overridable field is decided against the base in apply_overrides (derive-from-
    base), not here.
    """
    if "=" not in token:
        raise OverrideError(f"override '{token}' is not KEY=VALUE")
    key, _, value = token.partition("=")
    key = key.strip()
    value = value.strip()
    if not key:
        raise OverrideError(f"override '{token}' has an empty key")
    # vsomeip stores these as strings, but they are integer milliseconds/counts.
    # Guard with isascii() as well as isdigit(): str.isdigit() is True for non-ASCII
    # digit scripts (e.g. superscripts, Arabic-Indic) that int()/vsomeip cannot
    # parse, so a value like "²" would otherwise slip through as an unparsable
    # timer — exactly the fail-loud contract this check exists to keep.
    if not (value.isascii() and value.isdigit()):
        raise OverrideError(
            f"field '{key}' value '{value}' is not a non-negative integer"
        )
    return key, value


def apply_overrides(base: dict, overrides: list[str]) -> dict:
    """Return a copy of `base` with the given `service-discovery` fields patched.

    A field is overridable iff the base's service-discovery block already declares it
    (derive-from-base: no hard-coded field list to drift). Every field of `base` other
    than the named ones is preserved verbatim, so the result stays a superset of the
    base (composition, never a lossy swap).
    """
    sd = base.get(SD_BLOCK)
    if not isinstance(sd, dict):
        raise OverrideError(
            f"base config has no '{SD_BLOCK}' block to override "
            "(cannot apply an SD-timing precondition)"
        )
    if not overrides:
        raise OverrideError("no KEY=VALUE overrides given")
    result = json.loads(json.dumps(base))  # deep copy without mutating the input
    for token in overrides:
        key, value = parse_override(token)
        if key not in sd:
            raise OverrideError(
                f"'{key}' is not a field of the base '{SD_BLOCK}' block "
                f"(declared: {', '.join(sorted(sd))}) — typo, or add it to the base"
            )
        result[SD_BLOCK][key] = value
    return result


def main(argv: list[str]) -> int:
    if len(argv) == 1 and argv[0] == "--self-test":
        return _self_test()

    validate_only = bool(argv) and argv[0] == "--validate"
    if validate_only:
        argv = argv[1:]
        if len(argv) < 2:
            sys.stderr.write(
                "usage: dut_sd_timing_override.py --validate <base.json> KEY=VALUE ...\n"
            )
            return 2
        base_path, overrides = Path(argv[0]), argv[1:]
        out_path = None
    else:
        if len(argv) < 3:
            sys.stderr.write(
                "usage: dut_sd_timing_override.py <base.json> <out.json> "
                "KEY=VALUE [KEY=VALUE ...]\n"
                "       dut_sd_timing_override.py --validate <base.json> KEY=VALUE ...\n"
                "       dut_sd_timing_override.py --self-test\n"
            )
            return 2
        base_path, out_path, overrides = Path(argv[0]), Path(argv[1]), argv[2:]

    try:
        base = json.loads(base_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"dut_sd_timing_override: cannot read base '{base_path}': {exc}\n")
        return 1
    try:
        patched = apply_overrides(base, overrides)
    except OverrideError as exc:
        sys.stderr.write(f"dut_sd_timing_override: {exc}\n")
        return 1
    if validate_only:
        return 0
    try:
        out_path.write_text(json.dumps(patched, indent=4) + "\n")
    except OSError as exc:
        sys.stderr.write(f"dut_sd_timing_override: cannot write '{out_path}': {exc}\n")
        return 1
    return 0


def _self_test() -> int:
    """Built-in unit checks for the transform, run as a CI gate.

    This is an inline UNIT test of this tool's own logic (not a cross-file drift/
    freshness gate like the generator --check gates): it exercises the transform on
    synthetic configs and asserts its composition/validation guarantees, including the
    fail-loud paths the runtime wiring depends on. Values below are arbitrary, chosen
    only to test the transform property (a patched value overwrites the base; distinct
    values round-trip); they carry no case-precondition meaning.
    """
    base = {
        "unicast": "10.0.0.2",
        SD_BLOCK: {
            "enable": "true",
            "initial_delay_min": "10",
            "initial_delay_max": "20",
            "repetitions_base_delay": "30",
            "cyclic_offer_delay": "40",
        },
        "services": [{"service": "0x1234", "instance": "0x0001"}],
    }

    # 1. Patches only the named fields; leaves every other field (incl. sibling SD
    #    fields and the whole services[] block) untouched — composition, not swap.
    out = apply_overrides(base, ["initial_delay_min=7", "initial_delay_max=7"])
    assert out[SD_BLOCK]["initial_delay_min"] == "7", out
    assert out[SD_BLOCK]["initial_delay_max"] == "7", out
    assert out[SD_BLOCK]["cyclic_offer_delay"] == "40", out  # sibling untouched
    assert out[SD_BLOCK]["enable"] == "true", out
    assert out["services"] == base["services"], out  # derived base content preserved
    assert base[SD_BLOCK]["initial_delay_min"] == "10", "input must not be mutated"

    # 2. Two distinct values both round-trip; a patched value overwrites the base.
    out = apply_overrides(base, ["initial_delay_min=13", "initial_delay_max=41"])
    assert (out[SD_BLOCK]["initial_delay_min"], out[SD_BLOCK]["initial_delay_max"]) == (
        "13",
        "41",
    ), out

    # 3. Token without '=', empty key, non-integer / non-ASCII-digit value all fail
    #    loud. "²" is str.isdigit()==True but not int-parsable — must be rejected.
    for bad in ["initial_delay_min", "=5", "initial_delay_min=40ms",
                "initial_delay_min=-1", "initial_delay_min=²"]:
        try:
            apply_overrides(base, [bad])
        except OverrideError:
            pass
        else:  # pragma: no cover - only reached on a regression
            print(f"self-test FAIL: '{bad}' was not rejected", file=sys.stderr)
            return 1

    # 4. A field the base does not declare is a fail-loud typo guard (derive-from-base).
    try:
        apply_overrides(base, ["initial_delay_mn=7"])
    except OverrideError:
        pass
    else:  # pragma: no cover
        print("self-test FAIL: unknown field was not rejected", file=sys.stderr)
        return 1

    # 5. A base with no service-discovery block is a fail-loud setup error.
    try:
        apply_overrides({"services": []}, ["initial_delay_min=7"])
    except OverrideError:
        pass
    else:  # pragma: no cover
        print("self-test FAIL: missing SD block was not rejected", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as d:
        b, o = Path(d) / "base.json", Path(d) / "out.json"
        b.write_text(json.dumps(base))

        # 6. End-to-end through the file interface (the path the runner uses).
        rc = main([str(b), str(o), "initial_delay_min=7", "initial_delay_max=7"])
        assert rc == 0, rc
        reloaded = json.loads(o.read_text())
        assert reloaded[SD_BLOCK]["initial_delay_min"] == "7", reloaded
        assert reloaded["services"] == base["services"], reloaded

        # 7. main()'s fail-loud branch (the contract the runtime abort depends on):
        #    a bad token returns 1 and writes NO output file. 8. --validate is a
        #    dry-run apply: same reject, writes nothing. (stderr of the expected-fail
        #    calls is captured so the passing gate log stays clean.)
        o2 = Path(d) / "out2.json"
        with contextlib.redirect_stderr(io.StringIO()):
            assert main([str(b), str(o2), "initial_delay_mn=7"]) == 1
            assert main(["--validate", str(b), "initial_delay_min=7"]) == 0
            assert main(["--validate", str(b), "initial_delay_mn=7"]) == 1
        assert not o2.exists(), "no output file must be written on a failed override"

    print("dut_sd_timing_override self-test: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
