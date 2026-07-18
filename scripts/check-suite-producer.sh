#!/usr/bin/env bash
# Ratchet for the out-of-tree suite producer (CMakeLists.txt tc8_add_case +
# TC8_EXTRA_CASE_SUITES). Builds the harness with examples/demo-suite injected
# under suite "demo" — which deliberately reuses the in-tree case id
# SOMEIPSRV_OPTIONS_01 — and asserts both the in-tree and the demo case coexist.
# This transitively exercises every (suite, id) layer: the codegen namespace
# nesting (a stale sce-codegen fails the configure-time probe), the suite-aware
# collision check, the per-suite register stub, and the registry/CLI grouping.
#
# Kept OUT of the normal conformance build (the demo case is a phantom
# always-inconclusive fixture); run explicitly here / in CI.
#
# Usage: scripts/check-suite-producer.sh [build-dir] [jobs]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-${repo_root}/build-suite-producer-check}"
jobs="${2:-4}"

echo "[suite-producer] configuring ${build_dir} with examples/demo-suite (suite=demo)"
# -DTC8_SCE_FIND_PACKAGE=OFF matches both CI jobs (embed the vendored SCE);
# MOCK_DUT/UNIT_TESTS OFF keep this to a harness-only build. CMAKE_EXTRA_ARGS
# lets a caller append environment-specific flags (e.g. CMAKE_PREFIX_PATH-driven).
cmake -S "${repo_root}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DTC8_SCE_FIND_PACKAGE=OFF \
    -DTC8_BUILD_MOCK_DUT=OFF \
    -DTC8_BUILD_UNIT_TESTS=OFF \
    -DTC8_EXTRA_CASE_DIRS="${repo_root}/examples/demo-suite" \
    -DTC8_EXTRA_CASE_SUITES="demo" \
    ${CMAKE_EXTRA_ARGS:-}

echo "[suite-producer] building tc8-harness (-j${jobs})"
cmake --build "${build_dir}" --target tc8-harness -j"${jobs}"

echo "[suite-producer] asserting (suite, id) coexistence via --list-cases"
listing="$("${build_dir}/tc8-harness" test --list-cases)"

fail=0
if ! grep -q "^== suite: demo ==" <<<"${listing}"; then
    echo "[suite-producer] FAIL: no '== suite: demo ==' banner" >&2
    fail=1
fi
if ! grep -q "demo:SOMEIPSRV_OPTIONS_01" <<<"${listing}"; then
    echo "[suite-producer] FAIL: demo:SOMEIPSRV_OPTIONS_01 not registered" >&2
    fail=1
fi
# The bare in-tree case must still be present (the qualified one must NOT have
# displaced it) — match it as a line that is the id without a 'demo:' prefix.
if ! grep -qE "^  SOMEIPSRV_OPTIONS_01[[:space:]]" <<<"${listing}"; then
    echo "[suite-producer] FAIL: in-tree SOMEIPSRV_OPTIONS_01 missing" >&2
    fail=1
fi

# Regression: the smoke-test id extractor (dut/env/list-cases-ids.awk) must
# survive the qualified `demo:` prefix. A charset anchor (`^  [A-Z]`) silently
# dropped every non-default-suite id, breaking N1 per-case SD-timing overrides
# and secondary-iface detection for any injected suite. Run the REAL listing
# through the SSOT filter and assert both the qualified and bare ids come out.
ids="$(awk -f "${repo_root}/dut/env/list-cases-ids.awk" <<<"${listing}")"
if ! grep -qxF "demo:SOMEIPSRV_OPTIONS_01" <<<"${ids}"; then
    echo "[suite-producer] FAIL: list-cases-ids.awk dropped qualified id demo:SOMEIPSRV_OPTIONS_01" >&2
    fail=1
fi
if ! grep -qxF "SOMEIPSRV_OPTIONS_01" <<<"${ids}"; then
    echo "[suite-producer] FAIL: list-cases-ids.awk dropped bare id SOMEIPSRV_OPTIONS_01" >&2
    fail=1
fi

if [[ ${fail} -ne 0 ]]; then
    echo "[suite-producer] FAILED — (suite, id) coexistence regressed" >&2
    exit 1
fi
echo "[suite-producer] OK — tc8:SOMEIPSRV_OPTIONS_01 and demo:SOMEIPSRV_OPTIONS_01 coexist"
