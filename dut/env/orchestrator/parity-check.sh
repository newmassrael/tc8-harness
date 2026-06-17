#!/usr/bin/env bash
# Strangler parity gate — run the same cases through bash smoke-test.sh and the
# Rust tc8-orchestrator, then diff the per-case disposition. Behavioral
# equivalence is the SOLE precondition for ever deleting smoke-test.sh, so this
# is the mechanism that turns "looks right" into evidence. Run it as stages land
# and before any cutover; a mismatch means the orchestrator diverged from the
# SSOT it replaces.
#
# Usage:
#   dut/env/orchestrator/parity-check.sh [CASE ...]
#
# Both drivers need root (netns); each is invoked via `sudo -n` on its NOPASSWD
# path (smoke-test.sh + tc8-orchestrator), so the script itself runs unprivileged.
# Runs each driver at --workers 1 so per-case attribution is unambiguous. Must
# NOT run while a CI netns sweep is in flight (shared netns names) — the
# self-hosted runner is this host.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SMOKE="$ROOT/dut/env/smoke-test.sh"
ORCH="$HERE/target/debug/tc8-orchestrator"

# Default case set: positive categories the orchestrator implements today
# (ARP / ICMPv4) that need NO per-case expectation override.
#
# Conditioning boundary: the bring-up sysctls (arp_accept, delay_first_probe,
# ucast_solicit, ...) ARE covered, and since S3 they are a REAL parity surface —
# bash builds the fixture via setup-netns.sh while the orchestrator builds it via
# the native `netns` module, so e.g. ARP_05 (arp_accept=1) passing on both sides
# is evidence the port reproduced that sysctl, not a tautology. What the
# orchestrator does NOT yet port is the PER-CASE DUT neigh flush bash does in
# run_case (smoke-test.sh:907) before each case. That only diverges when a
# worker's bucket holds >1 ARP case or runs a cold-cache ARP_07..15 as a
# non-first case; ARP_03 / ICMPv4_TYPE_08 at workers=1 × 1-case are
# flush-independent. Grow this set toward those once the conditioning stage
# lands the flush.
CASES=("$@")
if [[ ${#CASES[@]} -eq 0 ]]; then
    CASES=(ICMPv4_TYPE_08 ARP_03)
fi

[[ -x "$SMOKE" ]] || { echo "parity-check: smoke-test.sh not found at $SMOKE" >&2; exit 2; }
[[ -x "$ORCH" ]]  || { echo "parity-check: orchestrator not built at $ORCH (cargo build)" >&2; exit 2; }

# Normalize a driver's per-case stdout line to a canonical disposition token.
# Both drivers print `[wN] <DISP> <CASE> ...`; bash uses one SKIP for both
# deterministic skips and non-conclusions (the reason prefix disambiguates),
# the orchestrator prints SKIP vs SKIP*. Unified mapping covers both.
#   $1 = full driver output   $2 = case id
disposition() {
    local out=$1 case=$2 line
    line=$(grep -E "\[w[0-9]+\] (PASS|FAIL|SKIP\*?) ${case}([^A-Za-z0-9_]|$)" <<<"$out" | head -1)
    if [[ -z "$line" ]]; then echo "ABSENT"; return; fi
    case "$line" in
        *" FAIL "*) echo "FAIL" ;;
        *" PASS "*) echo "PASS" ;;
        *" SKIP* "*) echo "NONCONC" ;;
        *" SKIP "*)
            if [[ "$line" =~ (inconclusive|error): ]]; then echo "NONCONC"; else echo "SKIP"; fi ;;
        *) echo "UNKNOWN" ;;
    esac
}

echo "parity-check: ${#CASES[@]} case(s) — bash smoke-test.sh vs tc8-orchestrator"
mismatches=0
printf '%-28s %-10s %-10s %s\n' CASE BASH ORCH RESULT
printf '%-28s %-10s %-10s %s\n' ---- ---- ---- ------

for case in "${CASES[@]}"; do
    bash_out=$(sudo -n "$SMOKE" --workers 1 "$case" 2>&1)
    orch_out=$(sudo -n "$ORCH" --workers 1 "$case" 2>&1)
    bd=$(disposition "$bash_out" "$case")
    od=$(disposition "$orch_out" "$case")
    if [[ "$bd" == "$od" && "$bd" != ABSENT && "$bd" != UNKNOWN ]]; then
        result="ok"
    else
        result="MISMATCH"
        (( mismatches++ ))
    fi
    printf '%-28s %-10s %-10s %s\n' "$case" "$bd" "$od" "$result"
done

echo
if (( mismatches > 0 )); then
    echo "parity-check: FAIL — $mismatches/${#CASES[@]} case(s) diverged" >&2
    exit 1
fi
echo "parity-check: PASS — all ${#CASES[@]} case(s) agree"
