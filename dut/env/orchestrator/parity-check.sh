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

# Default case set: positive cases that conclude on the orchestrator's expect
# surface (base SOME/IP identity + the DUT-MAC block + ARP/ICMPv4/IPv4 category
# statics, emitted flat for every case — bash's structure). The per-case eventgroup
# OVERRIDES and a TCP category branch are not ported yet (the override stage).
#
# Conditioning surface: the S3 bring-up sysctls (arp_accept=1, delay_first_probe,
# ucast_solicit, ...) AND the S4 per-case toggles + per-case DUT neigh flush are
# native, so the orchestrator and bash build BOTH the fixture and the per-case
# kernel state via independent code — a passing case is real evidence, not a
# tautology. The default set exercises three conditioning families end-to-end:
#   ICMPv4_TYPE_04  → the ipfrag_time global toggle
#   ARP_38          → the conf.<iface>/conf.all arp_accept toggle
#   ARP_48          → the neigh base_reachable/delay_first_probe/gc_stale toggles
#
# Cases still NONCONC here need --expect keys the builder does not emit yet (no TCP
# category branch → TCP_RETRANSMISSION_TO_*; per-case eventgroup overrides →
# SOMEIPSRV/ETS) — that is the override stage, NOT a conditioning gap. Grow this
# set as those land.
CASES=("$@")
if [[ ${#CASES[@]} -eq 0 ]]; then
    CASES=(ICMPv4_TYPE_08 ARP_03 ICMPv4_TYPE_04 ARP_38 ARP_48)
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
