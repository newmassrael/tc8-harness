#!/usr/bin/env bash
# Strangler parity gate — run the same cases through bash smoke-test.sh and the
# Rust tc8-orchestrator, then diff the per-case disposition. Behavioral
# equivalence is the SOLE precondition for ever deleting smoke-test.sh, so this
# is the mechanism that turns "looks right" into evidence. Run it as stages land
# and before any cutover; a mismatch means the orchestrator diverged from the
# SSOT it replaces.
#
# Usage:
#   dut/env/orchestrator/parity-check.sh [CASE ...]                  # single-pc
#   dut/env/orchestrator/parity-check.sh --topology external  [CASE ...]
#   dut/env/orchestrator/parity-check.sh --topology ssh-remote [CASE ...]
#   dut/env/orchestrator/parity-check.sh --topology external \
#        --bash-conf FILE --orch-conf FILE [CASE ...]
#
# Both drivers need root (netns); each is invoked via `sudo -n` on its NOPASSWD
# path (smoke-test.sh + tc8-orchestrator), so the script itself runs unprivileged.
# Runs each driver at --workers 1 so per-case attribution is unambiguous. Must
# NOT run while a CI netns sweep is in flight (shared netns names) — the
# self-hosted runner is this host.
#
# Topology modes (external / ssh-remote) drive a verification fixture both halves
# provision under the SAME fixed netns names (tc8-extfix-* / tc8-sshfix-*), so the
# two drivers MUST run sequentially — each invocation stands its fixture up and
# tears it down, and provision teardown-firsts to reclaim any leftover. Unlike
# single-pc (one fresh netns per case), the fixture is persistent within an
# invocation, so a topology run drives all cases through ONE invocation per driver
# (matching the bash example-conf usage) rather than the per-case loop.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SMOKE="$ROOT/dut/env/smoke-test.sh"
ORCH="$HERE/target/debug/tc8-orchestrator"

TOPOLOGY=single-pc
BASH_CONF=""
ORCH_CONF=""
CASES=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --topology)  TOPOLOGY=$2; shift 2 ;;
        --bash-conf) BASH_CONF=$2; shift 2 ;;
        --orch-conf) ORCH_CONF=$2; shift 2 ;;
        --) shift; CASES+=("$@"); break ;;
        *)  CASES+=("$1"); shift ;;
    esac
done

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
# Per-topology defaults: the case set, and (external/ssh-remote) the bash +
# orchestrator fixture confs. Defaults match the verified bash example-conf headers.
case "$TOPOLOGY" in
    single-pc)
        [[ ${#CASES[@]} -eq 0 ]] && CASES=(ICMPv4_TYPE_08 ARP_03 ICMPv4_TYPE_04 ARP_38 ARP_48)
        ;;
    external)
        [[ -z "$BASH_CONF" ]] && BASH_CONF="$ROOT/dut/env/topology.d/examples/external-netns-fixture.conf"
        [[ -z "$ORCH_CONF" ]] && ORCH_CONF="$HERE/examples/external-netns-fixture.toml"
        [[ ${#CASES[@]} -eq 0 ]] && CASES=(ICMPv4_TYPE_08 UDP_INTRODUCTION_03)
        ;;
    ssh-remote)
        [[ -z "$BASH_CONF" ]] && BASH_CONF="$ROOT/dut/env/topology.d/examples/ssh-remote-netns-fixture.conf"
        [[ -z "$ORCH_CONF" ]] && ORCH_CONF="$HERE/examples/ssh-remote-netns-fixture.toml"
        [[ ${#CASES[@]} -eq 0 ]] && CASES=(SOMEIPSRV_FORMAT_01 ICMPv4_TYPE_08)
        ;;
    *)
        echo "parity-check: unknown --topology '$TOPOLOGY' (single-pc | external | ssh-remote)" >&2
        exit 2 ;;
esac

[[ -x "$SMOKE" ]] || { echo "parity-check: smoke-test.sh not found at $SMOKE" >&2; exit 2; }
[[ -x "$ORCH" ]]  || { echo "parity-check: orchestrator not built at $ORCH (cargo build)" >&2; exit 2; }
if [[ "$TOPOLOGY" != single-pc ]]; then
    [[ -f "$BASH_CONF" ]] || { echo "parity-check: bash conf not found: $BASH_CONF" >&2; exit 2; }
    [[ -f "$ORCH_CONF" ]] || { echo "parity-check: orch conf not found: $ORCH_CONF" >&2; exit 2; }
fi

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

# Diff one case's disposition between the two drivers' outputs, print the row, and
# bump the global mismatch count. ABSENT/UNKNOWN never count as agreement.
compare_case() {
    local case=$1 bash_out=$2 orch_out=$3 bd od result
    bd=$(disposition "$bash_out" "$case")
    od=$(disposition "$orch_out" "$case")
    if [[ "$bd" == "$od" && "$bd" != ABSENT && "$bd" != UNKNOWN ]]; then
        result="ok"
    else
        result="MISMATCH"
        (( mismatches++ ))
    fi
    printf '%-28s %-10s %-10s %s\n' "$case" "$bd" "$od" "$result"
}

echo "parity-check [topology=$TOPOLOGY]: ${#CASES[@]} case(s) — bash smoke-test.sh vs tc8-orchestrator"
mismatches=0
printf '%-28s %-10s %-10s %s\n' CASE BASH ORCH RESULT
printf '%-28s %-10s %-10s %s\n' ---- ---- ---- ------

if [[ "$TOPOLOGY" == single-pc ]]; then
    # One invocation per case: each brings up its own fresh netns (clean attribution).
    for case in "${CASES[@]}"; do
        bash_out=$(sudo -n "$SMOKE" --workers 1 "$case" 2>&1)
        orch_out=$(sudo -n "$ORCH" --workers 1 "$case" 2>&1)
        compare_case "$case" "$bash_out" "$orch_out"
    done
else
    # One invocation per driver: the verification fixture is persistent within a run
    # (ssh-remote respawns its DUT per case inside it), so all cases share it. The
    # two halves use the same fixture netns names, hence strictly sequential.
    bash_all=$(sudo -n "$SMOKE" --topology "$TOPOLOGY" --topology-conf "$BASH_CONF" --workers 1 "${CASES[@]}" 2>&1)
    orch_all=$(sudo -n "$ORCH" --topology "$TOPOLOGY" --topology-conf "$ORCH_CONF" --workers 1 "${CASES[@]}" 2>&1)
    for case in "${CASES[@]}"; do
        compare_case "$case" "$bash_all" "$orch_all"
    done
fi

echo
if (( mismatches > 0 )); then
    echo "parity-check: FAIL — $mismatches/${#CASES[@]} case(s) diverged" >&2
    exit 1
fi
echo "parity-check: PASS — all ${#CASES[@]} case(s) agree"
