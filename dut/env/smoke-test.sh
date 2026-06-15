#!/usr/bin/env bash
# End-to-end smoke test:
#   netns setup → tc8-dut in dut ns → harness in tester ns
#   → SOME/IP-SD OfferService (svc=0xffff mth=0x8100 type=NOTIFICATION) captured.
#
# Usage:
#   sudo smoke-test.sh [--topology NAME] [--workers N] [--dut-first] \
#                      [--log-dir DIR] [--junit-xml PATH] \
#                      [--dut-control opcode|testability] [CASE_ID ...]
#   sudo smoke-test.sh [--workers N] --negative [--junit-xml PATH]
#
# --dut-control selects the DUT-control backend for seam-migrated cases
# (default opcode = in-house Upper Tester; testability = AUTOSAR Testability
# Protocol, port 30700). Cases driving the opcode builders directly ignore it.
#
# Runs each listed case against a fresh tc8-dut and reports a summary;
# exits non-zero if any case fails. Defaults to SOMEIPSRV_FORMAT_01.
#
# --topology NAME selects a deployment profile from topology.d/NAME.conf
# (default: single-pc, the historical netns-pair behaviour; TC8_TOPOLOGY
# env is honoured when the flag is absent). Profiles own how the tester
# interface is named, how (and whether) the DUT is started per case, and
# whether the DUT's kernel can be conditioned per case. See the
# "Topology profile contract" comment below.
#
# --workers N (default 1) runs N parallel (tc8-dut, harness) pairs, each
# pinned to its own netns pair (tc8-tester-$W / tc8-dut-$W), veth pair
# (veth-tester-$W / veth-dut-$W), and vsomeip tmp directory
# ($VSOMEIP_BASE/$W/, where $VSOMEIP_BASE is PID-scoped). Cases are
# distributed round-robin across workers. Each case still provisions a
# fresh tc8-dut (no cross-case state), so round-robin is safe.
#
# --dut-first inverts the default harness-first startup order. Used for
# negative tests that prove a case detects non-conformance (e.g. FORMAT_02
# must fail when the harness misses the initial session_id=0x0001 message).
#
# --negative runs a curated set of FORMAT_14..18 + ARP_13..15 assertions
# that inject a deliberately-wrong `--expect` value and confirm the case
# lands on the matching `fail:*` verdict. Guards against the regression
# where an `expected.*` comparison becomes trivially-true (e.g. field
# always 0).
set -euo pipefail

# Job control so each `&`-backgrounded command becomes its own process
# group leader; $! then doubles as the PGID, which lets `kill -SIG -$PGID`
# reach the `ip netns exec` wrapper AND its exec'd child atomically.
# Without this, the wrapper PID kills alone leave tc8-dut/tc8-harness
# orphaned, which the legacy `pkill -f` workaround papered over but
# cannot when multiple workers share the same binary path.
set -m

HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HARNESS=${HARNESS:-$ROOT/build/tc8-harness}
TC8_DUT_BIN=${TC8_DUT_BIN:-$ROOT/build/dut/dut_service/tc8-dut}
VSOMEIP_CFG=${VSOMEIP_CFG:-$ROOT/dut/dut_service/vsomeip.json}
CAPI_CFG=${CAPI_CFG:-$ROOT/dut/dut_service/commonapi.ini}

# Harness watchdog backstop (seconds). NOT a per-case budget: each case's
# timing lives once at its source of truth — the SCXML per-state deadlines
# and each stimulus's internal poll bound — and the harness exits the
# instant the SCXML reaches a final state (test_command.cpp's dispatch
# loop guards on `runner->isDone()`). So `-t` only bounds a hung harness
# or a non-self-terminating regression; it must merely exceed the longest
# legitimate case (someip_ets_152's internal `delay="180s"` ≈ 186 s wall).
# A green suite never reaches it because every case self-terminates at its
# own deadline first — replacing the former 689-entry per-case timeout
# maps, which only shadowed those deadlines and drifted from them.
readonly HARNESS_BACKSTOP_SEC=240

# Per-worker scratch root. Holds a sentinel subdir per live worker so the
# cleanup trap can tear down exactly the workers that were set up, even
# if a setup-netns.sh invocation fails mid-bring-up. Also holds per-case
# log tempfiles when --log-dir is not provided, and the stdout lock.
#
# PID-scoped (`.$$` suffix) so concurrent smoke-test.sh invocations on
# the same host (e.g. CI runner + local dev) get fully isolated state —
# in particular each run's `junit_records` files cannot bleed into the
# other's $JUNIT_OUT aggregation. The legacy non-scoped path was
# `/tmp/tc8-workers`; stale-scope GC below cleans up dirs left behind
# by crashed prior runs whose owner shell is gone.
WORK_ROOT=/tmp/tc8-workers.$$
STDOUT_LOCK=$WORK_ROOT/stdout.lock

# Per-run vsomeip + symlink scratch base. PID-scoped for the same
# reason as $WORK_ROOT — each run's worker symlinks
# (`$VSOMEIP_BASE/$W/tc8-{dut,harness}`) and vsomeip UDS sockets must
# not collide with a concurrent run's. Workers nest as `$VSOMEIP_BASE/$W`,
# replacing the legacy flat layout `/tmp/tc8-vsomeip-$W`. The
# kill_worker_procs marker `$VSOMEIP_BASE/$W/tc8-dut` is unique per
# (run-PID, worker-id) pair, so concurrent-run pkill no longer fans
# out across runs.
VSOMEIP_BASE=/tmp/tc8-vsomeip.$$

# DUT-specific expected values for SOMEIPSRV_FORMAT_14..18,
# FORMAT_19..28, and OPTIONS_04/07/15. Passed to the harness via
# `--expect` so the SCXML guards compare captured fields against
# these rather than hard-coded literals. Mirrors
# dut/dut_service/vsomeip.json + ets.fidl:
#   service_id    = 0xF4E7      (vsomeip.json services[0].service)
#   instance_id   = 0x0001      (vsomeip.json services[0].instance)
#   major_version = 1           (ets.fidl version.major)
#   ttl           = 3           (vsomeip.json service-discovery.ttl)
#   minor_version = 0           (ets.fidl version.minor / vsomeip default)
#   eventgroup_id = 0x0001      (Subscribe target — tc8-dut Nacks this
#                                 with the same ID echoed in the reply)
#   dut_iface_ip  = 172.16.0.2  (vsomeip.json unicast — OPTIONS_04 IPv4
#                                 Endpoint Option address field)
#   udp_port      = 30502       (vsomeip.json services[0].unreliable —
#                                 OPTIONS_07 IPv4 Endpoint UDP port)
#   tcp_port      = 30501       (vsomeip.json services[0].reliable.port —
#                                 OPTIONS_15 IPv4 Endpoint TCP port)
# Topology endpoint IPs — single source of truth for smoke-test.sh.
# single-pc passes them to setup-netns.sh in topology_bring_up_worker so
# the two files can never drift; external/ssh-remote topologies override
# them via TC8_TOPOLOGY_TESTER_IP / TC8_TOPOLOGY_DUT_IP (env or
# --topology-conf file).
#
# Wrapped in a function so evaluation happens AFTER the topology profile
# and the optional --topology-conf file are sourced — sudo's env_reset
# strips TC8_TOPOLOGY_* from the environment under the NOPASSWD rules,
# so the conf file is the reliable configuration channel and must be
# able to influence these values. Called from the topology loader below;
# all assignments are global.
init_expectation_defaults() {
TESTER_IP4=${TC8_TOPOLOGY_TESTER_IP:-172.16.0.1}
DUT_IP4=${TC8_TOPOLOGY_DUT_IP:-172.16.0.2}

TC8_DUT_EXPECT=(
    --expect service_id=0xF4E7
    --expect instance_id=0x0001
    --expect major_version=1
    --expect ttl=3
    --expect minor_version=0
    --expect eventgroup_id=0x0001
    --expect "dut_iface_ip=$DUT_IP4"
    --expect udp_port=30502
    --expect tcp_port=30501
    # §5.1.5.4 SD_BEHAVIOR_03/_04 verify the DUT answers FindService
    # with a multicast OfferService addressed to the SD multicast group
    # (vsomeip.json `service-discovery.multicast` for tc8-dut).
    --expect sd_multicast_ip=224.244.224.245
    # §5.1.5.5 OPTIONS_11/_14 verify the IPv4 Multicast Option fields
    # emitted in SubscribeEventgroupAck for the multicast-configured
    # eventgroup 0x0008 (vsomeip.json eventgroup multicast block).
    --expect mcast_ipv4=224.244.224.246
    --expect mcast_port=30495
)

# ARP §4.2 cases compare captured Sender Hardware Address (ARP_13),
# Sender Protocol Address (ARP_14), and Target Protocol Address (ARP_15)
# against operator-supplied identity. The DUT MAC is kernel-assigned per
# netns lifetime, so it is captured at worker bring-up time (after
# setup-netns.sh completes) and stored in $WORK_ROOT/$W/dut_mac. The IP
# pair matches setup-netns.sh defaults — override TESTER_IP/DUT_IP env
# vars there if the topology changes.
# §4.2.4.1 ARP_03..06 additionally compare the DUT UDP egress Ethernet
# destination (ARP_04/06) and filter DUT-originated ARP Requests by
# sender_hw (ARP_03/05) against the MAC the harness injects as the
# gratuitous/request sender. Must match `kTesterInjectedMac` in
# src/stimulus/arp_builder.h — edit both together.
ARP_TESTER_INJECTED_MAC=02:00:00:00:00:A1
# Second tester MAC for §4.2.4.2 Phase 3b Group C cache-merge cases
# (ARP_32/33/34/35). Must match `kTesterInjectedMac2` in arp_builder.h.
ARP_TESTER_INJECTED_MAC2=02:00:00:00:00:A2
# Third tester MAC for §4.2.4.2 Phase 3c Group D case ARP_40 (Response-
# learning). Must match `kTesterInjectedMac3` in arp_builder.h.
ARP_TESTER_INJECTED_MAC3=02:00:00:00:00:A3
# (TESTER_IP4 / DUT_IP4 are defined above TC8_DUT_EXPECT — the SD
# endpoint expectation reuses $DUT_IP4.)
# §4.7 DHCPv4 server emul identity — matches `kDefaultServerIdBe` in
# `src/sce_integration/dhcpv4_default_endpoints.h`. CM_05/_06 pre-pin
# `<this_ip, ARP_TESTER_INJECTED_MAC>` permanent on the DUT side so
# the synthetic gateway resolves without a real responder; if the C++
# constexpr changes, this literal must follow.
DHCPV4_SERVER1_IP4=172.16.0.10
# `dut.ip` feeds the stimulus (target_ip of the injected ARP
# Request); `arp.dut_iface_ip` is the SCXML expectation the captured
# DUT Reply's sender_proto_ip is compared against. In positive rows both
# carry the real DUT IP; `--negative` overrides only `arp.dut_iface_ip`
# (ARP_44) to prove the SCXML mismatch path without silencing the DUT.
ARP_DUT_EXPECT_STATIC=(
    --expect "arp.tester_ip=$TESTER_IP4"
    --expect "arp.dut_iface_ip=$DUT_IP4"
    --expect "dut.ip=$DUT_IP4"
    --expect "arp.tester_mac=$ARP_TESTER_INJECTED_MAC"
    --expect "arp.tester_mac2=$ARP_TESTER_INJECTED_MAC2"
    --expect "arp.tester_mac3=$ARP_TESTER_INJECTED_MAC3"
)
# §4.2.4.2 ARP_48/49 UT-channel cache conditioning: a topology whose
# DUT advertises UT 0x17 OpConditionArpCache declares its
# <DYNAMIC-ARP-CACHE-TIMEOUT> via TOPOLOGY_UT_ARP_CACHE_TIMEOUT_S (see
# the profile contract above); the knob rides into the trait stimulus,
# which then ages the DUT's table through the UT channel instead of
# relying on the Linux netns sysctl compression. Evaluated here —
# init_expectation_defaults runs after the --topology-conf source, so
# fixture confs (lwip-tap-fixture.conf) reach this branch.
if [[ -n "${TOPOLOGY_UT_ARP_CACHE_TIMEOUT_S:-}" ]]; then
    ARP_DUT_EXPECT_STATIC+=(
        --expect "arp_stimulus.ut_cache_conditioning_s=$TOPOLOGY_UT_ARP_CACHE_TIMEOUT_S"
    )
fi

# §4.3 ICMPv4 pilot cases (TYPE_08/09/10) compare captured Echo Reply
# identifier / sequence against operator-supplied values. The matching
# literals live in `src/stimulus/icmpv4_builder.h::kIcmpEchoId` /
# `kIcmpEchoSeq` — stimulus hardcodes them, this CLI value is purely the
# SCXML expectation. `--negative` rows flip one expectation alone to
# prove the fail path; any drift between these two sources silently
# turns a positive test into a false pass, so edit both together.
ICMPV4_TESTER_ECHO_ID=0x1234
ICMPV4_TESTER_ECHO_SEQ=0x5678
ICMPV4_DUT_EXPECT_STATIC=(
    --expect "icmpv4.tester_ip=$TESTER_IP4"
    --expect "icmpv4.dut_iface_ip=$DUT_IP4"
    --expect "icmpv4.echo_id=$ICMPV4_TESTER_ECHO_ID"
    --expect "icmpv4.echo_seq=$ICMPV4_TESTER_ECHO_SEQ"
)

# §4.4 IPv4 pilot cases (HEADER_01, HEADER_03, VERSION_03) compare the
# captured DUT-emitted IPv4 frame against the topology-pinned identity.
# Only the two IP values are wired — spec-fixed literals (version == 4,
# total_length >= 20, TTL >= 1) live inside the SCXML guards so there is
# no CLI knob to drift. The --negative row flips `ipv4.dut_iface_ip` to
# prove HEADER_03's pass guard depends on the expectation reaching the
# SCXML unchanged.
IPV4_DUT_EXPECT_STATIC=(
    --expect "ipv4.tester_ip=$TESTER_IP4"
    --expect "ipv4.dut_iface_ip=$DUT_IP4"
    # §4.6.5.5 UDP_USER_INTERFACE_07/_08 caller-specified IP axis. The
    # netns aliases (DUT 172.16.0.5 / TESTER 172.16.0.4) configured by
    # `setup-netns.sh` make the spec axis observable; SCXML reads
    # `expected.dut_alias_ip` / `expected.tester_alias_ip` while the
    # stimulus pins the same literals via constants in
    # `udp_pilot_common.h`. Pinning here lets `--negative
    # ipv4.dut_alias_ip=10.99.99.99` flip only the SCXML expectation,
    # exposing the strict-axis NEG row.
    # Alias IPs are netns defaults (setup-netns.sh configures them);
    # external topologies whose DUT carries different aliases override
    # via env.
    --expect "ipv4.dut_alias_ip=${TC8_TOPOLOGY_DUT_ALIAS_IP:-172.16.0.5}"
    --expect "ipv4.tester_alias_ip=${TC8_TOPOLOGY_TESTER_ALIAS_IP:-172.16.0.4}"
)
}

DUT_FIRST=0
NEGATIVE=0
LOG_DIR=""
JUNIT_OUT=""
WORKERS=1
DUT_CONTROL=""
TOPOLOGY=${TC8_TOPOLOGY:-single-pc}
TOPOLOGY_CONF=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --topology)  TOPOLOGY="$2"; shift 2 ;;
        --topology-conf) TOPOLOGY_CONF="$2"; shift 2 ;;
        --workers)   WORKERS="$2"; shift 2 ;;
        --dut-first) DUT_FIRST=1; shift ;;
        --negative)  NEGATIVE=1;  shift ;;
        --log-dir)   LOG_DIR="$2"; shift 2 ;;
        --junit-xml) JUNIT_OUT="$2"; shift 2 ;;
        --dut-control) DUT_CONTROL="$2"; shift 2 ;;
        *) break ;;
    esac
done

[[ "$WORKERS" =~ ^[1-9][0-9]*$ ]] \
    || { echo "smoke-test: --workers must be a positive integer, got '$WORKERS'" >&2; exit 1; }

if [[ $# -eq 0 ]]; then
    CASES=("SOMEIPSRV_FORMAT_01")
else
    CASES=("$@")
fi

# §4.7.6.5 USAGE_01 detection — the only case that needs the second veth
# pair (DIface-1 / TIface-1) per Topology 2. Workers bring up the pair
# only when the caller's case list includes USAGE_01, so 51 §4.7 + INTRO_01
# and other-section runs stay on today's single-pair netns shape with zero
# overhead. SECOND_VETH=1 is sticky for the whole script invocation, not
# per-case, because workers bring up netns once at startup (not per-case).
NEED_SECOND_VETH=0
for _case in "${CASES[@]}"; do
    if [[ "$_case" == "DHCPv4_CLIENT_USAGE_01" ]]; then
        NEED_SECOND_VETH=1
        break
    fi
done
# Topology 2 second-pair endpoints — single source of truth for
# smoke-test.sh. Mirror of setup-netns.sh's defaults (172.17.0.0/24).
TESTER_IP4_2=172.17.0.1
DUT_IP4_2=172.17.0.2

# ── Topology profile contract ────────────────────────────────────────
# A profile at topology.d/<name>.conf is a sourced bash fragment that
# must define:
#
#   Variables:
#     TOPOLOGY_DESCRIPTION        one-line human description
#     TOPOLOGY_DUT_CONDITIONING   1 = per-case DUT kernel conditioning
#                                 (sysctl/neigh) is possible; 0 = the
#                                 DUT stack is not ours to manage —
#                                 conditioning steps are logged + skipped
#     TOPOLOGY_SUPPORTS_NEGATIVE  1 = --negative self-validation works
#     TOPOLOGY_SUPPORTS_DUT_SPAWN 1 = smoke-test starts one fresh DUT
#                                 per case; 0 = a persistent external
#                                 DUT is assumed already running
#     TOPOLOGY_MAX_WORKERS        worker cap ("" = no cap)
#
#   Optional variables:
#     TOPOLOGY_UT_ARP_CACHE_TIMEOUT_S
#                                 non-empty = the DUT advertises UT
#                                 0x17 OpConditionArpCache and this is
#                                 its <DYNAMIC-ARP-CACHE-TIMEOUT> in
#                                 seconds (lwIP fixture: compile-time
#                                 ARP_MAXAGE = 300). Rides into the
#                                 harness as --expect
#                                 arp_stimulus.ut_cache_conditioning_s so the
#                                 ARP_48/49 stimulus conditions the
#                                 cache through the UT channel; also
#                                 suppresses the Group E
#                                 conditioning-skip INFO (the UT path
#                                 carries the case instead of the
#                                 netns sysctls). Empty/unset = only
#                                 TOPOLOGY_DUT_CONDITIONING decides.
#
#   Functions (every one must log its own failures — no silent fail):
#     topology_preflight                 startup environment validation
#     topology_bring_up_worker W         per-worker bring-up (after the
#                                        common scaffolding); must write
#                                        $WORK_ROOT/$W/dut_mac
#     topology_tear_down_worker W        per-worker teardown
#     topology_tester_iface W            echoes the tester capture iface
#     topology_tester_iface_secondary W  echoes the Topology 2 second
#                                        iface, or nothing if unsupported
#     topology_exec_tester W CMD...      runs a foreground command in the
#                                        tester network context
#     topology_run_harness W LOG ARGS... starts the harness backgrounded
#                                        in the tester context; echoes PID
#     topology_start_dut W LOG CFG ENV.. starts one DUT instance
#                                        (no-op for persistent DUTs)
#     topology_stop_dut W                stops the per-case DUT instance
TOPOLOGY_DIR="$HERE/topology.d"
TOPOLOGY_FILE="$TOPOLOGY_DIR/$TOPOLOGY.conf"
if [[ ! -f "$TOPOLOGY_FILE" ]]; then
    echo "smoke-test: unknown topology '$TOPOLOGY' — no profile at $TOPOLOGY_FILE" >&2
    echo "smoke-test: available topologies:" >&2
    for _p in "$TOPOLOGY_DIR"/*.conf; do
        [[ -f "$_p" ]] || continue
        _pn=$(basename "${_p%.conf}")
        echo "  --topology $_pn" >&2
    done
    exit 1
fi
# shellcheck source=/dev/null
source "$TOPOLOGY_FILE"

# Contract validation — a partially-implemented profile must fail loudly
# at startup, enumerating every gap, not at first use mid-run.
_contract_errors=0
for _v in TOPOLOGY_DESCRIPTION TOPOLOGY_DUT_CONDITIONING \
          TOPOLOGY_SUPPORTS_NEGATIVE TOPOLOGY_SUPPORTS_DUT_SPAWN \
          TOPOLOGY_MAX_WORKERS; do
    [[ -n "${!_v+x}" ]] || {
        echo "smoke-test: topology '$TOPOLOGY' does not define required variable $_v" >&2
        _contract_errors=1
    }
done
for _f in topology_preflight topology_bring_up_worker \
          topology_tear_down_worker topology_tester_iface \
          topology_tester_iface_secondary topology_exec_tester \
          topology_run_harness topology_start_dut topology_stop_dut; do
    declare -F "$_f" >/dev/null || {
        echo "smoke-test: topology '$TOPOLOGY' does not define required function $_f()" >&2
        _contract_errors=1
    }
done
[[ $_contract_errors -eq 0 ]] \
    || { echo "smoke-test: topology '$TOPOLOGY' violates the profile contract — aborting" >&2; exit 1; }
unset _contract_errors _v _f _p _pn
echo "smoke-test: topology '$TOPOLOGY' — $TOPOLOGY_DESCRIPTION"

# Optional per-site topology options (TC8_TOPOLOGY_* assignments).
# sudo's env_reset strips TC8_TOPOLOGY_* under the NOPASSWD rules, so a
# CLI-passed file is the reliable configuration channel for external /
# remote topologies.
# Mode gates: reject flag combinations the selected topology cannot
# honour. Deliberately BEFORE the --topology-conf source — a rejected
# invocation must not execute a site conf that may carry side effects
# (fixture provisioning, device setup).
if [[ "$NEGATIVE" == "1" && "$TOPOLOGY_SUPPORTS_NEGATIVE" != "1" ]]; then
    echo "smoke-test: --negative requires a topology with a spawned reference DUT (deliberate mis-expectations + start-order control); topology '$TOPOLOGY' does not support it" >&2
    exit 1
fi
if [[ "$DUT_FIRST" == "1" && "$TOPOLOGY_SUPPORTS_DUT_SPAWN" != "1" ]]; then
    echo "smoke-test: --dut-first controls DUT-vs-harness start order, but topology '$TOPOLOGY' does not spawn the DUT — the flag cannot take effect" >&2
    exit 1
fi
if [[ -n "$TOPOLOGY_MAX_WORKERS" ]] && (( WORKERS > TOPOLOGY_MAX_WORKERS )); then
    echo "smoke-test: --workers $WORKERS exceeds topology '$TOPOLOGY' limit of $TOPOLOGY_MAX_WORKERS (one shared physical DUT cannot serve parallel workers)" >&2
    exit 1
fi

if [[ -n "$TOPOLOGY_CONF" ]]; then
    [[ -f "$TOPOLOGY_CONF" ]] || {
        echo "smoke-test: --topology-conf '$TOPOLOGY_CONF' does not exist" >&2
        exit 1
    }
    # shellcheck source=/dev/null
    source "$TOPOLOGY_CONF"
    echo "smoke-test: topology options loaded from $TOPOLOGY_CONF"
fi

# Expectation defaults are evaluated here — after profile + options —
# so TC8_TOPOLOGY_* overrides reach the --expect arrays.
init_expectation_defaults

[[ $EUID -eq 0 ]] || { echo "smoke-test: must run as root (try: sudo $0)" >&2; exit 1; }
[[ -x "$HARNESS"  ]] || { echo "smoke-test: harness missing: $HARNESS"  >&2; exit 1; }
topology_preflight \
    || { echo "smoke-test: topology '$TOPOLOGY' preflight failed — aborting before any case runs" >&2; exit 1; }

if [[ -n "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR"
fi

# JUnit XML reporter — opt-in via --junit-xml. Each worker appends one
# pipe-delimited record per case to $WORK_ROOT/$W/junit_records; after
# all workers finish, the records are aggregated into a Surefire-shape
# XML file at $JUNIT_OUT (consumed by GitHub Actions dorny/test-reporter
# and most other JUnit consumers). Per-worker append → no lock needed
# during the run; the aggregator runs single-threaded after `wait`.
if [[ -n "$JUNIT_OUT" ]]; then
    mkdir -p "$(dirname "$JUNIT_OUT")"
    JUNIT_RUN_TS=$(date -u +%Y-%m-%dT%H:%M:%S)
fi
JUNIT_RUN_START=$EPOCHREALTIME

# Per-worker output-block emission serialized on a file lock so 4
# workers printing multi-line log dumps don't interleave. Single-line
# progress messages stay unserialized (atomic under PIPE_BUF=4096).
emit_block() {
    # stdin → stdout, but only one emitter at a time.
    (
        flock -x 200
        cat
    ) 200>"$STDOUT_LOCK"
}

# Append one pipe-delimited record to $WORK_ROOT/$W/junit_records.
# Format: case_name|mode|status|duration_sec|verdict_line
#   case_name: case_id for positive runs, case_id_neg for negative
#   mode: positive | negative
#   status: pass | fail
#   duration_sec: %.3f wall seconds
#   verdict_line: the harness's `verdict  : ...` line (may be empty if
#                 the harness never printed one — e.g. crash)
# Aggregator runs after `wait`; per-worker append needs no lock.
junit_record_case() {
    local W=$1
    local case_name=$2
    local mode=$3
    local start_ts=$4
    local hlog=$5
    local rc=$6
    [[ -n "$JUNIT_OUT" ]] || return 0
    local end_ts=$EPOCHREALTIME
    local duration
    duration=$(awk -v s="$start_ts" -v e="$end_ts" 'BEGIN { printf "%.3f", e - s }')
    local status="pass"
    (( rc == 0 )) || status="fail"
    local verdict_line=""
    if [[ -r "$hlog" ]]; then
        verdict_line=$(grep -m1 -E '^verdict  :' "$hlog" 2>/dev/null || true)
    fi
    printf '%s|%s|%s|%s|%s\n' \
        "$case_name" "$mode" "$status" "$duration" "$verdict_line" \
        >>"$WORK_ROOT/$W/junit_records"
}

# Record a topology-skipped case in the JUnit stream. Reuses the
# pipe-delimited record shape with status=skip and the human reason in
# the verdict-line slot; junit_emit_xml renders it as <skipped/>.
junit_record_skip() {
    local W=$1
    local case_name=$2
    local mode=$3
    local reason=$4
    [[ -n "$JUNIT_OUT" ]] || return 0
    printf '%s|%s|skip|0.000|%s\n' \
        "$case_name" "$mode" "$reason" \
        >>"$WORK_ROOT/$W/junit_records"
}

# Emit Surefire-shape <testsuites><testsuite><testcase>… XML to
# $JUNIT_OUT from per-worker $WORK_ROOT/$W/junit_records files. Runs
# single-threaded after all workers have completed. Cases are grouped
# into <testsuite> blocks by their category prefix (case_id stripped
# of trailing _NN and _neg suffixes), e.g. ARP_07 → suite "ARP",
# IPv4_HEADER_05 → suite "IPv4_HEADER".
junit_emit_xml() {
    [[ -n "$JUNIT_OUT" ]] || return 0
    local total_records=0 W
    for (( W=0; W<WORKERS; W++ )); do
        if [[ -s "$WORK_ROOT/$W/junit_records" ]]; then
            total_records=$(( total_records + $(wc -l <"$WORK_ROOT/$W/junit_records") ))
        fi
    done
    if (( total_records == 0 )); then
        # No records — write an empty-but-valid suite anyway so consumers
        # don't choke on a missing file.
        cat >"$JUNIT_OUT" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="tc8-harness smoke" tests="0" failures="0" time="0.000"/>
EOF
        return 0
    fi
    local total_wall
    total_wall=$(awk -v s="$JUNIT_RUN_START" -v e="$EPOCHREALTIME" \
        'BEGIN { printf "%.3f", e - s }')
    local concat="$WORK_ROOT/junit_records.all"
    : >"$concat"
    for (( W=0; W<WORKERS; W++ )); do
        if [[ -s "$WORK_ROOT/$W/junit_records" ]]; then
            cat "$WORK_ROOT/$W/junit_records" >>"$concat"
        fi
    done
    awk -F'|' \
        -v outfile="$JUNIT_OUT" \
        -v run_ts="$JUNIT_RUN_TS" \
        -v total_wall="$total_wall" '
        function xml_escape(s,    r) {
            r = s
            gsub(/&/, "\\&amp;", r)
            gsub(/</, "\\&lt;", r)
            gsub(/>/, "\\&gt;", r)
            gsub(/"/, "\\&quot;", r)
            return r
        }
        function suite_of(name,    s) {
            s = name
            sub(/_neg$/, "", s)
            sub(/_NEG$/, "", s)
            sub(/_PLATFORM_KNOWN_FAIL$/, "", s)
            sub(/_[0-9]+$/, "", s)
            return s
        }
        {
            name = $1; mode = $2; status = $3; dur = $4; vline = $5
            sk = suite_of(name)
            if (!(sk in seen)) { seen[sk] = 1; suites[++ns] = sk }
            tests_per[sk]++
            time_per[sk] += dur + 0
            cnt = ++idx[sk]
            cname[sk, cnt] = name
            cmode[sk, cnt] = mode
            cstatus[sk, cnt] = status
            cdur[sk, cnt] = dur
            cvline[sk, cnt] = vline
            if (status == "fail") fails_per[sk]++
            if (status == "skip") skips_per[sk]++
            tot_tests++
            if (status == "fail") tot_fails++
            if (status == "skip") tot_skips++
        }
        END {
            printf "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" > outfile
            printf "<testsuites name=\"tc8-harness smoke\" tests=\"%d\" failures=\"%d\" skipped=\"%d\" time=\"%s\" timestamp=\"%s\">\n",
                tot_tests, tot_fails+0, tot_skips+0, total_wall, run_ts > outfile
            for (i = 1; i <= ns; i++) {
                sk = suites[i]
                printf "  <testsuite name=\"%s\" tests=\"%d\" failures=\"%d\" skipped=\"%d\" time=\"%.3f\">\n",
                    xml_escape(sk), tests_per[sk], fails_per[sk]+0, skips_per[sk]+0, time_per[sk]+0 > outfile
                for (j = 1; j <= idx[sk]; j++) {
                    printf "    <testcase classname=\"%s\" name=\"%s\" time=\"%s\"",
                        xml_escape(sk), xml_escape(cname[sk, j]), cdur[sk, j] > outfile
                    if (cstatus[sk, j] == "fail") {
                        msg = cvline[sk, j]
                        if (msg == "") msg = "no verdict line"
                        printf "><failure type=\"%s\" message=\"%s\"/></testcase>\n",
                            xml_escape(cmode[sk, j]), xml_escape(msg) > outfile
                    } else if (cstatus[sk, j] == "skip") {
                        printf "><skipped message=\"%s\"/></testcase>\n",
                            xml_escape(cvline[sk, j]) > outfile
                    } else {
                        printf "/>\n" > outfile
                    }
                }
                printf "  </testsuite>\n" > outfile
            }
            printf "</testsuites>\n" > outfile
        }
    ' "$concat"
    rm -f "$concat"
}

# SIGKILL every process whose cmdline matches a per-worker binary path
# and wait for them to disappear. The caller passes a symlink-via path
# like $VSOMEIP_BASE/$W/tc8-dut — bring_up_worker creates that symlink,
# run_case invokes through it, so argv[0] (and thus /proc/PID/cmdline)
# contains the per-(run-PID, worker-id) scoped string.
#
# Why not PGID-based kill: under `set -m` bash assigns a fresh PGID to
# each backgrounded command, but `ip netns exec` forks internally and
# the forked child gets reparented to init the moment ip's wait returns
# — observed in the wild as tc8-dut PIDs with PPid=1 (init) and a PGID
# whose leader is already gone. Killing that PGID is unreliable across
# iproute2 versions; matching by worker-unique argv[0] is robust.
#
# Why not SIGTERM grace: vsomeip SD is in its repetition phase for the
# first ~1.5 s after boot (offers fire at 50 ms, 250 ms, 650 ms,
# 1450 ms). A SIGTERM+grace shutdown lets stragglers fire during the
# window that the NEXT case's harness is already pcap-open. FORMAT_02
# then captures a stale offer with session_id≥2 and reports
# fail:session_id_not_0x0001. Graceful shutdown is only valuable for
# StopOffer propagation to real peers; between cases nothing depends on
# it, so SIGKILL is correct here.
kill_worker_procs() {
    local marker=$1
    [[ -n "$marker" ]] || return 0
    pkill -KILL -f "$marker" 2>/dev/null || true
    local _
    for _ in 1 2 3 4 5; do
        pgrep -f "$marker" >/dev/null 2>&1 || return 0
        sleep 0.1
    done
}

# Common per-worker scaffolding around the topology hooks. Sentinel
# file $WORK_ROOT/$W/up is touched BEFORE the topology bring-up starts
# and left in place until teardown succeeds, so a crash mid-setup is
# still reachable by the cleanup trap.
#
# The tc8-harness symlink gives each worker's harness a worker-unique
# argv[0] in /proc/PID/cmdline. kill_worker_procs pkills by that unique
# string, scoping the kill to this worker only. Without it, concurrent
# workers would share the real binary path and pkill would fan out
# across workers. Path is additionally PID-scoped via $VSOMEIP_BASE so
# concurrent smoke-test.sh runs don't collide on the marker. The
# harness always runs on this host, so the symlink is common; the
# tc8-dut symlink is profile business (only spawning topologies need
# it).
common_bring_up_worker() {
    local W=$1
    mkdir -p "$WORK_ROOT/$W" "$VSOMEIP_BASE/$W"
    : >"$WORK_ROOT/$W/up"
    : >"$WORK_ROOT/$W/junit_records"
    : >"$WORK_ROOT/$W/skips"
    : >"$WORK_ROOT/$W/processed"
    ln -sf "$HARNESS" "$VSOMEIP_BASE/$W/tc8-harness"
    topology_bring_up_worker "$W"
    # Flush stimulus-suppression iptables rules leaked by a SIGKILLed
    # prior run. The harness RAIIs (TesterAutoRstDrop/TesterAutoAckDrop,
    # tcp_pilot_common.h) install every rule inside the dedicated
    # `tc8-stimulus` chain precisely so this single shape-agnostic flush
    # can clean leaks: on persistent-tester topologies (external /
    # ssh-remote) one leaked pure-ACK drop silently breaks every later
    # TCP handshake against the DUT. No-op when the chain does not
    # exist (fresh netns / clean host).
    topology_exec_tester "$W" iptables -w 5 -F tc8-stimulus 2>/dev/null || true
    [[ -s "$WORK_ROOT/$W/dut_mac" ]] || {
        echo "smoke-test: topology '$TOPOLOGY' bring-up for worker $W did not record the DUT MAC at $WORK_ROOT/$W/dut_mac — profile contract violation" >&2
        exit 1
    }
}

common_tear_down_worker() {
    local W=$1
    # Reap any harness still running under this worker's symlink path
    # (belt-and-suspenders — run_case/run_negative_case already kill
    # per case). DUT-side reaping is the profile's job.
    kill_worker_procs "$VSOMEIP_BASE/$W/tc8-harness"
    topology_tear_down_worker "$W"
    rm -rf "$VSOMEIP_BASE/$W" "$WORK_ROOT/$W"
}

cleanup() {
    # Tear down every worker that completed (or attempted) bring-up.
    # Sentinel-driven so interrupts during the initial bring-up loop
    # still clean up whatever got created.
    if [[ -d "$WORK_ROOT" ]]; then
        local dir W
        for dir in "$WORK_ROOT"/*; do
            [[ -d "$dir" ]] || continue
            W=$(basename "$dir")
            [[ "$W" == "stdout.lock" ]] && continue
            common_tear_down_worker "$W"
        done
        rm -rf "$WORK_ROOT"
    fi
    rm -rf "$VSOMEIP_BASE"
}
trap cleanup EXIT

# Leftover GC for prior smoke-test.sh runs that crashed before their EXIT
# trap fired — vsomeip half-init can leave tc8-dut/harness alive,
# blocking the next run's UDS bind. Two parts:
#
# 1. PID-scoped sibling scopes (current scheme). Each $WORK_ROOT /
#    $VSOMEIP_BASE pair carries the owner shell's PID in its name. If
#    the owner is gone, the run is dead — kill any leftover process
#    pinned via that scope's symlink-path marker (unique per
#    (owner-PID, worker-id), so concurrent live runs are unaffected)
#    and rm the dirs. Live concurrent runs are detected via
#    `kill -0 OWNER` and skipped.
#
# 2. Legacy non-scoped paths (`/tmp/tc8-workers`, `/tmp/tc8-vsomeip-N`
#    flat). Pre-PID-scope smoke-test.sh versions used these; any
#    leftover from those is reaped via the legacy symlink-path
#    pattern. After the PID-scope migration nothing current writes to
#    these paths, so the cleanup is a one-shot no-op on a clean host.
shopt -s nullglob
for stale in /tmp/tc8-vsomeip.*; do
    [[ -d "$stale" ]] || continue
    [[ "$stale" == "$VSOMEIP_BASE" ]] && continue
    owner=${stale##*.}
    [[ "$owner" =~ ^[0-9]+$ ]] || continue
    if kill -0 "$owner" 2>/dev/null; then
        continue
    fi
    pkill -KILL -f "$stale/" 2>/dev/null || true
    rm -rf "$stale"
done
# A process can outlive its scratch dir: a run's exit trap rm -rf's
# its own scope even when a worker pkill missed, and the dir-keyed
# loop above can then never see the survivor again (observed
# 2026-06-11: four per-case tc8-dut workers from a mis-topologied run
# outlived their dir and held the lwIP fixture lock fd they had
# inherited, deadlocking the weekly sweep). Reap by cmdline instead:
# anything EXECUTED from a PID-scoped scratch dir whose owner shell
# is gone is an orphan, dir or no dir. Anchored pattern so only
# scratch-dir binaries/symlinks match, never an operator's shell that
# merely mentions the path.
while read -r opid oargs; do
    owner=${oargs#/tmp/tc8-vsomeip.}
    owner=${owner%%/*}
    [[ "$owner" =~ ^[0-9]+$ ]] || continue
    if kill -0 "$owner" 2>/dev/null; then
        continue
    fi
    echo "smoke-test: reaping orphan pid $opid of dead run $owner: $oargs" >&2
    kill -KILL "$opid" 2>/dev/null || true
done < <(pgrep -af '^/tmp/tc8-vsomeip\.[0-9]+/' || true)
unset opid oargs
for stale in /tmp/tc8-workers.*; do
    [[ -d "$stale" ]] || continue
    [[ "$stale" == "$WORK_ROOT" ]] && continue
    owner=${stale##*.}
    [[ "$owner" =~ ^[0-9]+$ ]] || continue
    if kill -0 "$owner" 2>/dev/null; then
        continue
    fi
    rm -rf "$stale"
done
shopt -u nullglob
unset stale owner

# Legacy non-PID-scoped paths from pre-migration smoke-test.sh runs.
pkill -KILL -f '/tmp/tc8-vsomeip-[0-9][0-9]*/tc8-' 2>/dev/null || true
rm -rf /tmp/tc8-workers /tmp/vsomeip-* /tmp/vsomeip.lck /tmp/tc8-vsomeip-[0-9]*

mkdir -p "$WORK_ROOT" "$VSOMEIP_BASE"
: >"$STDOUT_LOCK"

# Parallel bring-up: setup-netns.sh is idempotent and operates on
# distinct names per worker, so concurrent netlink ops don't collide.
# Wall time for N=4: ~0.3 s vs ~1.2 s serial.
# Explicit-PID waits everywhere a worker fan-out joins: a bare `wait`
# would also wait on unrelated background children — e.g. a persistent
# DUT a --topology-conf fixture spawned — and deadlock the run.
_tc8_join_pids=()
for (( W=0; W<WORKERS; W++ )); do
    common_bring_up_worker "$W" &
    _tc8_join_pids+=($!)
done
wait "${_tc8_join_pids[@]}"

# Log a skipped DUT-stack conditioning step. Conditioning exists to
# shape the spawned reference DUT's Linux kernel for a specific case
# (sysctl/neigh manipulation); on topologies that do not manage the DUT
# kernel the step cannot apply. The case still runs — a conformant DUT
# must satisfy the spec assertion natively — but the omission is logged
# so a verdict difference against the single-pc baseline is explainable
# from the run output alone.
log_conditioning_skip() {
    local W=$1 case_id=$2 what=$3
    echo "[w$W] INFO ${case_id}: DUT-stack conditioning not applied ($what) — topology '$TOPOLOGY' does not manage the DUT network stack"
}

# SSOT for "this case is skipped": JUnit <skipped/> stream + per-worker skips
# ledger (feeds the summary count). Callers emit their own stdout block. Used
# by both the pre-run topology skip (skip_case) and the post-harness
# capability skip in run_case (Tier 2 2b#4) so the two skip flavours record
# identically.
record_skip() {
    local W=$1 case_id=$2 reason=$3
    junit_record_skip "$W" "$case_id" positive "$reason"
    echo "${case_id}|${reason}" >>"$WORK_ROOT/$W/skips"
}

# Record a case the selected topology cannot execute, with the reason,
# in stdout + summary + JUnit. Never silent: shows up as SKIP in all
# three places. Decided in bash BEFORE the harness runs (topology limit);
# contrast the capability skip in run_case, decided from the harness verdict.
skip_case() {
    local W=$1 case_id=$2 reason=$3
    {
        echo "=========================================="
        echo "[w$W] SKIP ${case_id} — ${reason}"
        echo "=========================================="
    } | emit_block
    record_skip "$W" "$case_id" "$reason"
}

# Run one case against a specific worker's tester context.
# Writes logs to per-case files under $LOG_DIR (if set) or worker-scoped
# mktemps. Emits a single multi-line block to stdout under flock so
# concurrent workers don't interleave.
#
# Args: worker_id case_id
run_case() {
    local W=$1
    local case_id=$2
    # Canonical case identity for the per-case override maps below. Bash
    # associative-array keys are case-sensitive, but case IDs are
    # case-insensitive everywhere else: the harness registry resolves via
    # equalsIgnoreAsciiCase and SpecInventory::canonicalise upper-cases
    # (the split-brain identity closed as P10). Folding the lookup key to
    # upper-case keeps this layer in agreement, so a test-dir-name
    # invocation (`dhcpv4_client_reacquisition_05`) hits the upper-case
    # map keys instead of silently missing and taking the default.
    local case_id_canon=${case_id^^}
    local start_ts=$EPOCHREALTIME
    local tester_iface
    tester_iface=$(topology_tester_iface "$W")
    # netns names for the DUT-stack conditioning blocks below. Only
    # dereferenced when TOPOLOGY_DUT_CONDITIONING=1, which implies the
    # single-pc netns naming convention — other topologies never reach
    # the guarded blocks.
    local tester_ns="tc8-tester-$W"
    local dut_ns="tc8-dut-$W"
    local veth_d="veth-dut-$W"
    local vsp="$VSOMEIP_BASE/$W/"
    local harness_link="$vsp/tc8-harness"
    local dut_mac
    dut_mac=$(cat "$WORK_ROOT/$W/dut_mac")

    local hlog dlog keep_logs
    if [[ -n "$LOG_DIR" ]]; then
        hlog="$LOG_DIR/${case_id}.harness.log"
        dlog="$LOG_DIR/${case_id}.dut.log"
        keep_logs=1
    else
        hlog=$(mktemp "$WORK_ROOT/$W/${case_id}.harness.XXXXXX")
        dlog=$(mktemp "$WORK_ROOT/$W/${case_id}.dut.XXXXXX")
        keep_logs=0
    fi

    # Scope the vsomeip tmp wipe to the sockets + lock file only — NEVER
    # remove the per-worker binary symlinks that kill_worker_procs uses
    # to pattern-match. A concurrent worker's state at
    # $VSOMEIP_BASE/OTHER/ is never touched.
    rm -f "$VSOMEIP_BASE/$W"/vsomeip-* "$VSOMEIP_BASE/$W"/vsomeip.lck 2>/dev/null || true
    : >"$hlog"
    : >"$dlog"

    # Per-case flush of DUT neighbor cache. setup-netns.sh flushes once
    # at netns creation, but every run that provokes a unicast egress
    # (every case using emit*Boot stimulus) leaves <tester_ip, tester_mac>
    # learned in DUT's table for the kernel's reachable_time window.
    # Without this per-case flush, the second-and-later ARP_07..15 case
    # would hit cache and never emit an ARP Request, failing on timeout.
    #
    # Tester side is intentionally NOT flushed: Phase 2 entry-learning
    # cases (ARP_03..06) rely on the DUT's cache holding the tester's
    # *injected* MAC (kTesterInjectedMac) that our raw-ARP stimulus puts
    # there. If the tester's cache were flushed, any tester-kernel
    # egress toward the DUT (e.g. the ICMP port-unreachable reply to
    # the UT-triggered datagram landing on an unbound port) would
    # trigger tester-kernel ARP resolution via a normal ARP Request
    # (sender_hw = kernel MAC, not injected MAC). DUT learns kernel MAC
    # and overwrites the injected entry per RFC 826 §2.3, and
    # ARP_04/06's UDP-egress eth_dst check fails. The NUD_PROBE flakiness
    # on the tester side is addressed via `ucast_solicit=0` in
    # setup-netns.sh instead (keeps cache intact, just disables re-probing).
    if [[ "$TOPOLOGY_DUT_CONDITIONING" == "1" ]]; then
        ip -n "$dut_ns" neigh flush dev "$veth_d"
    else
        # Only cache-sensitive families care about the missing flush;
        # logging it for every case would be noise without information.
        case "$case_id" in
            ARP_*|IPv4_AUTOCONF_*)
                log_conditioning_skip "$W" "$case_id" \
                    "per-case DUT neigh cache flush — repeat runs against a persistent DUT may hit a warm ARP cache"
                ;;
        esac
    fi

    # ARP_38 exercises the RFC 826 §2.3 step 4 check ("Am I the target
    # protocol address?"): a non-gratuitous ARP Response with target_ip
    # set to an unused host should be dropped, and a conformant DUT must
    # then emit its own ARP Request when provoked for UDP egress. Linux
    # with `arp_accept=1` (the default for ARP_05/06 cache-learning)
    # explicitly bypasses the target_ip check for unicast Replies and
    # creates a neigh entry from the injected frame — the opposite of
    # what this case tests. Temporarily disable `arp_accept` for the
    # duration of ARP_38 only; restore after the harness has its verdict.
    #
    # Abnormal-termination safety (Ctrl-C mid-case): the top-level
    # `trap cleanup EXIT` → `tear_down_worker` → `cleanup.sh` destroys
    # the netns on any shell exit, and sysctls live inside the netns, so
    # a leaked `arp_accept=0` vanishes with the netns regardless of
    # whether the in-function restore below fires. No per-function trap
    # needed.
    local toggle_arp_accept=0
    if [[ "$case_id" == "ARP_38" ]]; then
        if [[ "$TOPOLOGY_DUT_CONDITIONING" == "1" ]]; then
            toggle_arp_accept=1
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.conf.$veth_d.arp_accept=0" >/dev/null
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.conf.all.arp_accept=0"     >/dev/null
        else
            log_conditioning_skip "$W" "$case_id" \
                "arp_accept=0 — Linux-reference workaround for the RFC 826 step-4 target-ip check"
        fi
    fi

    # ARP_39/40 exercise the spec's "DUT learns from a tester-injected
    # ARP frame" path. The tester first lets the DUT broadcast its own
    # ARP Request (cache miss after the UT 0x02 stimulus), then injects an ARP
    # Request (ARP_39) or Response (ARP_40) carrying the new MAC. For
    # this to work, the tester *kernel* must NOT auto-respond to the
    # DUT's broadcast — otherwise the DUT learns the kernel's veth MAC
    # first, the entry transitions to NUD_REACHABLE, and Linux's
    # `neigh_update` rules then refuse to override the lladdr from the
    # subsequent tester injection (without OVERRIDE flag, REACHABLE
    # entries are sticky). `arp_ignore=8` disables ARP-reply generation
    # for all local addresses on the receiving iface; receiving and
    # learning still work, only the kernel's own outbound Reply is
    # suppressed.
    #
    # No conflict with `<DUT_IP, DUT_MAC>` NUD_PERMANENT pin on the
    # tester (see reference_tester_neigh_pin.md) — that's the tester's
    # outgoing direction (resolving DUT), arp_ignore is the incoming
    # direction (replying to others).
    # Tester-side conditioning — the tester is always a Linux host we
    # own (this one), so this applies on every topology; only the
    # execution context (netns vs plain) differs, which
    # topology_exec_tester absorbs.
    local toggle_arp_ignore=0
    if [[ "$case_id" == "ARP_39" || "$case_id" == "ARP_40" ]]; then
        toggle_arp_ignore=1
        topology_exec_tester "$W" sysctl -qw "net.ipv4.conf.$tester_iface.arp_ignore=8" >/dev/null
    fi

    # §4.5 IPv4_AUTOCONF cluster: the tc8-dut's UT-Confirmation reply
    # (sendResponse → sendto) goes through the kernel stack, which
    # after the per-case DUT-side `neigh flush` above has no entry for
    # the tester. The kernel then emits its own ARP Request to resolve
    # <tester_ip> — eth_src=DUT_MAC, sender_proto_ip=DUT_IP,
    # target=tester_ip, which DOES match the cluster A field-shape
    # filter (`opcode==1 AND eth_src==DUT_MAC`) and breaks _01/_06/_08
    # (target not in 169.254/16, sender not 0). Pin the entry as
    # NUD_PERMANENT so the kernel never ARP-resolves tester. tc8-dut
    # LL state machine emits Probes/Announces via AF_PACKET SOCK_RAW
    # bypassing the kernel stack, so this pin doesn't suppress any
    # spec-relevant traffic. _03 isn't affected because its filter
    # is the full `is_arp_probe()` shape (sender_proto_ip==0) which
    # rejects the kernel ARP, but pinning is harmless and keeps
    # behaviour uniform across the cluster.
    #
    # §4.5.6.5 LINKLOCAL_PACKETS_04 / §4.5.6.6 NETWORK_PARTITIONS_01
    # likewise gate on `is_arp_announce()` (sender_ip == target_ip
    # ∈ 169.254/16) which already rejects the kernel's tester-resolve
    # ARP — pin is uniformly applied for consistency, not strict need.
    local toggle_dut_tester_neigh_pin=0
    case "$case_id" in
        IPv4_AUTOCONF_ADDRESS_SELECTION_*|IPv4_AUTOCONF_CONFLICT_*|IPv4_AUTOCONF_ANNOUNCING_*|IPv4_AUTOCONF_LINKLOCAL_PACKETS_*|IPv4_AUTOCONF_NETWORK_PARTITIONS_*)
            if [[ "$TOPOLOGY_DUT_CONDITIONING" == "1" ]]; then
                toggle_dut_tester_neigh_pin=1
                local tester_mac_pin
                tester_mac_pin=$(cat "$WORK_ROOT/$W/tester_mac")
                ip -n "$dut_ns" neigh replace "$TESTER_IP4" \
                    lladdr "$tester_mac_pin" \
                    dev "$veth_d" nud permanent
            else
                log_conditioning_skip "$W" "$case_id" \
                    "DUT-side <tester_ip> NUD_PERMANENT pin — suppresses the Linux reference DUT's kernel ARP resolve during UT confirmations"
            fi
            ;;
    esac

    # §4.7.6.7 CM_05/_06: the spec mandates DUT applies Option 3 (Router)
    # to the routing table on BOUND so post-BOUND egress to
    # IP-UNUSED-ADDRESS forwards via the gateway. The harness uses
    # `$DHCPV4_SERVER1_IP4` (kDefaultServerIdBe in the SCE side) as the
    # synthetic gateway — there is no real host at that IP, so the
    # DUT's ARP for the gateway would otherwise fail and Linux would
    # silently drop the egress before pcap sees it. Pre-pin the
    # gateway → tester-injected MAC binding as NUD_PERMANENT so the
    # DUT's first sendto resolves immediately to kTesterInjectedMac
    # (which the SCXML cond on udp.eth_dst then verifies).
    case "$case_id" in
        DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_05|DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_06)
            if [[ "$TOPOLOGY_DUT_CONDITIONING" == "1" ]]; then
                ip -n "$dut_ns" neigh replace "$DHCPV4_SERVER1_IP4" \
                    lladdr "$ARP_TESTER_INJECTED_MAC" \
                    dev "$veth_d" nud permanent
            else
                log_conditioning_skip "$W" "$case_id" \
                    "DUT-side synthetic-gateway NUD_PERMANENT pin — the external DUT must resolve the Option 3 router address itself"
            fi
            ;;
    esac

    # §4.2.4.2 Phase 3c Group E (ARP_48/49) compress Linux's ARP-cache
    # expiry timers so the DUT's cache transitions through STALE →
    # DELAY → PROBE within the test window:
    #   * `base_reachable_time_ms` — REACHABLE state TTL (kernel default
    #     30 s). Randomised by the kernel to [base/2, 3*base/2 − 1].
    #   * `delay_first_probe_time` — dwell in DELAY before PROBE
    #     (default 5 s; setup-netns.sh raises it to 30 s for Phase 2's
    #     ARP_03/05 absence-window guard).
    #   * `gc_stale_time` — STALE state dwell before GC-removal (default
    #     60 s) — incidental backstop, the PROBE path is the primary
    #     ARP-request trigger.
    local toggle_neigh_gc=0
    if [[ ( "$case_id" == "ARP_48" || "$case_id" == "ARP_49" ) \
          && "$TOPOLOGY_DUT_CONDITIONING" == "1" ]]; then
        toggle_neigh_gc=1
        # base_reachable_time_ms = 500 puts the kernel's randomised
        # REACHABLE expiry in [250, 749] ms — always before the first
        # UT 0x02 request reaches the DUT (~1.75 s after harness
        # start). First DUT egress USE therefore transitions STALE →
        # DELAY; the delay_first_probe_time knob below then schedules
        # DELAY → PROBE, at which point the kernel emits the broadcast
        # ARP Request the SCXML is waiting for (spec step 11 / 15).
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.base_reachable_time_ms=500" >/dev/null
        # delay_first_probe_time is the dwell in DELAY before PROBE.
        # setup-netns.sh sets this to 30 (Phase 2 absence tests
        # ARP_03/05 need NUD_PROBE kept out of their 3 s listen
        # window). Dropping to 1 here: after the first DUT USE
        # transitions STALE → DELAY, the next neigh timer tick (≤1 s)
        # fires DELAY → PROBE and the kernel emits ARP Request.
        # ARP_49's two-UDP flow still works because DELAY→PROBE fires
        # ~1 s after the FIRST USE (~1.75 s into stimulus), which is
        # AFTER the second UT request at ~2.25 s — order UDP1 → UDP2 →
        # ARP is preserved on the wire.
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.delay_first_probe_time=1"   >/dev/null
        # Keep `ucast_solicit` at kernel default (3). Setting it to 0 is
        # tempting (skip unicast probes our fake MAC1 wouldn't answer,
        # go straight to broadcast) but the Linux neigh state machine
        # computes `max_probes = UCAST_SOLICIT + APP_PROBES` when a
        # neighbour is already in NUD_PROBE — with UCAST_SOLICIT=0 and
        # APP_PROBES=0, the DELAY→PROBE transition fires `probes=0 >=
        # max_probes=0` immediately and the entry goes FAILED without
        # sending any ARP. Leaving UCAST_SOLICIT=3 makes Linux emit
        # unicast probes (opcode=1, sender_hw=DUT, target_proto_ip=
        # tester_ip); the SCXML's ARP-request guard treats unicast and
        # broadcast Requests identically.
        #
        # `net.ipv4.neigh.default.gc_interval` and `gc_thresh1` are
        # intentionally NOT set: the `default/` sysctl directory is not
        # exposed in child netns on this kernel build, so any write
        # would no-op and log an error. The DELAY → PROBE path is the
        # primary ARP-request trigger for Group E; GC is incidental.
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.gc_stale_time=1"             >/dev/null
    elif [[ ( "$case_id" == "ARP_48" || "$case_id" == "ARP_49" ) \
            && -z "${TOPOLOGY_UT_ARP_CACHE_TIMEOUT_S:-}" ]]; then
        # When the topology declares TOPOLOGY_UT_ARP_CACHE_TIMEOUT_S the
        # case conditions the DUT cache through UT 0x17 instead — no
        # sysctl substitute is being skipped, so no INFO either.
        log_conditioning_skip "$W" "$case_id" \
            "compressed neigh-cache expiry timers — the case's STALE/DELAY/PROBE window assumes a conditioned Linux reference DUT"
    fi

    # §4.3.3.2 ICMPv4_TYPE_04 compresses Linux's IP fragment reassembly
    # timer from the kernel default (30 s) down to 3 s per netns so the
    # tester-side post-send wait stays in the single-digit seconds
    # range. `net.ipv4.ipfrag_time` is the upper bound on how long the
    # DUT's reassembly context holds a partial datagram before dropping
    # it; lowering it lets the test assert "after the DUT's reassembly
    # timer expired, no Time Exceeded was emitted" without burning 30 s
    # of real time per case.
    #
    # §4.4.4.6 IPv4_FRAGMENTS_02/03/04 explicitly DO NOT get this
    # toggle — they need frag 0's bucket to stay alive at the DUT
    # through the phase-1 absence window (2 s) + phase-gap (~500 ms) +
    # phase-2 arrival (~2.5 s), which is tight against a 3 s reassembly
    # timer. Default ipfrag_time=30 s gives frag 0's bucket a 30 s
    # lifetime — well past phase 2's arrival — so the matched retry
    # completes reassembly cleanly.
    #
    # Netns destroy via the top-level trap is the safety net on
    # abnormal termination (sysctls live inside the netns); the
    # in-function restore below keeps the worker's state clean between
    # cases.
    local toggle_ipfrag_time=0
    case "$case_id" in
        ICMPv4_TYPE_04)
            if [[ "$TOPOLOGY_DUT_CONDITIONING" == "1" ]]; then
                toggle_ipfrag_time=1
                ip netns exec "$dut_ns" sysctl -qw "net.ipv4.ipfrag_time=3" >/dev/null
            else
                log_conditioning_skip "$W" "$case_id" \
                    "ipfrag_time=3 — the case's post-send wait assumes a compressed DUT reassembly timer"
            fi
            ;;
        # §4.4.4.7 IPv4_REASSEMBLY_10/_11/_12 — collapse Linux's
        # static reassembly timer from 30 s default to 2 s so the
        # spec's wait-vs-timer boundaries are exercised in seconds.
        # _10 verifies the ipIniReassembleTimeout boundary directly
        #   (Phase A: 1 s wait < 2 s timer, reassemble; Phase B: 3 s
        #   wait > 2 s timer, drop).
        # _11 (Large TTL): 3 s inter-fragment wait > 2 s timer; on
        #   Linux the timer ignores TTL so the bucket expires before
        #   frag 1 — fail_timeout (Linux known-fail). A strict-RFC 791
        #   DUT would extend the timer via MAX(TLB, TTL) and reply.
        # _12 (Low TTL): 1 s wait < 2 s timer; bucket alive at
        #   frag 1 regardless of TTL → reply. Invariant exercised:
        #   Low TTL must not shrink the timer below the wait — on
        #   Linux trivially satisfied (no TTL coupling); on a strict-
        #   RFC 791 DUT MAX(2, 2) preserves the 2 s window. Margin
        #   tightened from 30 s/1 s to 2 s/1 s vs the kernel default.
        # The spec's recommendation is 15 s; we collapse to 2 s here
        # so each case completes in seconds rather than tens of
        # seconds.
        IPv4_REASSEMBLY_10|IPv4_REASSEMBLY_11|IPv4_REASSEMBLY_12)
            if [[ "$TOPOLOGY_DUT_CONDITIONING" == "1" ]]; then
                toggle_ipfrag_time=1
                ip netns exec "$dut_ns" sysctl -qw "net.ipv4.ipfrag_time=2" >/dev/null
            else
                log_conditioning_skip "$W" "$case_id" \
                    "ipfrag_time=2 — the case's wait-vs-timer boundaries assume a compressed DUT reassembly timer"
            fi
            ;;
    esac

    # §4.8.6.11 TCP_RETRANSMISSION_TO_05 — Linux's default
    # `tcp_syn_linear_timeouts=4` keeps the first 4 SYN retransmit
    # RTOs at the constant TCP_TIMEOUT_INIT (1 s) before the
    # exponential branch in `tcp_retransmit_timer` engages — a
    # deliberate kernel optimisation for connection-setup latency
    # that violates RFC 6298 §5 step 5.5's literal "MUST set
    # RTO <- RTO * 2 on every retransmit". For this conformance
    # case to verify the DUT's *exponential-backoff capability*
    # (rather than Linux's setup-latency optimisation), we drop
    # `tcp_syn_linear_timeouts` to 0 in the dut_ns so doubling
    # kicks in from retransmit 1 — producing the 1 s / 2 s / 4 s
    # inter-frame sequence the SCXML guards expect. Sysctl scope
    # is per-netns; restoring on case exit keeps cross-case state
    # clean.
    local toggle_syn_linear_timeouts=0
    case "$case_id" in
        TCP_RETRANSMISSION_TO_05)
            if [[ "$TOPOLOGY_DUT_CONDITIONING" == "1" ]]; then
                toggle_syn_linear_timeouts=1
                ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_syn_linear_timeouts=0" >/dev/null
            else
                log_conditioning_skip "$W" "$case_id" \
                    "tcp_syn_linear_timeouts=0 — disables Linux's SYN linear-RTO optimisation; a strict-RFC 6298 DUT passes natively"
            fi
            ;;
    esac

    # §4.8.6.11 TCP_RETRANSMISSION_TO_04 — Linux's default
    # `tcp_recovery=1` (RACK) and `tcp_early_retrans=3` (TLP) trigger
    # a thin-stream "rapid retransmit" path on a single-segment
    # outstanding queue that holds icsk_rto at RTO_MIN baseline
    # (200 ms) instead of doubling on each fire — preserving
    # connection-recovery latency at the cost of RFC 6298 §5
    # step 5.5's literal exponential-backoff requirement. For this
    # conformance case to verify the DUT's exponential-backoff
    # capability for data segments, RACK and TLP are disabled in
    # the dut_ns so `tcp_retransmit_timer` follows the canonical
    # out_reset_timer path: state == TCP_ESTABLISHED && retransmits >
    # 0 ⇒ icsk_rto <<= 1 on every fire, yielding 200 / 400 / 800 ms
    # inter-frame deltas. Restored on case exit.
    local toggle_data_rto_recovery=0
    case "$case_id" in
        TCP_RETRANSMISSION_TO_04|TCP_RETRANSMISSION_TO_03)
            if [[ "$TOPOLOGY_DUT_CONDITIONING" == "1" ]]; then
                toggle_data_rto_recovery=1
                ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_early_retrans=0" >/dev/null
                ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_recovery=0" >/dev/null
            else
                log_conditioning_skip "$W" "$case_id" \
                    "tcp_early_retrans=0 + tcp_recovery=0 — disables Linux RACK/TLP thin-stream RTO; a strict-RFC 6298 DUT passes natively"
            fi
            ;;
    esac

    # Harness watchdog backstop (see HARNESS_BACKSTOP_SEC). Per-case timing
    # lives in the SCXML deadlines / stimulus bounds; the harness exits on
    # the SCXML final state, so this only catches a hang.
    local case_timeout=$HARNESS_BACKSTOP_SEC

    local -a expect_args=(
        "${TC8_DUT_EXPECT[@]}"
        "${ARP_DUT_EXPECT_STATIC[@]}"
        --expect "arp.dut_iface_mac=$dut_mac"
        --expect "dut.mac=$dut_mac"
        --expect "dhcpv4.dut_iface_mac=$dut_mac"
        "${ICMPV4_DUT_EXPECT_STATIC[@]}"
        "${IPV4_DUT_EXPECT_STATIC[@]}"
    )

    # §5.1.5.5 BASIC_03 needs the SCXML eventgroup_id assertion to match
    # the eventgroup the harness actually subscribes to (0x0002, declared
    # under TestEventUINT8 in dut/ets/ets.fdepl + dut/dut_service/
    # vsomeip.json). Other §5.1 cases keep the global 0x0001 default.
    # `--expect` is last-wins per src/cli/expect_parser.cpp, so appending
    # the override here cleanly shadows TC8_DUT_EXPECT.
    declare -A CASE_EXPECT_OVERRIDES=(
        [SOMEIPSRV_BASIC_03]="eventgroup_id=0x0002"
        # §5.1.5.1.28 FORMAT_28 round-trip eventgroup_id check: the
        # trait subscribes to eg 0x0002 (Ack path); SCXML cond checks
        # captured.eventgroup_id == expected.eventgroup_id, so the
        # --expect must match the trait's subscribe target.
        # Sister cases FORMAT_19..27 don't read expected.eventgroup_id
        # (they assert Type/Length/IndexFirst/Service/Instance/Major/
        # TTL/Reserved against the configured identity, which is unchanged)
        # so they need no per-case override even though their stimulus
        # also subscribes to 0x0002 for the Ack path.
        [SOMEIPSRV_FORMAT_28]="eventgroup_id=0x0002"
        # §5.1.5.3 SD_MESSAGE_09 — same eventgroup target as BASIC_03;
        # the verdict differs (Notification UDP src_port vs OfferService
        # Endpoint Option port) but the stimulus + Subscribe target are
        # identical.
        [SOMEIPSRV_SD_MESSAGE_09]="eventgroup_id=0x0002"
        # §5.1.5.5 OPTIONS_08..14 + §5.1.5.3 SD_MESSAGE_13 subscribe to
        # the multicast-configured eventgroup 0x0008 (declared under
        # TestEventUINT8 in dut/ets/ets.fdepl + the matching multicast
        # block in vsomeip.json). The override keeps the SCXML
        # eventgroup_id assertions consistent with the stimulus.
        [SOMEIPSRV_OPTIONS_08]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_09]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_10]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_11]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_12]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_13]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_14]="eventgroup_id=0x0008"
        [SOMEIPSRV_SD_MESSAGE_13]="eventgroup_id=0x0008"
        # §5.1.6 SOMEIP_ETS_086/_087 lift BASIC_03's Subscribe→Ack→
        # Notification chain on eventgroups 0x02 / 0x05 respectively.
        # Same per-case eventgroup_id override pattern as BASIC_03 keeps
        # the SCXML phase 2 assertion consistent with the stimulus.
        [SOMEIP_ETS_086]="eventgroup_id=0x0002"
        [SOMEIP_ETS_087]="eventgroup_id=0x0005"
        # §5.1.6 SOMEIP_ETS_121 mirrors _087 — Subscribe(eg 0x05)
        # phase 2 cond uses expected.eventgroup_id.
        [SOMEIP_ETS_121]="eventgroup_id=0x0005"
        # §5.1.6 SOMEIP_ETS_094 subscribes to eg 0x02 (server-side
        # reboot detection chain reuses the BASIC_03 wire shape).
        [SOMEIP_ETS_094]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_154 stimulus targets configured eg 0x02 so
        # the option walker reaches the IPv4 endpoint validation step
        # (subscribing to unknown eg would silent-drop earlier).
        [SOMEIP_ETS_154]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_162/_163 mirror ETS_154 (configured eg 0x02
        # so the option walker reaches the IPv4 validation step before
        # silent-drop).
        [SOMEIP_ETS_162]="eventgroup_id=0x0002"
        [SOMEIP_ETS_163]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_109/_110/_111/_112/_113/_119 mirror ETS_134
        # (configured eg 0x02 keeps the option walker active so each
        # malformation axis is exercised before the silent-drop gate).
        [SOMEIP_ETS_109]="eventgroup_id=0x0002"
        [SOMEIP_ETS_110]="eventgroup_id=0x0002"
        [SOMEIP_ETS_111]="eventgroup_id=0x0002"
        [SOMEIP_ETS_112]="eventgroup_id=0x0002"
        [SOMEIP_ETS_113]="eventgroup_id=0x0002"
        [SOMEIP_ETS_119]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_115/_116/_174/_178 mirror ETS_134 (configured
        # eg 0x02 keeps option walker active for the relevant axis).
        [SOMEIP_ETS_115]="eventgroup_id=0x0002"
        [SOMEIP_ETS_116]="eventgroup_id=0x0002"
        [SOMEIP_ETS_174]="eventgroup_id=0x0002"
        [SOMEIP_ETS_178]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_176/_177 stimulus on configured eg 0x02 so the
        # SubscribeAck observation matches the eventgroup_id assertion.
        [SOMEIP_ETS_176]="eventgroup_id=0x0002"
        [SOMEIP_ETS_177]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_117/_173/_175 also subscribe on configured
        # eg 0x02 so verdicts assert against the same eventgroup_id.
        [SOMEIP_ETS_117]="eventgroup_id=0x0002"
        [SOMEIP_ETS_173]="eventgroup_id=0x0002"
        [SOMEIP_ETS_175]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_107/_108 subscribe on configured eg 0x05.
        [SOMEIP_ETS_107]="eventgroup_id=0x0005"
        [SOMEIP_ETS_108]="eventgroup_id=0x0005"
        # §5.1.6 SOMEIP_ETS_120 subscribes to configured eg 0x02.
        [SOMEIP_ETS_120]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_155 chains Subscribe / Stop / Subscribe on
        # configured eg 0x02 so both Acks land on the eventgroup_id cond.
        [SOMEIP_ETS_155]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_152 burst Subscribes target configured eg 0x02
        # so each emit elicits an Ack and bumps vsomeip's outgoing SD
        # session_id counter (every Ack contributes to the wrap timeline).
        [SOMEIP_ETS_152]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_147 subscribes to eg 0x02 (mirror of _086).
        [SOMEIP_ETS_147]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_148/_149/_151 also subscribe to eg 0x02.
        [SOMEIP_ETS_148]="eventgroup_id=0x0002"
        [SOMEIP_ETS_149]="eventgroup_id=0x0002"
        [SOMEIP_ETS_151]="eventgroup_id=0x0002"
        # §5.1.6 SOMEIP_ETS_150 subscribes to eg 0x06 (Multicast variant).
        [SOMEIP_ETS_150]="eventgroup_id=0x0006"
    )
    local case_overrides="${CASE_EXPECT_OVERRIDES[$case_id_canon]:-}"
    if [[ -n "$case_overrides" ]]; then
        for tok in $case_overrides; do
            expect_args+=(--expect "$tok")
        done
    fi

    # When --log-dir is set, additionally save every captured frame to a
    # per-case pcap file for post-mortem debugging of flaky failures.
    local -a extra_args=()
    if [[ -n "$LOG_DIR" ]]; then
        extra_args+=(--pcap-dump "$LOG_DIR/${case_id}.pcap")
    fi

    # Tier-2 DUT-control backend passthrough (--dut-control). 'testability'
    # drives seam-migrated cases (those whose stimulus takes IDutControl&)
    # through the AUTOSAR Testability endpoint (port 30700) instead of the
    # default in-house opcode UT — the North Star validation path. Cases
    # that call the opcode builders directly ignore the flag. Empty = opcode
    # (every existing case unaffected).
    if [[ -n "$DUT_CONTROL" ]]; then
        extra_args+=(--dut-control "$DUT_CONTROL")
    fi

    # §5.1.5 SOMEIPSRV multi-instance / multi-service plumbing:
    # SD_MESSAGE_01/_02 + RPC_14/_17 require Number Of Instances=2 for
    # SERVICE-ID-1; RPC_01/_02/_13 require a second SERVICE-ID-2. Each
    # variant ships its own vsomeip.json (services[] differs) and is
    # gated at runtime by env vars dut_main.cpp inspects (TC8_DUT_*).
    # The single-instance baseline (every other §5.1.5 case) is
    # untouched.
    #
    # CRITICAL: SD_MESSAGE_17/_18 use `cfg.someip.instance_id + 1` and
    # `cfg.someip.major_version + 1` as UNKNOWN-* sentinels; activating
    # instance 0x0002 in the multi-instance variant would convert
    # vsomeip's Nack into an Ack and break those legacy assertions.
    # Mapping a §5.1.5 case here MUST be paired with a verification that
    # its cond does not depend on (instance_id+1) or (major_version+1)
    # being unknown.
    local dut_vsomeip_cfg="$VSOMEIP_CFG"
    local -a dut_extra_env=()
    declare -A CASE_VSOMEIP_VARIANT=(
        [SOMEIPSRV_SD_MESSAGE_01]="multi-instance"
        [SOMEIPSRV_SD_MESSAGE_02]="multi-instance"
        [SOMEIPSRV_RPC_14]="multi-instance"
        [SOMEIPSRV_RPC_17]="multi-instance"
        [SOMEIPSRV_RPC_01]="multi-service"
        [SOMEIPSRV_RPC_02]="multi-service"
        [SOMEIPSRV_RPC_13]="multi-service-shared-port"
        # §5.1.6 SOMEIP_ETS_097 routes clientServiceActivate to the
        # CommonAPI Proxy spawn path (ets3 ClientTarget) instead of the
        # ETS_098..101 raw-UDP runner. Env-gated so the existing
        # client-mode cases keep their wire shape.
        [SOMEIP_ETS_097]="client-mode"
        # §5.1.6 SOMEIP_ETS_084 reuses ETS_097's CommonAPI Proxy path —
        # observation of DUT-emitted Subscribe + StopSubscribe for ets3
        # depends on the proxy spawn on activate / unsubscribe on deactivate.
        [SOMEIP_ETS_084]="client-mode"
        # §5.1.6 SOMEIP_ETS_081 reuses the same Proxy spawn path; the
        # reboot OfferService verdict depends on the DUT vsomeip TCP
        # client-endpoint lifecycle reacting to the lower-sid offer.
        [SOMEIP_ETS_081]="client-mode"
        # §5.1.6 SOMEIP_ETS_082 selects the UDP-unreliable target event
        # in ets3.fdepl (eventgroup 0x000B) so the DUT-emitted
        # SubscribeEventgroup carries an IPv4 Endpoint Option with
        # l4proto = 0x11 (UDP). Implies TC8_DUT_CLIENT_MODE=1.
        [SOMEIP_ETS_082]="client-mode-udp"
        # §5.1.6 SOMEIP_ETS_106 ClientServiceSubscribeEventgroup chain reuses
        # the UDP variant: clientServiceActivate + clientServiceSubscribeEvent
        # group + UDP-OfferService → DUT proxy emits Subscribe via UDP.
        [SOMEIP_ETS_106]="client-mode-udp"
        # §5.1.6 SOMEIP_ETS_103/_104/_105 GetLastValueOfEvent* require Client
        # Mode active so clientServiceSubscribeEventgroup wires up the proxy
        # subscribe path (without it the Method 0x32 dispatch is a no-op).
        [SOMEIP_ETS_103]="client-mode-udp"
        [SOMEIP_ETS_104]="client-mode-udp"
        [SOMEIP_ETS_105]="client-mode-udp"
    )
    case "${CASE_VSOMEIP_VARIANT[$case_id_canon]:-}" in
        multi-instance)
            dut_vsomeip_cfg="$ROOT/dut/dut_service/vsomeip-multi-instance.json"
            dut_extra_env+=(TC8_DUT_INSTANCE_2=1)
            ;;
        multi-service)
            dut_vsomeip_cfg="$ROOT/dut/dut_service/vsomeip-multi-service.json"
            dut_extra_env+=(TC8_DUT_SERVICE_2=1)
            ;;
        multi-service-shared-port)
            dut_vsomeip_cfg="$ROOT/dut/dut_service/vsomeip-multi-service-shared-port.json"
            dut_extra_env+=(TC8_DUT_SERVICE_2=1)
            ;;
        client-mode)
            dut_extra_env+=(TC8_DUT_CLIENT_MODE=1)
            ;;
        client-mode-udp)
            dut_extra_env+=(TC8_DUT_CLIENT_MODE=1 TC8_DUT_CLIENT_MODE_UDP=1)
            ;;
    esac

    # §4.7.6.5 USAGE_01 / Topology 2 multi-iface: harness opens a
    # second `PcapSource` on TIface-1 so DUT-emitted DISCOVERs from
    # DIface-1 reach the same pipeline as DIface-0's. Stimulus
    # injection still uses the primary iface (UT server listens
    # INADDR_ANY → dispatches by iface_index byte). A topology without
    # a second tester interface cannot execute the case at all —
    # explicit SKIP, never a misleading timeout FAIL.
    if [[ "$case_id" == "DHCPv4_CLIENT_USAGE_01" ]]; then
        local sec_iface
        sec_iface=$(topology_tester_iface_secondary "$W")
        if [[ -z "$sec_iface" ]]; then
            skip_case "$W" "$case_id" \
                "requires a secondary tester interface (TC8 Topology 2); topology '$TOPOLOGY' provides none"
            (( keep_logs == 0 )) && rm -f "$hlog" "$dlog"
            return 0
        fi
        extra_args+=(--interface-secondary "$sec_iface")
    fi

    # Order matters: harness first, then tc8-dut. SD Session ID starts
    # at 0x0001 for the very first OfferService after vsomeip SD init —
    # if tc8-dut starts first, pcap opens after that initial
    # OfferService has already been sent, and FORMAT_02
    # (session_id==0x0001) fails because the first captured frame is a
    # later repetition (0x0002+). --dut-first inverts this for negative
    # tests. Non-spawning topologies assume a persistent external DUT —
    # start order does not apply there (and --dut-first is rejected at
    # startup).
    local hp
    if [[ "$TOPOLOGY_SUPPORTS_DUT_SPAWN" == "1" ]]; then
        if [[ "$DUT_FIRST" == "1" ]]; then
            topology_start_dut "$W" "$dlog" "$dut_vsomeip_cfg" \
                "${dut_extra_env[@]}" >/dev/null
            sleep 1.5
            hp=$(topology_run_harness "$W" "$hlog" test \
                --case "$case_id" -i "$tester_iface" -t "$case_timeout" \
                "${expect_args[@]}" "${extra_args[@]}")
        else
            hp=$(topology_run_harness "$W" "$hlog" test \
                --case "$case_id" -i "$tester_iface" -t "$case_timeout" \
                "${expect_args[@]}" "${extra_args[@]}")
            sleep 0.5
            topology_start_dut "$W" "$dlog" "$dut_vsomeip_cfg" \
                "${dut_extra_env[@]}" >/dev/null
        fi
    else
        if [[ "$dut_vsomeip_cfg" != "$VSOMEIP_CFG" || ${#dut_extra_env[@]} -gt 0 ]]; then
            echo "[w$W] INFO ${case_id}: case requests DUT flavor '$(basename "$dut_vsomeip_cfg")${dut_extra_env[*]:+ ${dut_extra_env[*]}}' — topology '$TOPOLOGY' does not spawn the DUT; the external DUT must provide the equivalent service"
        fi
        echo "[w$W] INFO ${case_id}: using persistent external DUT at $DUT_IP4 (topology '$TOPOLOGY')" >"$dlog"
        hp=$(topology_run_harness "$W" "$hlog" test \
            --case "$case_id" -i "$tester_iface" -t "$case_timeout" \
            "${expect_args[@]}" "${extra_args[@]}")
    fi

    # Wait for the harness to reach a verdict (or hit its own -t
    # timeout). The harness exits the poll loop and prints the verdict as
    # soon as the SCXML reaches a final state; polling on $hp lets fast
    # cases finish without burning the worst-case envelope. Upper bound
    # is (case_timeout + 3 s stimulus budget) / 0.2 s poll tick, capped
    # at 1100 iterations (220 s wall) so a hung harness can't stretch the
    # smoke suite indefinitely. The 1100 ceiling accommodates §5.1.6
    # SOMEIP_ETS_152 (200 s `case_timeout` to cover the ~140 s wall the
    # SD-session-id wrap burst needs against vsomeip's ~480 acks/sec
    # outgoing rate); the prior 500 ceiling fit §4.8.6.1 BASICS_11/12's
    # 90 s envelope but capped ETS_152 at 100 s wall (premature kill
    # before phase 2 wrap observation). Raise it further only if a later
    # case's case_timeout exceeds 215 s.
    local wait_budget=$(( (case_timeout + 3) * 5 ))
    (( wait_budget > 1100 )) && wait_budget=1100
    local _
    for _ in $(seq 1 "$wait_budget"); do
        kill -0 "$hp" 2>/dev/null || break
        sleep 0.2
    done

    kill_worker_procs "$harness_link"
    topology_stop_dut "$W"

    # Restore arp_accept to the Phase 2 default. Idempotent — the toggle
    # above only flipped it for ARP_38, but re-setting to 1 is harmless
    # for other cases and guards against leaks across cases on the same
    # worker (setup-netns.sh sets 1 at worker bring-up; the per-case
    # toggle scope here stays symmetric).
    if [[ $toggle_arp_accept -eq 1 ]]; then
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.conf.$veth_d.arp_accept=1" >/dev/null
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.conf.all.arp_accept=1"     >/dev/null
    fi

    # Restore arp_ignore to the default (0 = reply to all). Symmetric to
    # the ARP_39/40 toggle above — tester-side, so it applies on every
    # topology; on single-pc the netns destroy is the additional safety
    # net.
    if [[ $toggle_arp_ignore -eq 1 ]]; then
        topology_exec_tester "$W" sysctl -qw "net.ipv4.conf.$tester_iface.arp_ignore=0" >/dev/null
    fi

    # Drop the §4.5 NUD_PERMANENT pin on <tester_ip>. `ip neigh
    # flush` (run at the next case's start, line ~366) skips
    # PERMANENT entries by default, so a leak here would survive
    # into a follow-up ARP_07..15 case on the same worker — those
    # cases require the DUT kernel to ARP-resolve tester from a
    # cold cache, which the leaked pin would suppress.
    if [[ $toggle_dut_tester_neigh_pin -eq 1 ]]; then
        ip -n "$dut_ns" neigh del "$TESTER_IP4" dev "$veth_d" 2>/dev/null || true
    fi

    # Restore neigh GC sysctls to the kernel defaults. If another ARP
    # case runs on the same worker after ARP_48/49, a leaked low
    # `base_reachable_time_ms` would starve the cache and turn
    # ARP_03..06's positive paths into false UDP-eth_dst failures.
    # trap cleanup EXIT is the backstop on abnormal termination (netns
    # destroy wipes sysctls), but in-function restore keeps the
    # worker's state clean between cases.
    if [[ $toggle_neigh_gc -eq 1 ]]; then
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.base_reachable_time_ms=30000" >/dev/null
        # Restore to setup-netns.sh's Phase-2 value (30), NOT the kernel
        # default (5) — ARP_03/05 rely on the 30 s dwell to keep
        # NUD_PROBE out of their 3 s absence window.
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.delay_first_probe_time=30"    >/dev/null
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.gc_stale_time=60"              >/dev/null
    fi

    # Restore ipfrag_time to the kernel default (30 s). Leaking 3 s to
    # a subsequent case is harmless today (no other fragment-heavy
    # case on the same worker), but the in-function restore keeps
    # worker state symmetric with the arp/neigh toggles above.
    if [[ $toggle_ipfrag_time -eq 1 ]]; then
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.ipfrag_time=30" >/dev/null
    fi

    # Restore tcp_syn_linear_timeouts to the kernel default 4 after
    # TCP_RETRANSMISSION_TO_05. Cross-case leak is harmless today (no
    # sibling case depends on the linear-timeouts default), but
    # symmetric restoration keeps worker state predictable.
    if [[ $toggle_syn_linear_timeouts -eq 1 ]]; then
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_syn_linear_timeouts=4" >/dev/null
    fi

    # Restore RACK / TLP defaults after TCP_RETRANSMISSION_TO_04.
    # Cross-case leak is harmless today (no sibling case depends on
    # those defaults), but symmetric restoration keeps worker state
    # predictable.
    if [[ $toggle_data_rto_recovery -eq 1 ]]; then
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_early_retrans=3" >/dev/null
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_recovery=1" >/dev/null
    fi

    # Conformance verdict classes that are NOT a DUT violation (ISO/IEC 9646 /
    # TTCN-3 model), read from the harness `verdict  :` line (the donedata SSOT
    # via verdictFor):
    #   skip         — the selected --dut-control backend lacks a capability the
    #                  case requires (e.g. a kernel state-probe absent from
    #                  standard AUTOSAR testability; Tier-2 2b#4).
    #   inconclusive — the asserted condition was not exercised within the
    #                  observation window (e.g. a long throughput race did not
    #                  reach its boundary): the DUT was not shown to violate
    #                  anything, so this must not be a FAIL.
    #   error        — a precondition / harness step failed (e.g. the DUT stack
    #                  never came up): a test-environment fault, not a DUT defect.
    # All three route to the skip ledger as <skipped/> — none reds the
    # conformance gate; only an observed FAIL does. The class prefix is kept in
    # the reason so the three stay distinguishable in the summary + JUnit.
    local nonfail_reason=""
    if [[ -r "$hlog" ]]; then
        nonfail_reason=$(grep -m1 -E '^verdict  : (skip|inconclusive|error):' "$hlog" 2>/dev/null \
            | sed -E 's/^verdict  : ((skip|inconclusive|error):.*)$/\1/' || true)
    fi

    {
        echo "=========================================="
        echo "[w$W] ${case_id}"
        echo "=========================================="
        echo "---- harness output ----"
        cat "$hlog"
        echo "---- tc8-dut output (tail) ----"
        tail -20 "$dlog"
        echo "--------------------------------"
        if [[ -n "$nonfail_reason" ]]; then
            echo "[w$W] SKIP ${case_id} — ${nonfail_reason}"
        elif grep -q 'verdict  : pass' "$hlog"; then
            echo "[w$W] PASS ${case_id}"
        else
            echo "[w$W] FAIL ${case_id} did not return pass verdict"
        fi
    } | emit_block

    if [[ -n "$nonfail_reason" ]]; then
        record_skip "$W" "$case_id" "$nonfail_reason"
        if (( keep_logs == 0 )); then
            rm -f "$hlog" "$dlog"
        fi
        return 0
    fi

    local rc=0
    grep -q 'verdict  : pass' "$hlog" || rc=1
    junit_record_case "$W" "$case_id" positive "$start_ts" "$hlog" "$rc"
    if (( keep_logs == 0 )); then
        rm -f "$hlog" "$dlog"
    fi
    return $rc
}

# Runs a case with one `--expect` key deliberately replaced by a wrong
# value and asserts the harness reports the expected `fail:*` reason.
# Used by --negative to prove that FORMAT_14..18 + ARP_13..15 guards
# aren't trivially-true.
#
# Args: worker_id case_id wrong_token expected_fail_reason
run_negative_case() {
    local W=$1
    local case_id=$2
    # Canonical case identity for the override maps — see run_case
    # (case-insensitive map keys, P10).
    local case_id_canon=${case_id^^}
    local wrong_token=$3
    local expected_reason=$4
    local start_ts=$EPOCHREALTIME
    local tester_ns="tc8-tester-$W"
    local dut_ns="tc8-dut-$W"
    local veth_t="veth-tester-$W"
    local veth_d="veth-dut-$W"
    local vsp="$VSOMEIP_BASE/$W/"
    local mock_dut_link="$vsp/tc8-dut"
    local harness_link="$vsp/tc8-harness"
    local dut_mac
    dut_mac=$(cat "$WORK_ROOT/$W/dut_mac")

    local hlog dlog keep_logs
    if [[ -n "$LOG_DIR" ]]; then
        hlog="$LOG_DIR/${case_id}.harness.log"
        dlog="$LOG_DIR/${case_id}.dut.log"
        keep_logs=1
    else
        hlog=$(mktemp "$WORK_ROOT/$W/${case_id}.harness.XXXXXX")
        dlog=$(mktemp "$WORK_ROOT/$W/${case_id}.dut.XXXXXX")
        keep_logs=0
    fi

    rm -f "$VSOMEIP_BASE/$W"/vsomeip-* "$VSOMEIP_BASE/$W"/vsomeip.lck 2>/dev/null || true
    : >"$hlog"
    : >"$dlog"

    ip -n "$dut_ns" neigh flush dev "$veth_d"

    # Mirror run_case's per-case arp_accept toggle for ARP_38. No negative
    # row targets ARP_38 today (the pass-path fail-guard uses
    # `expected.tester_mac` which would need a symmetric tester_real_mac
    # CLI split before it could be meaningfully overridden), but keeping
    # this symmetric with run_case prevents a silent misbehaviour the
    # day that row is added.
    local toggle_arp_accept=0
    if [[ "$case_id" == "ARP_38" ]]; then
        toggle_arp_accept=1
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.conf.$veth_d.arp_accept=0" >/dev/null
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.conf.all.arp_accept=0"     >/dev/null
    fi

    # Mirror run_case's per-case ipfrag_time toggle. The negative path
    # for IPv4_REASSEMBLY_10/_12 lands on fail_*_echo_id (id flip)
    # before any timer-coupled outcome differs, so the toggle does not
    # change the verdict — but symmetric sysctl state across run_case
    # / run_negative_case is the project convention (see ICMPv4_TYPE_04
    # below and the cross-cutting "mirror run_case sysctl toggles"
    # commit 9b726a0). _11 carries no negative row (positive path
    # already lands on fail_timeout on Linux); the toggle is gated on
    # case-id so its absence in NEG_ROWS leaves the run_negative_case
    # branch a no-op for that id.
    local toggle_ipfrag_time=0
    case "$case_id" in
        ICMPv4_TYPE_04)
            toggle_ipfrag_time=1
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.ipfrag_time=3" >/dev/null
            ;;
        IPv4_REASSEMBLY_10|IPv4_REASSEMBLY_11|IPv4_REASSEMBLY_12)
            toggle_ipfrag_time=1
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.ipfrag_time=2" >/dev/null
            ;;
    esac

    # Mirror run_case's RETRANSMISSION_TO sysctl toggles for the
    # negative path. The negative case fails on its first listening
    # deadline (DUT-side wrong-IP injection makes the first
    # is_dut_*-segment guard unreachable), so neither toggle changes
    # the verdict — the listen-window expires before any RTO
    # observation. Keeping the toggles symmetric with run_case keeps
    # cross-case sysctl state predictable and avoids a future
    # silent-asymmetry surprise if a negative variant ever exercises
    # the retx path.
    local toggle_syn_linear_timeouts=0
    case "$case_id" in
        TCP_RETRANSMISSION_TO_05)
            toggle_syn_linear_timeouts=1
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_syn_linear_timeouts=0" >/dev/null
            ;;
    esac
    local toggle_data_rto_recovery=0
    case "$case_id" in
        TCP_RETRANSMISSION_TO_04|TCP_RETRANSMISSION_TO_03)
            toggle_data_rto_recovery=1
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_early_retrans=0" >/dev/null
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_recovery=0" >/dev/null
            ;;
    esac

    # §4.2.4.2 Phase 3c Group D — mirror run_case's tester-side
    # `arp_ignore=8` toggle for ARP_39/40. The negative path lands on
    # `fail:udp_eth_dst_not_injected_macN` via the tester-kernel
    # auto-Reply race (DUT learns kernel MAC ≠ overridden wrong-mac)
    # so the verdict is correct without the toggle. Mirroring keeps
    # the cross-cutting "run_case sysctl symmetric in run_negative_case"
    # convention uniform with the ARP_38 precedent above and prevents
    # a silent misbehaviour the day a NEG variant exercises the
    # cache-stickiness path directly.
    local toggle_arp_ignore=0
    if [[ "$case_id" == "ARP_39" || "$case_id" == "ARP_40" ]]; then
        toggle_arp_ignore=1
        ip netns exec "$tester_ns" sysctl -qw "net.ipv4.conf.$veth_t.arp_ignore=8" >/dev/null
    fi

    # §4.2.4.2 Phase 3c Group E — mirror run_case's per-case neigh GC
    # sysctl block for ARP_48/49. The negative path's wait_udp1 fail
    # branch fires before the cache-expiry path becomes relevant
    # (UDP1 emits with cached MAC1 whether REACHABLE or DELAY) so
    # the verdict is correct without the toggle. Same forward-defense
    # rationale as the ARP_38 / ARP_39/40 mirrors above.
    local toggle_neigh_gc=0
    if [[ "$case_id" == "ARP_48" || "$case_id" == "ARP_49" ]]; then
        toggle_neigh_gc=1
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.base_reachable_time_ms=500" >/dev/null
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.delay_first_probe_time=1"   >/dev/null
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.gc_stale_time=1"             >/dev/null
    fi

    # Rebuild the expect array: keep every baseline entry whose key does
    # not match the wrong token's key, then append the wrong value. The
    # baseline combines SOME/IP and ARP tokens so this loop handles
    # negatives for either protocol without per-protocol branching.
    local -a baseline=(
        "${TC8_DUT_EXPECT[@]}"
        "${ARP_DUT_EXPECT_STATIC[@]}"
        --expect "arp.dut_iface_mac=$dut_mac"
        --expect "dut.mac=$dut_mac"
        --expect "dhcpv4.dut_iface_mac=$dut_mac"
        "${ICMPV4_DUT_EXPECT_STATIC[@]}"
        "${IPV4_DUT_EXPECT_STATIC[@]}"
    )
    local wrong_key="${wrong_token%%=*}"
    local -a override=()
    local i=0 tok
    while (( i < ${#baseline[@]} )); do
        if [[ "${baseline[i]}" == "--expect" ]]; then
            tok="${baseline[i+1]}"
            if [[ "${tok%%=*}" != "$wrong_key" ]]; then
                override+=(--expect "$tok")
            fi
            (( i += 2 ))
        else
            (( i += 1 ))
        fi
    done
    override+=(--expect "$wrong_token")

    # Mirror run_case: when --log-dir is set, capture the per-case pcap so
    # a flaky negative (should not happen, but parity matters) is debuggable.
    local -a neg_extra_args=()
    if [[ -n "$LOG_DIR" ]]; then
        neg_extra_args+=(--pcap-dump "$LOG_DIR/${case_id}.neg.pcap")
    fi

    # Mirror run_case's §5.1.5 multi-instance / multi-service variant
    # dispatch so SOMEIPSRV negatives that depend on the multi-* DUT
    # plumbing (RPC_14/_17 phase 2 cond on expected.service_id, etc.)
    # actually exercise the phase they're trying to fault.
    local neg_dut_vsomeip_cfg="$VSOMEIP_CFG"
    local -a neg_dut_extra_env=()
    declare -A NEG_CASE_VSOMEIP_VARIANT=(
        [SOMEIPSRV_SD_MESSAGE_01]="multi-instance"
        [SOMEIPSRV_SD_MESSAGE_02]="multi-instance"
        [SOMEIPSRV_RPC_14]="multi-instance"
        [SOMEIPSRV_RPC_17]="multi-instance"
        [SOMEIPSRV_RPC_01]="multi-service"
        [SOMEIPSRV_RPC_02]="multi-service"
        [SOMEIPSRV_RPC_13]="multi-service-shared-port"
        [SOMEIP_ETS_097]="client-mode"
        [SOMEIP_ETS_084]="client-mode"
        [SOMEIP_ETS_081]="client-mode"
        [SOMEIP_ETS_082]="client-mode-udp"
        [SOMEIP_ETS_106]="client-mode-udp"
        [SOMEIP_ETS_103]="client-mode-udp"
        [SOMEIP_ETS_104]="client-mode-udp"
        [SOMEIP_ETS_105]="client-mode-udp"
    )
    case "${NEG_CASE_VSOMEIP_VARIANT[$case_id_canon]:-}" in
        multi-instance)
            neg_dut_vsomeip_cfg="$ROOT/dut/dut_service/vsomeip-multi-instance.json"
            neg_dut_extra_env+=(TC8_DUT_INSTANCE_2=1)
            ;;
        multi-service)
            neg_dut_vsomeip_cfg="$ROOT/dut/dut_service/vsomeip-multi-service.json"
            neg_dut_extra_env+=(TC8_DUT_SERVICE_2=1)
            ;;
        multi-service-shared-port)
            neg_dut_vsomeip_cfg="$ROOT/dut/dut_service/vsomeip-multi-service-shared-port.json"
            neg_dut_extra_env+=(TC8_DUT_SERVICE_2=1)
            ;;
        client-mode)
            neg_dut_extra_env+=(TC8_DUT_CLIENT_MODE=1)
            ;;
        client-mode-udp)
            neg_dut_extra_env+=(TC8_DUT_CLIENT_MODE=1 TC8_DUT_CLIENT_MODE_UDP=1)
            ;;
    esac

    # Mirror run_case's CASE_EXPECT_OVERRIDES so a negative whose stimulus
    # subscribes to a non-default eventgroup (e.g. SD_MESSAGE_13 → 0x0008)
    # still asserts against the correct expected.eventgroup_id baseline.
    # `--expect` is last-wins so appending the override after the wrong
    # token cleanly shadows the global default without colliding with
    # the wrong_key strip above (which only removes the `wrong_token`
    # key from baseline). Skipped for keys whose wrong_token would
    # itself touch the override key — none today.
    declare -A NEG_CASE_EXPECT_OVERRIDES=(
        [SOMEIPSRV_OPTIONS_08]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_09]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_10]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_11]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_12]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_13]="eventgroup_id=0x0008"
        [SOMEIPSRV_OPTIONS_14]="eventgroup_id=0x0008"
        [SOMEIPSRV_SD_MESSAGE_13]="eventgroup_id=0x0008"
        # §5.1.6 SOMEIP_ETS_086/_087 mirror run_case's per-case
        # eventgroup_id override so the negative service_id flip still
        # asserts against the correct eventgroup_id (the cond never
        # fires, but symmetry keeps the harness state consistent).
        [SOMEIP_ETS_086]="eventgroup_id=0x0002"
        [SOMEIP_ETS_087]="eventgroup_id=0x0005"
        [SOMEIP_ETS_121]="eventgroup_id=0x0005"
        [SOMEIP_ETS_094]="eventgroup_id=0x0002"
        [SOMEIP_ETS_154]="eventgroup_id=0x0002"
        [SOMEIP_ETS_162]="eventgroup_id=0x0002"
        [SOMEIP_ETS_163]="eventgroup_id=0x0002"
        [SOMEIP_ETS_109]="eventgroup_id=0x0002"
        [SOMEIP_ETS_110]="eventgroup_id=0x0002"
        [SOMEIP_ETS_111]="eventgroup_id=0x0002"
        [SOMEIP_ETS_112]="eventgroup_id=0x0002"
        [SOMEIP_ETS_113]="eventgroup_id=0x0002"
        [SOMEIP_ETS_119]="eventgroup_id=0x0002"
        [SOMEIP_ETS_115]="eventgroup_id=0x0002"
        [SOMEIP_ETS_116]="eventgroup_id=0x0002"
        [SOMEIP_ETS_174]="eventgroup_id=0x0002"
        [SOMEIP_ETS_178]="eventgroup_id=0x0002"
        [SOMEIP_ETS_176]="eventgroup_id=0x0002"
        [SOMEIP_ETS_177]="eventgroup_id=0x0002"
        [SOMEIP_ETS_117]="eventgroup_id=0x0002"
        [SOMEIP_ETS_173]="eventgroup_id=0x0002"
        [SOMEIP_ETS_175]="eventgroup_id=0x0002"
        [SOMEIP_ETS_107]="eventgroup_id=0x0005"
        [SOMEIP_ETS_108]="eventgroup_id=0x0005"
        [SOMEIP_ETS_120]="eventgroup_id=0x0002"
        [SOMEIP_ETS_155]="eventgroup_id=0x0002"
        [SOMEIP_ETS_147]="eventgroup_id=0x0002"
        [SOMEIP_ETS_148]="eventgroup_id=0x0002"
        [SOMEIP_ETS_149]="eventgroup_id=0x0002"
        [SOMEIP_ETS_150]="eventgroup_id=0x0006"
        [SOMEIP_ETS_151]="eventgroup_id=0x0002"
        [SOMEIP_ETS_152]="eventgroup_id=0x0002"
    )
    local neg_case_overrides="${NEG_CASE_EXPECT_OVERRIDES[$case_id_canon]:-}"
    if [[ -n "$neg_case_overrides" ]]; then
        for tok in $neg_case_overrides; do
            override+=(--expect "$tok")
        done
    fi

    # Harness watchdog backstop — same global value as run_case. The
    # negative SCXML branches self-terminate on their own deadlines, so
    # the backstop only catches a hang.
    local case_timeout=$HARNESS_BACKSTOP_SEC

    local hp dp
    ip netns exec "$tester_ns" "$harness_link" test \
        --case "$case_id" -i "$veth_t" -t "$case_timeout" \
        "${override[@]}" "${neg_extra_args[@]}" >"$hlog" 2>&1 &
    hp=$!

    sleep 0.5

    ip netns exec "$dut_ns" env \
        COMMONAPI_CONFIG="$CAPI_CFG" \
        VSOMEIP_CONFIGURATION="$neg_dut_vsomeip_cfg" \
        VSOMEIP_APPLICATION_NAME=tc8-dut \
        VSOMEIP_BASE_PATH="$vsp" \
        "${neg_dut_extra_env[@]}" \
        "$mock_dut_link" >"$dlog" 2>&1 &
    dp=$!

    local wait_budget=$(( (case_timeout + 3) * 5 ))
    (( wait_budget > 250 )) && wait_budget=250
    local _
    for _ in $(seq 1 "$wait_budget"); do
        kill -0 "$hp" 2>/dev/null || break
        sleep 0.2
    done

    kill_worker_procs "$harness_link"
    kill_worker_procs "$mock_dut_link"

    if [[ $toggle_arp_accept -eq 1 ]]; then
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.conf.$veth_d.arp_accept=1" >/dev/null
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.conf.all.arp_accept=1"     >/dev/null
    fi

    # Mirror run_case's restoration of ipfrag_time. Symmetric with
    # the install block above.
    if [[ $toggle_ipfrag_time -eq 1 ]]; then
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.ipfrag_time=30" >/dev/null
    fi

    # Mirror run_case's restoration of RETRANSMISSION_TO sysctl
    # toggles. Symmetric with the run_case restore block; see the
    # toggle install above for the no-op rationale on the negative
    # path.
    if [[ $toggle_syn_linear_timeouts -eq 1 ]]; then
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_syn_linear_timeouts=4" >/dev/null
    fi
    if [[ $toggle_data_rto_recovery -eq 1 ]]; then
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_early_retrans=3" >/dev/null
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_recovery=1" >/dev/null
    fi

    # Mirror run_case's restoration of arp_ignore (ARP_39/40).
    # Symmetric with the install block above.
    if [[ $toggle_arp_ignore -eq 1 ]]; then
        ip netns exec "$tester_ns" sysctl -qw "net.ipv4.conf.$veth_t.arp_ignore=0" >/dev/null
    fi

    # Mirror run_case's restoration of neigh GC sysctls (ARP_48/49).
    # delay_first_probe_time restored to setup-netns.sh's Phase-2 value
    # (30), NOT the kernel default (5) — keeps cross-case state symmetric
    # with run_case (Phase 2 ARP_03/05 absence-window protection relies
    # on the 30 s dwell).
    if [[ $toggle_neigh_gc -eq 1 ]]; then
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.base_reachable_time_ms=30000" >/dev/null
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.delay_first_probe_time=30"    >/dev/null
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.neigh.$veth_d.gc_stale_time=60"              >/dev/null
    fi

    {
        echo "=========================================="
        echo "[w$W] negative ${case_id} with --expect ${wrong_token}"
        echo "    expecting verdict '${expected_reason}'"
        echo "=========================================="
        echo "---- harness output ----"
        cat "$hlog"
        echo "--------------------------------"
        if grep -qF "verdict  : ${expected_reason}" "$hlog"; then
            echo "[w$W] PASS negative ${case_id} landed on ${expected_reason}"
        else
            echo "[w$W] FAIL negative ${case_id} did not land on ${expected_reason}"
        fi
    } | emit_block

    local rc=0
    grep -qF "verdict  : ${expected_reason}" "$hlog" || rc=1
    junit_record_case "$W" "${case_id}_neg" negative "$start_ts" "$hlog" "$rc"
    if (( keep_logs == 0 )); then
        rm -f "$hlog" "$dlog"
    fi
    return $rc
}

# Worker main: read $WORK_ROOT/$W/bucket line-by-line, dispatch each to
# run_case or run_negative_case depending on mode, append failures to
# $WORK_ROOT/$W/fails.
worker_main() {
    local W=$1
    local mode=$2
    local bucket="$WORK_ROOT/$W/bucket"
    local fails="$WORK_ROOT/$W/fails"
    : >"$fails"
    [[ -s "$bucket" ]] || return 0
    local line case_id wrong_tok expected_reason
    while IFS= read -r line; do
        if [[ "$mode" == "negative" ]]; then
            IFS='|' read -r case_id wrong_tok expected_reason <<<"$line"
            if ! run_negative_case "$W" "$case_id" "$wrong_tok" "$expected_reason"; then
                echo "${case_id}(neg)" >>"$fails"
            fi
        else
            case_id="$line"
            if ! run_case "$W" "$case_id"; then
                echo "$case_id" >>"$fails"
            fi
        fi
        # Execution ledger — the summary cross-checks processed-row count
        # against the scheduled total. A worker that dies mid-bucket (or
        # has its stdin slurped by a misbehaving child) must surface as a
        # hard error, never as "all cases passed".
        echo "$case_id" >>"$WORK_ROOT/$W/processed"
    done <"$bucket"
}

# Distribute work rows round-robin across WORKERS buckets.
distribute() {
    local W
    for (( W=0; W<WORKERS; W++ )); do
        : >"$WORK_ROOT/$W/bucket"
    done
    local i=0
    local row
    for row in "$@"; do
        echo "$row" >>"$WORK_ROOT/$(( i % WORKERS ))/bucket"
        (( i += 1 ))
    done
}

if [[ "$NEGATIVE" == "1" ]]; then
    # Each row wires one FORMAT_14..18 or ARP_13..15 to a deliberately-
    # wrong expectation and the `fail:*` reason the case's SCXML
    # prescribes for that mismatch. Wrong values are chosen to not
    # collide with any plausible DUT identity (tc8-dut ships
    # service_id=0xF4E7 etc. — see TC8_DUT_EXPECT above).
    NEG_ROWS=(
        "SOMEIPSRV_FORMAT_14|service_id=0x0000|fail:entry_service_id_mismatch"
        "SOMEIPSRV_FORMAT_15|instance_id=0xFFFE|fail:entry_instance_id_mismatch"
        "SOMEIPSRV_FORMAT_16|major_version=9|fail:entry_major_version_mismatch"
        "SOMEIPSRV_FORMAT_17|ttl=99|fail:entry_ttl_mismatch"
        "SOMEIPSRV_FORMAT_18|minor_version=42|fail:entry_minor_version_mismatch"
        # §5.1.5.5 OPTIONS NEG rows — cases 04/07/15 read expected.*
        # endpoint values (dut_iface_ip, udp_port, tcp_port). Cases
        # 01/02/03/05/06 verify spec invariants on captured fields
        # alone (length, type, reserved bytes, L4-Proto presence) so
        # an expectation flip can't fault them.
        "SOMEIPSRV_OPTIONS_04|dut_iface_ip=10.99.99.99|fail:ipv4_endpoint_address_not_dut_iface_ip"
        "SOMEIPSRV_OPTIONS_07|udp_port=12345|fail:ipv4_endpoint_udp_port_mismatch"
        "SOMEIPSRV_OPTIONS_15|tcp_port=12345|fail:no_ipv4_endpoint_option_with_tcp_l4_or_port_mismatch"
        # §5.1.5.5 OPTIONS_11 / §5.1.5.3 SD_MESSAGE_13 NEG rows — both
        # cases assert echoed/configured Multicast Option fields against
        # expected.* baselines. _11's mcast_ipv4 flip lands directly on
        # fail_ipv4; SD_MESSAGE_13's service_id flip lands on fail_ack_
        # field (the cond ANDs across multiple echoed fields). 08/09/
        # 10/12/13/14 verify spec invariants on captured fields alone
        # (length / type / reserveds / l4-proto presence / port literal)
        # so an expectation flip can't fault them — same precedent as
        # OPTIONS_01/02/03/05/06.
        "SOMEIPSRV_OPTIONS_11|mcast_ipv4=10.99.99.99|fail:ipv4_multicast_address_mismatch"
        "SOMEIPSRV_SD_MESSAGE_13|service_id=0x0000|fail:subscribe_ack_field_mismatch"
        # §5.1.5.3 SD_MESSAGE NEG rows — _03/_04 read expected.major_version,
        # _05/_06 read expected.minor_version, _07 reads expected.ttl,
        # _11 reads expected.service_id, _15 reads expected.instance_id
        # / eventgroup_id / major_version. _14/_16/_17/_18/_19 verify
        # spec-defined sentinels (TTL=0 + literal 0xFFFE / 0x0002 / 2)
        # on captured fields alone so an expectation flip can't fault
        # them — same precedent as OPTIONS_01/02/03/05/06.
        "SOMEIPSRV_SD_MESSAGE_03|major_version=99|fail:offer_entry_major_version_mismatch"
        "SOMEIPSRV_SD_MESSAGE_05|minor_version=42|fail:offer_entry_minor_version_mismatch"
        "SOMEIPSRV_SD_MESSAGE_07|ttl=99|fail:offer_entry_ttl_mismatch"
        "SOMEIPSRV_SD_MESSAGE_11|service_id=0x0000|fail:ack_entry_service_id_mismatch"
        "SOMEIPSRV_SD_MESSAGE_15|instance_id=0xFFFE|fail:nack_entry_echo_fields_mismatch"
        # SD_MESSAGE_02 phase 1 cond gates entries[0/1].service_id ==
        # expected.service_id (instance_id is extracted from the 2-entry
        # OfferService and compared against the captured slot in phase
        # 2/3, so an expected.instance_id flip is no longer load-bearing
        # after the spec-literal extraction refactor). Flip service_id
        # so phase 1 conjunct fails → 2-entry Find never matches →
        # listen window expires on fail_phase1_no_two_entry_offer.
        # RPC_14/_17 phase 2/3 read expected.service_id; flipping it
        # forces phase 2 to time out before the real Response can match.
        # SD_MESSAGE_01 + RPC_01/_02/_13 omitted — their conds rely
        # on captured-only invariants (entry-count + 0xF4E8 literal +
        # SSOT in someipsrv_si2::*) so an expect flip can't fault them.
        "SOMEIPSRV_SD_MESSAGE_02|service_id=0x0000|fail:no_two_entry_offer_for_findservice_any_within_listen_window"
        "SOMEIPSRV_RPC_14|service_id=0x0000|fail:no_response_from_instance_1_udp_port_30502"
        "SOMEIPSRV_RPC_17|service_id=0x0000|fail:no_response_from_instance_1_tcp_port_30501"
        # §5.1.6 SOMEIP_ETS NEG rows — _005/_027 cover the SD-side phase 1
        # expectation (service_id flip → phase 1 OfferService cond never
        # matches → timeout). _035 covers the response-side TCP src_port
        # axis the case adds on top of the ETS_027 echo shape.
        "SOMEIP_ETS_005|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_027|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_035|tcp_port=12345|fail:echo_uint8_reliable_response_did_not_match_request_or_wrong_tcp_src_port"
        # Wave 2 §5.1.6 ETS rows — SD-side phase 1 expectation flip
        # rebases the OfferService cond so the malformed-cluster cases
        # never reach their phase 2 verdicts (which themselves cover
        # the malformed-input axis). ETS_037 also flips phase 1 →
        # the post-reset TCP_INFO observation never executes.
        "SOMEIP_ETS_001|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_002|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_003|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_004|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_037|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 3-a §5.1.6 ETS Array length-prefix cluster — same SD-side
        # phase 1 service_id flip pattern as Wave 2 (_001..004/_037).
        # _033 reuses the malformed-length axis (length_override) since
        # CommonAPI-SOMEIP on Linux does not enforce SomeIpArrayMinLength
        # when length-width != 0; the same NEG token rebases its phase 1.
        "SOMEIP_ETS_028|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_029|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_031|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_032|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_033|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 3-b §5.1.6 ETS Array-family + FLOAT64 cluster — same SD-side
        # phase 1 service_id flip pattern as Wave 3-a.
        "SOMEIP_ETS_019|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_022|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_030|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 3-c §5.1.6 ETS ENUM + UTF16DYNAMIC cluster — same SD-side
        # phase 1 service_id flip pattern as Waves 3-a/b.
        "SOMEIP_ETS_009|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_039|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 3-d §5.1.6 ETS UTF16FIXED + UTF8DYNAMIC + UTF8FIXED cluster —
        # same SD-side phase 1 service_id flip pattern as Waves 3-a/b/c.
        "SOMEIP_ETS_046|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_048|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_053|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 3-e §5.1.6 ETS UTF DYNAMIC NEG cluster (length_override +
        # wrong_BOM axes) — same SD-side phase 1 service_id flip pattern.
        # Each phase-2 verdict already covers the malformed-input axis; the
        # phase 1 flip rebases the OfferService cond so the case never
        # reaches the (lenient) phase-2 verdict.
        "SOMEIP_ETS_040|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_042|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_045|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_049|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_051|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_052|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 3-f §5.1.6 ETS UTF multi-phase + odd-byte cluster (positives
        # _044/_047 + NEG _043/_041/_050) — same SD-side phase 1 service_id
        # flip pattern as Waves 3-a..3-e. The flip rebases the OfferService
        # cond so neither the multi-phase chain nor the lenient verdict is
        # reached.
        "SOMEIP_ETS_041|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_043|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_044|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_047|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_050|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 4 §5.1.6 ETS datatype axis trio (echoBitfields + echoUNION +
        # echoUINT8E2E) — same SD-side phase 1 service_id flip pattern.
        # Each phase-2 verdict already covers its datatype axis; the
        # phase 1 flip rebases the OfferService cond so the case never
        # reaches the byte-equality verdict.
        "SOMEIP_ETS_007|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_034|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_038|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-a §5.1.6 ETS UNION NEG cluster (length_override + inner-prefix
        # mutations + wrong-type discriminant). Same SD-side flip pattern; the
        # phase 1 timeout rebases the OfferService cond before any of the
        # phase-2 union-axis verdicts can fire.
        "SOMEIP_ETS_070|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_071|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_072|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_073|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-b §5.1.6 ETS Event/Field cluster — Subscribe→Ack→
        # Notification chain on eventgroups 0x02 (_086) / 0x05 (_087).
        # Phase 1 cond requires sd_ipv4_endpoint_count >= 1; service_id
        # flip never matches the BASIC_03-shape phase 1 transition, so
        # phase 1 deadline lands on the with-endpoint failure reason.
        "SOMEIP_ETS_086|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        "SOMEIP_ETS_087|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        # Wave 5-k §5.1.6 ETS_121 mirrors _087's Subscribe(eg 0x05) wire
        # shape; phase 1 cond requires sd_ipv4_endpoint_count >= 1 so
        # service_id flip lands the with-endpoint failure reason.
        "SOMEIP_ETS_121|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        # Wave 5-k §5.1.6 ETS_122 InterfaceVersion Getter Method Request
        # (method_id 0x25). Phase 1 cond uses the bare-OfferService
        # shape (no endpoint dependency); service_id flip lands the
        # standard no-offer failure reason.
        "SOMEIP_ETS_122|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-k §5.1.6 ETS_123/_124/_125 SubscribeEventgroup with
        # EntriesLen mutations (too long beyond message, too long but
        # within message, too short). All three use the bare-OfferService
        # phase 1 shape; service_id flip lands the standard no-offer
        # failure reason before the malformed Subscribe even reaches DUT.
        "SOMEIP_ETS_123|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_124|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_125|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # ETS_127 lenient verdict: any OfferService for SERVICE-ID-1.
        # service_id flip lands on the standard no-offer reason.
        "SOMEIP_ETS_127|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_128|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_130|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-k batch 2 §5.1.6 ETS_134..144 SubscribeEventgroup wire-shape
        # mutations (Length / OptionsLen / option-body-Length / non-existing
        # IDs / reserved fields). All share the bare-OfferService phase 1
        # shape (lift from _123..125), so service_id flip lands the standard
        # no-offer reason before the malformed Subscribe reaches DUT.
        "SOMEIP_ETS_134|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_135|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_136|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_137|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_138|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_139|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_140|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_141|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_142|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_143|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_144|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-k batch 3 §5.1.6 ETS_153 SubscribeEventgroup SOME/IP Length
        # lies smaller than actual; same bare-OfferService phase 1 shape.
        "SOMEIP_ETS_153|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-k batch 3 §5.1.6 ETS_154 SubscribeEventgroup with invalid
        # IPv4 endpoint (255.255.255.255); same bare-OfferService phase 1 shape.
        "SOMEIP_ETS_154|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-l §5.1.6 ETS_162/_163 SubscribeEventgroup with unallowed
        # Endpoint IPv4 (DUT self / 111.111.111.111); same bare-OfferService
        # phase 1 shape — service_id flip lands the no-offer reason.
        "SOMEIP_ETS_162|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_163|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-m §5.1.6 ETS_109/_110/_111/_112/_113/_119 Subscribe wire-shape
        # mutations (port=0 / IP=32.0.0.0 / Length-cut / IPv4Option Length=0 /
        # OptionsLen=0 / wrong l4proto). Same bare-OfferService phase 1.
        "SOMEIP_ETS_109|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_110|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_111|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_112|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_113|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_119|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-m + 5-l §5.1.6 ETS_115/_116/_174/_178 Subscribe wire-shape
        # mutations (#Opt1 overcount / unknown option type ×2 / wrong Method ID).
        "SOMEIP_ETS_115|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_116|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_174|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_178|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-l §5.1.6 ETS_171 unicast FindService — service_id flip
        # changes the OfferService observation cond so it never matches.
        "SOMEIP_ETS_171|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-l §5.1.6 ETS_176/_177 trailing-payload Subscribes —
        # service_id flip lands phase 1 OfferService gate.
        "SOMEIP_ETS_176|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_177|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-l + 5-m §5.1.6 ETS_117/_118/_173/_175 multi-option / FindService-with-option /
        # unicast Subscribe ×2 / unreferenced Configuration Option.
        "SOMEIP_ETS_117|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_118|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_173|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_175|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-m §5.1.6 ETS_107/_108/_114/_120 multi-entry SD / Stop+absence /
        # shortened EntriesLen / alternate-IPs Subscribe.
        "SOMEIP_ETS_107|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_108|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_114|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_120|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-l §5.1.6 ETS_166 TestFieldUINT8 get/set/get — service_id flip
        # lands phase 1 OfferService gate before any RPC.
        "SOMEIP_ETS_166|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-m §5.1.6 ETS_106 ClientServiceSubscribe — service_id flip
        # lands phase 1 OfferService gate before any client-mode chain.
        "SOMEIP_ETS_106|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-l §5.1.6 ETS_164 SuspendInterface — service_id flip lands
        # phase 1 OfferService gate before any field/suspend RPC.
        "SOMEIP_ETS_164|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-l §5.1.6 ETS_167/_168 TestFieldUINT8Array / Reliable.
        "SOMEIP_ETS_167|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_168|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-m §5.1.6 ETS_103/_104/_105 GetLastValueOfEvent* — service_id
        # flip lands phase 1 OfferService gate before any client-mode chain.
        "SOMEIP_ETS_103|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_104|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_105|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-k batch 3 §5.1.6 ETS_155 Subscribe-Stop-Subscribe chain;
        # service_id flip lands phase 1 OfferService gate before any Subscribe.
        "SOMEIP_ETS_155|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-k batch 3 §5.1.6 ETS_152 SD session_id wrap; service_id flip
        # lands phase 1 OfferService gate at 6 s deadline before the burst
        # has any chance to elicit Acks. Background-thread stimulus keeps
        # emitting on the failure path but no Acks come back.
        "SOMEIP_ETS_152|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-k batch 3 §5.1.6 ETS_146 ResetInterface field-axis chain;
        # service_id flip lands phase 1 OfferService gate before any RPC.
        "SOMEIP_ETS_146|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-k batch 3 §5.1.6 ETS_147 Subscribe eg 0x02 + cyclic event
        # observation; phase 1 uses with-endpoint OfferService cond per _086.
        "SOMEIP_ETS_147|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        # Wave 5-k batch 3 §5.1.6 ETS_148/_149/_150/_151 mirror _147 wire
        # shape (Subscribe + cyclic event observation). _150 swaps to eg 0x06.
        "SOMEIP_ETS_148|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        "SOMEIP_ETS_149|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        "SOMEIP_ETS_150|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        "SOMEIP_ETS_151|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        # Wave 5-c §5.1.6 ETS length-axis NEG cluster — SOME/IP Length
        # mutations (0x00 / 0x04 / 0x10000) on echoUINT8 method 0x08;
        # same SD-side phase 1 service_id flip pattern as Wave 5-a.
        # The flip rebases the OfferService cond before the lenient
        # phase 2 length verdict can fire.
        "SOMEIP_ETS_054|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_055|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_058|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-d §5.1.6 ETS UTF FIXED NEG cluster — too_long /
        # too_short payloads on echoUTF16FIXED (Method 0x14) +
        # echoUTF8FIXED (Method 0x13). Same SD-side flip pattern; the
        # phase 1 timeout rebases the OfferService cond before any of
        # the phase-2 verdicts (lenient-positive for _063/_065,
        # 4-path for _064/_066) can fire.
        "SOMEIP_ETS_063|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_064|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_065|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_066|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-f §5.1.6 ETS Array cluster — _067 zero-length array
        # (positive lenient: empty echoed payload), _068/_069 unaligned
        # 3-message bundles over TCP/UDP. All three flip phase 1
        # service_id so the OfferService cond never matches → phase 1
        # timeout, before any of the phase-2 echo verdicts fire.
        "SOMEIP_ETS_067|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_068|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_069|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-e §5.1.6 ETS Subscribe extensions — _088 multi-entry
        # bundled Subscribe (eg 0x02/0x05/0x06), _092 ttl=0 silence,
        # _095 ttl-expiry absence. _088/_095 phase 1 cond requires
        # sd_ipv4_endpoint_count >= 1 (BASIC_03 shape) so service_id
        # flip lands the with-endpoint failure reason; _092 uses the
        # same shape so all three flip cleanly to phase 1 timeout.
        "SOMEIP_ETS_088|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        "SOMEIP_ETS_092|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        "SOMEIP_ETS_095|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        # Wave 5-g §5.1.6 ETS wrong-header cluster — single SOME/IP
        # header field corruption on echoUINT8 (Method 0x08). Same
        # SD-side flip pattern as Waves 2..5-d; phase 1 deadline
        # rebases the OfferService cond before the lenient phase 2
        # verdict can fire.
        "SOMEIP_ETS_074|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_075|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_076|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_077|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_078|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-h §5.1.6 ETS — _059 resetInterface wrong-iface-version
        # Fire&Forget silence (absence verdict), _060 multicast
        # FindService → unicast OfferService UDP+TCP endpoints, _061
        # 2-message UDP bundle (echoUINT8 + echoENUM). _059/_061 flip
        # phase 1 service_id → standard no_offer reason; _060's phase 1
        # cond also requires both UDP and TCP IPv4 Endpoint Options so
        # the service_id flip lands the per-case with-endpoints reason.
        "SOMEIP_ETS_059|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_060|service_id=0x0000|fail:no_offer_service_with_udp_and_tcp_endpoints_within_listen_window"
        "SOMEIP_ETS_061|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-i §5.1.6 ETS Client-Mode subset — _098 absence-of-Subscribe,
        # _099 FindService observed for SERVICE-ID-2, _100 FindService bounded
        # to Start-Up Phase, _101 StopOfferService stops further FindService.
        # All four are gated through Phase 1 OfferService observation on
        # SERVICE-ID-1, so a service_id flip lands the standard no-offer reason.
        "SOMEIP_ETS_098|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_099|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_100|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "SOMEIP_ETS_101|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # Wave 5-j §5.1.6 ETS — _096 SubscribeEventgroup carrying TCP
        # IPv4 Endpoint option without a pre-established TCP connection;
        # phase 1 cond requires sd_ipv4_endpoint_count >= 1 (BASIC_03
        # shape) so service_id flip lands the with-endpoint failure
        # reason. _091 cyclic OfferService session_id increment shares
        # the same with-endpoint phase 1 gate.
        "SOMEIP_ETS_096|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        "SOMEIP_ETS_091|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        # §5.1.6 SOMEIP_ETS_097 NEG: phase 1 SERVICE-ID-1 OfferService gate
        # uses the standard no-endpoint shape; service_id flip lands the
        # bare-OfferService failure reason. The TCP refuse-then-accept path
        # never reaches phase 2 so the wire-side stimulus cost is unchanged.
        "SOMEIP_ETS_097|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # §5.1.6 SOMEIP_ETS_094 NEG: phase 1 OfferService cond uses the
        # with-endpoint shape (mirrors ETS_086/087 base — same
        # SubscribeEventgroup chain), so service_id flip lands the
        # with-endpoint failure reason before the reboot-detection
        # chain has any effect.
        "SOMEIP_ETS_094|service_id=0x0000|fail:no_offer_service_with_ipv4_endpoint_within_listen_window"
        # §5.1.6 SOMEIP_ETS_084 NEG: phase 1 SERVICE-ID-1 OfferService gate
        # uses the standard no-endpoint shape (same as _097); service_id
        # flip lands the bare-OfferService failure reason before the
        # client-mode subscribe/unsubscribe chain matters.
        "SOMEIP_ETS_084|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # §5.1.6 SOMEIP_ETS_081 NEG: phase 1 SERVICE-ID-1 OfferService gate
        # uses the standard no-endpoint shape (same as _084/_097); service_id
        # flip lands the bare-OfferService failure reason before the
        # server-reboot TCP renewal chain matters.
        "SOMEIP_ETS_081|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # §5.1.6 SOMEIP_ETS_082 NEG: same phase 1 SERVICE-ID-1 OfferService
        # gate (no-endpoint shape) lands before the UDP re-subscribe chain.
        "SOMEIP_ETS_082|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # §5.1.6 SOMEIP_ETS_093 NEG: phase 1 SERVICE-ID-1 OfferService gate
        # uses the standard no-endpoint shape; service_id flip lands the
        # bare-OfferService failure reason before the per-channel reboot
        # tracker Subscribe chain matters.
        "SOMEIP_ETS_093|service_id=0x0000|fail:no_offer_service_within_listen_window"
        # §5.1.6 SOMEIP_ETS_089 NEG: phase 1 SERVICE-ID-1 OfferService gate
        # uses the standard no-endpoint shape; service_id flip lands the
        # bare-OfferService failure reason before the suspendInterface
        # stimulus matters.
        "SOMEIP_ETS_089|service_id=0x0000|fail:no_offer_service_within_listen_window"
        "ARP_13|arp.dut_iface_mac=de:ad:be:ef:00:00|fail:sender_hw_addr_not_dut_iface"
        "ARP_14|arp.dut_iface_ip=10.99.99.99|fail:sender_proto_ip_not_dut_iface"
        "ARP_15|arp.tester_ip=10.99.99.99|fail:target_proto_ip_not_tester"
        # §4.2.4.1 Phase 2 (ARP_03..06) negatives:
        #   ARP_03/05: override arp.tester_ip so the learning stimulus
        #     injects a *wrong* sender_proto_ip; DUT's cache stays cold
        #     for the real tester IP; the UT-provoked unicast egress
        #     (envelope pinned to the ipv4.tester_ip topology identity,
        #     untouched by this override) then triggers a real ARP
        #     Request → case lands on fail_unexpected_arp_request.
        #   ARP_04/06: override arp.tester_mac so the SCXML expected.tester_mac
        #     mismatches the MAC actually injected (hardcoded in arp_builder.h);
        #     observed UDP's Eth-dst == injected synthetic MAC != expected →
        #     lands on fail_wrong_eth_dst.
        "ARP_03|arp.tester_ip=10.99.99.99|fail:dut_arp_request_after_cache_populated"
        "ARP_04|arp.tester_mac=de:ad:be:ef:00:00|fail:udp_eth_dst_not_tester_mac"
        "ARP_05|arp.tester_ip=10.99.99.99|fail:dut_arp_request_after_gratuitous_learning"
        "ARP_06|arp.tester_mac=de:ad:be:ef:00:00|fail:udp_eth_dst_not_tester_mac"
        # §4.2.4.2 Phase 3a field-check cases ARP_43/44: opened via the
        # Phase 3b CLI split (`dut.ip` / `dut.mac` feed
        # the stimulus, `arp.dut_iface_ip` / `arp.dut_iface_mac` feed the
        # SCXML expectation). Overriding only the iface key shifts the
        # SCXML comparison target without silencing the DUT; the SCXML
        # fail guards were also relaxed (dropped the `sender_hw ==
        # expected.dut_iface_mac` conjunction) so the override reaches the
        # intended fail branch instead of fail_no_reply.
        "ARP_43|arp.dut_iface_mac=de:ad:be:ef:00:00|fail:eth_src_not_dut_iface_mac"
        "ARP_44|arp.dut_iface_ip=10.99.99.99|fail:reply_sender_ip_not_dut_iface"
        # §4.2.4.2 Phase 3b Group C cache-merge cases (ARP_32..35):
        # override `arp.tester_mac2` so the SCXML expectation no longer
        # matches the DUT's observed UDP egress eth_dst (= real MAC2,
        # still hardcoded to `kTesterInjectedMac2` in arp_builder.h).
        # The observed eth_dst equals neither `expected.tester_mac` (MAC1
        # = 02:00:00:00:00:A1) nor the overridden `expected.tester_mac2`,
        # so the SCXML falls through to `fail:udp_eth_dst_neither_mac1_nor_mac2`.
        # This validates the pass-guard dependency on tester_mac2 without
        # needing a DUT that actually does the wrong thing.
        "ARP_32|arp.tester_mac2=de:ad:be:ef:00:00|fail:udp_eth_dst_neither_mac1_nor_mac2"
        "ARP_33|arp.tester_mac2=de:ad:be:ef:00:00|fail:udp_eth_dst_is_mac1_not_mac2"
        "ARP_34|arp.tester_mac2=de:ad:be:ef:00:00|fail:udp_eth_dst_is_mac1_not_mac2"
        "ARP_35|arp.tester_mac2=de:ad:be:ef:00:00|fail:udp_eth_dst_neither_mac1_nor_mac2"
        # §4.2.4.2 Phase 3c Group D stateful-learning cases (ARP_39/40):
        # override the MAC the SCXML compares the DUT's UDP egress
        # eth_dst against. Without arp_ignore=8 (run_negative_case omits
        # the per-case toggle to keep the runtime path symmetric with
        # other negatives), the DUT learns the tester KERNEL'S MAC from
        # the auto-Reply race; that lladdr ≠ the wrong overridden
        # value, so SCXML lands on `fail:udp_eth_dst_not_injected_macN`
        # — the intended fail branch (the test asserts the dependency
        # on the per-case MAC expectation, not on the cache stickiness
        # mechanism that the positive path exercises).
        "ARP_39|arp.tester_mac2=de:ad:be:ef:00:00|fail:udp_eth_dst_not_injected_mac2"
        "ARP_40|arp.tester_mac3=de:ad:be:ef:00:00|fail:udp_eth_dst_not_injected_mac3"
        # ARP_45 (two-Request target_hw check): override `arp.tester_mac`
        # so the SCXML expectation for the FIRST Reply's target_hw no
        # longer matches the DUT's actual reply (target_hw=real MAC1
        # from the injected Request). Lands on the first-response fail
        # branch.
        "ARP_45|arp.tester_mac=de:ad:be:ef:00:00|fail:first_response_target_hw_not_mac1"
        # §4.2.4.2 Phase 3c Group E timeout cases (ARP_48/49): override
        # the MAC the SCXML expects on the FIRST DUT UDP egress. The
        # cache-expiry path itself doesn't matter for the negative —
        # UDP1 fires while the cache still has MAC1 (whether REACHABLE
        # or DELAY), and the SCXML's wait_udp1 fail branch fires before
        # the rest of the stimulus completes.
        "ARP_48|arp.tester_mac=de:ad:be:ef:00:00|fail:first_udp_eth_dst_not_learned_mac"
        "ARP_49|arp.tester_mac=de:ad:be:ef:00:00|fail:first_udp_eth_dst_not_learned_mac"
        # ARP_46/47 still closed: guards check hardcoded RFC constants
        # (hw_type=1, hw_addr_len=6) with no `expected.*` override knob.
        # Reaching those fail branches requires a non-conformant DUT.
        # §4.4 IPv4 positive-field cases (HEADER_01, HEADER_03,
        # VERSION_03, TTL_01): override `ipv4.dut_iface_ip` to a value
        # the DUT never emits. Every pass-guard conjuncts
        # `captured.src_addr == expected.dut_iface_ip` so the pass path
        # goes out of reach and the case lands on fail_timeout. Proves
        # the src_addr filter is load-bearing — without it, SOME/IP SD
        # multicast and tester-originated frames would both false-pass.
        "IPv4_HEADER_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_within_listen_window"
        "IPv4_HEADER_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_with_expected_source_address"
        "IPv4_VERSION_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_within_listen_window"
        "IPv4_TTL_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_within_listen_window"
        # IPv4_VERSION_01 / TTL_05 share ipv4_positive_reply's fail
        # reason (same as HEADER_03's timeout string). Also override
        # dut_iface_ip to force the pass path out of reach.
        "IPv4_VERSION_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_with_expected_source_address"
        "IPv4_TTL_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_with_expected_source_address"
        # IPv4_CHECKSUM_05: overriding dut_iface_ip takes the pass+fail
        # branches (both gated on src_addr match) out of reach; lands on
        # fail_timeout, proving the SCXML's src_addr conjunct is
        # load-bearing.
        "IPv4_CHECKSUM_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_within_listen_window"
        # §4.3.3.2 ICMPv4_TYPE_22: override icmpv4.dut_iface_ip so the
        # SCXML's `captured.src_ip == expected.dut_iface_ip` conjunct
        # goes out of reach; the DUT still emits the Echo Reply but
        # the src_ip comparison rejects it, landing the case on
        # fail_timeout. Proves the src_ip guard is load-bearing (same
        # pattern as the IPv4 positive-reply rows above).
        "ICMPv4_TYPE_22|icmpv4.dut_iface_ip=10.99.99.99|fail:no_echo_reply_within_listen_window"
        # §4.3.3.2 ICMPv4_TYPE_18: override icmpv4.dut_iface_ip — the
        # SCXML's pass guard (type=3 AND code=2 AND src_ip match) and
        # the fail_wrong_code guard (type=3 AND code!=2 AND src_ip
        # match) both conjunct on src_ip, so both go out of reach.
        # The DUT still emits Destination Unreachable but the case
        # lands on fail_timeout.
        "ICMPv4_TYPE_18|icmpv4.dut_iface_ip=10.99.99.99|fail:no_dest_unreachable_within_listen_window"
        # §4.3.3.1 ICMPv4_ERROR_02: override icmpv4.dut_iface_ip —
        # both pass (pointer==22 + src_ip match) and fail_wrong_pointer
        # (pointer!=22 + src_ip match) guards conjunct on src_ip, so
        # both go out of reach. The DUT still emits Parameter Problem
        # but the case lands on fail_timeout. Proves the src_ip guard
        # is load-bearing. ERROR_03 / TYPE_04 are absence-shape and
        # have no load-bearing guard that a simple override moves
        # out of reach without masquerading as pass-on-timeout, so
        # they carry no negative row (shared limitation with
        # TYPE_05/10/16 and ERROR_04/05).
        "ICMPv4_ERROR_02|icmpv4.dut_iface_ip=10.99.99.99|fail:no_parameter_problem_within_listen_window"
        # §4.3.3.2 ICMPv4_TYPE_11: override icmpv4.dut_iface_ip — pass
        # and all three fail_* guards (zero_receive / zero_transmit /
        # wrong_originate) conjunct on src_ip, so flipping the
        # expectation drives every branch out of reach. The DUT still
        # emits Timestamp Reply with the correct originate / non-zero
        # receive+transmit, but the SCXML's src_ip filter rejects it
        # → fail_timeout. Proves the src_ip filter is load-bearing.
        # No row for the timestamp-field fail branches: Linux's
        # icmp_timestamp() unconditionally echoes Originate verbatim
        # and fills Receive / Transmit via `inet_current_timestamp()`
        # (always non-zero unless the system clock is exactly midnight
        # UT to the millisecond — practically unreachable), so
        # reaching fail_zero_receive / fail_zero_transmit /
        # fail_wrong_originate requires a non-conformant DUT (same
        # class as ARP_46/47's RFC-constant guards).
        "ICMPv4_TYPE_11|icmpv4.dut_iface_ip=10.99.99.99|fail:no_timestamp_reply_within_listen_window"
        # §4.3.3.2 ICMPv4_TYPE_12: override icmpv4.echo_id — pass
        # conjuncts on `captured.echo_id == expected.echo_id`, so
        # flipping the expected value out of band drives the SCXML
        # into fail_id_mismatch (the explicit mismatch branch fires
        # before fail_seq_mismatch since the id check has higher
        # specificity). Proves the identifier-echo invariant the
        # spec asserts is load-bearing in the SCXML — not just
        # "any Timestamp Reply".
        "ICMPv4_TYPE_12|icmpv4.echo_id=0xFFFE|fail:timestamp_reply_identifier_not_echoed"
        # No row for `parameter_problem_pointer_not_option_or_pointer_byte`:
        # that fail reason fires only when the DUT's Pointer value is
        # neither 20 nor 22 — no CLI override flips Linux's pointer
        # emission off {20}, so reaching that branch requires a non-
        # conformant DUT (same class as ARP_46/47's hardcoded-constant
        # guards).
        # §4.4.4.6 IPv4_FRAGMENTS_01: flipping icmpv4.echo_id moves
        # the pass conjunct (echo_id match) out of reach so the SCXML
        # lands on fail_echo_id (the explicit mismatch branch fires
        # before fail_data_mismatch since it has higher specificity).
        # Proves the echo_id match is load-bearing in the reassembly
        # path — not just "any DUT reply".
        "IPv4_FRAGMENTS_01|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch"
        # §4.4.4.6 IPv4_FRAGMENTS_02/03/04: flipping icmpv4.echo_id
        # moves phase 2's pass conjunct out of reach — the DUT's
        # reassembled Echo Reply has the real kIcmpEchoId in its
        # header, but the SCXML compares against the wrong expected.
        # Lands on fail_echo_id with the case-specific reason string
        # (compound template's 3-way phase-2 fail split mirrors
        # FRAGMENTS_01's diagnostic granularity). Proves the phase 2
        # echo_id conjunct is load-bearing across all three
        # compound consumers.
        "IPv4_FRAGMENTS_02|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_after_id_retry"
        "IPv4_FRAGMENTS_03|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_after_src_retry"
        "IPv4_FRAGMENTS_04|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_after_protocol_retry"
        # §4.4.4.6 IPv4_FRAGMENTS_05: override ipv4.dut_iface_ip so the
        # SCXML pass-guard conjunct `captured.src_ip ==
        # expected.dut_iface_ip` goes out of reach. The DUT still emits
        # the UDP via TriggerSendUdp (ut.status==Ok) but the observed
        # src_ip never matches the 10.99.99.99 expectation → listen
        # window expires → fail_timeout. Proves the src_ip match is
        # load-bearing (not just "any UDP on the wire"). ADDRESSING_01/
        # 02 carry no negative row: their SCXML guards read only
        # captured.ut_* fields which have no --expect backing, so no
        # CLI override flips a pass guard without also breaking the
        # stimulus.
        "IPv4_FRAGMENTS_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        # §4.4.4.7 IPv4_REASSEMBLY_04: flipping icmpv4.echo_id moves the
        # pass conjunct (echo_id match on the unordered-reassembly Echo
        # Reply) out of reach. The DUT still reassembles by offset key
        # and emits Echo Reply with the real kIcmpEchoId, but the SCXML
        # compares against the wrong expected → lands on fail_echo_id
        # with the unordered-reassembly reason string. Proves the
        # echo_id match is load-bearing on the out-of-order path —
        # complements FRAGMENTS_01's same-axis check on the in-order
        # 2-fragment path. _06/_07/_09 (pure absence) carry no negative
        # row — their SCXML guards have no flippable conjunct, see the
        # ICMPv4_TYPE_10/16 precedent.
        "IPv4_REASSEMBLY_04|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_after_unordered_reassembly"
        # §4.4.4.7 IPv4_REASSEMBLY_12: same axis as REASSEMBLY_04 —
        # flipping icmpv4.echo_id sends the pass conjunct out of reach
        # so the SCXML lands on fail_echo_id with the low-TTL reason
        # string. Proves the echo_id match is load-bearing on the
        # Low-TTL reassembly path.
        "IPv4_REASSEMBLY_12|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_after_low_ttl_reassembly"
        # §4.4.4.7 IPv4_REASSEMBLY_11 carries no negative row — the
        # case's positive path already lands on fail_timeout on Linux
        # (ipfrag_time=2 dut_ns toggle + 3 s inter-fragment wait =
        # bucket expired before frag 1, no Echo Reply). An echo_id
        # flip would land on the same fail_timeout, providing zero
        # diagnostic variance. Same precedent as _13 (overlap drop)
        # and _06/_07/_09 (pure absence): no flippable conjunct that
        # can be observed when no reply lands.
        # §4.4.4.7 IPv4_REASSEMBLY_10: flipping icmpv4.echo_id sends
        # phase_a's pass conjunct out of reach. The DUT reassembles
        # Phase A (inside ipfrag_time=2 s) and emits Echo Reply with
        # the real id=0x1234, but the SCXML compares against 0xFFFE →
        # lands on fail_phase_a_echo_id. Phase B's hypothetical reply
        # is unreachable since phase_a's terminal final state already
        # ended the case. Proves the phase_a echo_id match is load-
        # bearing on the within-timer reassembly path.
        "IPv4_REASSEMBLY_10|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_phase_a_within_timer"
        # §4.8.6.1 TCP_BASICS_01..05: every pass/fail branch conjuncts
        # on `captured.src_ip == expected.dut_iface_ip` so flipping the
        # expectation to an unreachable 10.99.99.99 sends every guard
        # out of reach. The DUT still emits the spec-mandated segment
        # (SYN,ACK for 01/02, ACK for 03, RST for 04/05) but the SCXML
        # never matches → the FIRST listen window (phase 1 in compound
        # cases) times out first, landing the case on its phase-1
        # fail_timeout reason. Proves the src_ip conjunct is load-
        # bearing across all five new TCP pilot cases.
        #
        # BASICS_04 has 3 phases (SYN/FIN/Data) and BASICS_05 has 2
        # phases (SYN+ACK/ACK); the negative row drives both into
        # phase-1 timeout (`_after_syn` / `_after_synack`) because
        # phase 1's pass guard is the first one made unreachable —
        # phases 2/3 are never entered, so their timeout reasons are
        # not reachable from this CLI flip. Phase-2/3 reachability is
        # exercised by ctest unit tests + positive smoke runs.
        "TCP_BASICS_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_ack_within_listen_window"
        "TCP_BASICS_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_ack_within_listen_window"
        "TCP_BASICS_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ack_to_tester_fin_within_listen_window"
        "TCP_BASICS_04|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_rst_after_syn"
        "TCP_BASICS_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_rst_after_synack"
        "TCP_BASICS_06|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_within_listen_window"
        "TCP_BASICS_07|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ack_within_listen_window"
        "TCP_BASICS_08|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_fin_from_established"
        "TCP_BASICS_10|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_close_fin_phase1"
        "TCP_BASICS_09|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_fin_into_last_ack"
        # §4.8.6.2 TCP_CHECKSUM_01..03: every pass/fail conjunct gates
        # on `captured.src_ip == expected.dut_iface_ip`, so flipping
        # the expectation to 10.99.99.99 sends every guard out of
        # reach. CHECKSUM_01/02 land on phase-1 timeout
        # (no_dut_handshake_ack); CHECKSUM_03 lands on the single
        # listen window's timeout. CHECKSUM_02's absence-pass gets
        # FLIPPED into a fail by the unreachable phase-1 guard —
        # without the handshake-consume step the absence-listen never
        # opens, which is the right diagnostic ("we never even saw the
        # handshake" beats "we passed by absence due to a fixture
        # bug").
        "TCP_CHECKSUM_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_within_listen_window"
        "TCP_CHECKSUM_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_within_listen_window"
        "TCP_CHECKSUM_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_data_segment_within_listen_window"
        # TCP_CHECKSUM_04 — IP flip makes the snippet's BPF
        # `src host <dut_iface_ip>` unreachable on every observed
        # SYN; both cycle-1 and cycle-2 snippets time out and the
        # verdict ladder's first cond (`not cycle1_isn_captured`)
        # short-circuits to `cycle1_syn_capture_timeout`.
        "TCP_CHECKSUM_04|ipv4.dut_iface_ip=10.99.99.99|fail:cycle1_syn_capture_timeout"
        # §4.8.6.3 UNACCEPTABLE: every pass-guard gates on
        # `captured.src_ip == expected.dut_iface_ip`, so the IP flip
        # makes the first listening state unreachable on each case.
        # Each row's expected fail reason matches the first state's
        # fail terminal (deadline_first / fail_timeout_phase1 /
        # fail_no_handshake_ack / fail_p1_no_handshake_ack).
        "TCP_UNACCEPTABLE_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_synack_to_first_tester_syn"
        "TCP_UNACCEPTABLE_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_synack_to_first_tester_syn"
        "TCP_UNACCEPTABLE_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_rst_to_listen_synack"
        "TCP_UNACCEPTABLE_07|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_rst_to_listen_synack"
        "TCP_UNACCEPTABLE_06|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_within_listen_window"
        "TCP_UNACCEPTABLE_04|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_within_listen_window"
        "TCP_UNACCEPTABLE_14|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        "TCP_UNACCEPTABLE_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_rst_to_unacceptable_ack_in_syn_recv"
        "TCP_UNACCEPTABLE_08|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_rst_phase1_synack_with_unacceptable_ack"
        "TCP_UNACCEPTABLE_09|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        "TCP_UNACCEPTABLE_10|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_within_listen_window"
        "TCP_UNACCEPTABLE_12|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        # §4.8.6.6 TCP_FLAGS_INVALID_01/02: every pass / wrong-seq
        # transition gates on `captured.src_ip == expected.dut_iface_ip`
        # so the IP flip makes both the SYN+ACK observation (01) and
        # the DUT-RST observation (02) unreachable. SCXML lands on the
        # first state's 5 s deadline — fail_timeout_first_synack on 01,
        # fail_timeout (no_dut_rst_to_syn_ack_in_listen) on 02. Proves
        # the src_ip conjunct is load-bearing across both LISTEN-state
        # probes.
        "TCP_FLAGS_INVALID_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_synack_to_first_tester_syn"
        "TCP_FLAGS_INVALID_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_rst_to_syn_ack_in_listen"
        # §4.8 TIME-WAIT cluster (BASICS_11/12/13/14, UNACCEPTABLE_13,
        # FLAGS_INVALID_14): every state's pass guard gates on
        # `captured.src_ip == expected.dut_iface_ip`, so the IP flip
        # uniformly drives the case to its first state's 5 s deadline.
        # BASICS_11/12 land on no_dut_handshake_ack (their listening
        # _replay_rst is unreachable without first walking the prelude
        # observation chain), so the negative path's wall-time is just
        # ~5 s — far below the positive path's 90 s envelope.
        "TCP_BASICS_11|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_BASICS_12|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_BASICS_13|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_BASICS_14|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_UNACCEPTABLE_11|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        "TCP_UNACCEPTABLE_13|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        "TCP_FLAGS_INVALID_14|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        "TCP_FLAGS_INVALID_12|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        "TCP_FLAGS_INVALID_07|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ack_to_otw_seq_syn_in_syn_recv"
        "TCP_FLAGS_INVALID_08|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        "TCP_FLAGS_INVALID_11|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        "TCP_FLAGS_INVALID_10|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        "TCP_FLAGS_INVALID_09|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        "TCP_FLAGS_INVALID_13|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1"
        "TCP_FLAGS_INVALID_15|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_synack_phase1_syn_rcvd"
        "TCP_FLAGS_INVALID_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_to_active_open"
        "TCP_FLAGS_INVALID_04|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_to_active_open"
        "TCP_FLAGS_INVALID_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_phase1_syn_ack_rst"
        "TCP_FLAGS_INVALID_06|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_phase1_bare_ack"
        "TCP_HEADER_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_data_segment_within_listen_window"
        "TCP_HEADER_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_HEADER_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_HEADER_06|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_HEADER_07|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_HEADER_08|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_HEADER_09|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_HEADER_04|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_HEADER_11|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_MSS_OPTIONS_11|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_with_mss_option"
        "TCP_MSS_OPTIONS_12|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_with_non_default_mss"
        "TCP_MSS_OPTIONS_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_ack_within_listen_window"
        "TCP_MSS_OPTIONS_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_ack_within_listen_window"
        "TCP_MSS_OPTIONS_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_ack_within_listen_window"
        "TCP_MSS_OPTIONS_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ack_to_synack_with_ilen0_mss"
        "TCP_MSS_OPTIONS_10|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_data_segment_within_listen_window"
        "TCP_MSS_OPTIONS_06|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_data_segment_phase1_mv200"
        "TCP_MSS_OPTIONS_09|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_data_segment_phase1_mv200"
        "TCP_BASICS_17|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_synack_to_simultaneous_syn"
        "TCP_FLAGS_PROCESSING_11|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_FLAGS_PROCESSING_06|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_FLAGS_PROCESSING_08|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_rst_to_fin_in_closed"
        "TCP_FLAGS_PROCESSING_07|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1_cw"
        "TCP_FLAGS_PROCESSING_09|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1_cw"
        "TCP_FLAGS_PROCESSING_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_synack_to_prelude_syn_phase1"
        "TCP_FLAGS_PROCESSING_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_synack_phase1_syn_rcvd"
        "TCP_CLOSING_06|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_CLOSING_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_CLOSING_09|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_CLOSING_07|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_CLOSING_08|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_CALL_ABORT_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_CALL_RECEIVE_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_CALL_RECEIVE_04|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1_est"
        "TCP_CALL_ABORT_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_phase1_closing"
        "TCP_ACKNOWLEDGEMENT_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ack_to_data"
        "TCP_ACKNOWLEDGEMENT_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_ACKNOWLEDGEMENT_04|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_NAGLE_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_first_data_segment"
        "TCP_NAGLE_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_first_data_segment"
        "TCP_CONTROL_FLAGS_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_CONTROL_FLAGS_08|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_ack_to_first_syn"
        "TCP_URGENT_PTR_04|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_OUT_OF_ORDER_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_FLAGS_PROCESSING_10|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_first_data_segment"
        "TCP_OUT_OF_ORDER_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_OUT_OF_ORDER_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_OUT_OF_ORDER_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_PROBING_WINDOWS_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack"
        "TCP_PROBING_WINDOWS_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_first_data_segment"
        "TCP_PROBING_WINDOWS_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_first_data_segment"
        "TCP_PROBING_WINDOWS_04|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_first_data_segment"
        "TCP_PROBING_WINDOWS_06|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_first_data_segment"
        "TCP_RETRANSMISSION_TO_06|ipv4.dut_iface_ip=10.99.99.99|fail:dut_handshake_did_not_complete"
        "TCP_RETRANSMISSION_TO_05|ipv4.dut_iface_ip=10.99.99.99|fail:dut_handshake_did_not_complete"
        "TCP_RETRANSMISSION_TO_04|ipv4.dut_iface_ip=10.99.99.99|fail:dut_handshake_did_not_complete"
        "TCP_RETRANSMISSION_TO_03|ipv4.dut_iface_ip=10.99.99.99|fail:dut_handshake_did_not_complete"
        "TCP_SEQUENCE_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_ack_within_listen_window"
        "TCP_SEQUENCE_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_ack_within_listen_window"
        "TCP_SEQUENCE_04|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_syn_ack_within_listen_window"
        "TCP_SEQUENCE_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ack_to_synack_within_listen_window"
        "TCP_SEQUENCE_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ack_for_seg1"
        "TCP_CONNECTION_ESTAB_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_synack_for_leg1"
        "TCP_CONNECTION_ESTAB_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_handshake_ack_for_leg1"
        "TCP_CONNECTION_ESTAB_07|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ack_to_tester_fin"
        "TCP_CONNECTION_ESTAB_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_synack_for_leg1"
        # §4.6 UDP udp_field_check egress consumers: every pass/fail
        # transition conjuncts `captured.src_ip == expected.dut_iface_ip`
        # AND `captured.dst_ip == expected.tester_ip`; flipping
        # ipv4.dut_iface_ip sends both transitions out of reach so the
        # SCXML lands on fail_timeout. Proves the src_ip conjunct is
        # load-bearing on every §4.6 egress field-check consumer.
        # ipv4_udp_ut_presence / udp_ut_received_check consumers gate on
        # captured.has_ut_response (port-based, not IP-keyed) — no CLI
        # override flips a pass guard without breaking the stimulus, so
        # those carry no NEG_ROW (same precedent as ADDRESSING_01/02).
        "UDP_FIELDS_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        "UDP_FIELDS_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        # §4.6.5.4 UDP_FIELDS_04 Topology 2 phase 1: SCXML phase 1 cond
        # filters on captured.src_ip == expected.dut_iface_ip; the flip
        # sends the egress UDP out of reach so SCXML stays in
        # listening_phase1 → fail_phase1_no_host1_egress at deadline.
        "UDP_FIELDS_04|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_to_host1_within_listen_window"
        # §4.6.5.4 UDP_FIELDS_05 Topology 2 phase 1: SCXML phase 1 cond
        # filters on captured.ut_recv_src_ip == expected.tester_ip; the
        # flip lands the UT-Confirmation outside the cond so SCXML
        # stays in listening_phase1 → fail_phase1_no_host1_receipt.
        # Distinct override key (tester_ip vs dut_iface_ip) because
        # FIELDS_05's pass guard reads from the tester axis.
        "UDP_FIELDS_05|ipv4.tester_ip=10.99.99.99|fail:no_ut_confirmation_for_host1_receipt"
        "UDP_FIELDS_06|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        "UDP_FIELDS_07|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        "UDP_FIELDS_13|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        "UDP_FIELDS_14|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        # §4.6.5.4 UDP_FIELDS_12 max-length: harness's 45-fragment burst
        # targets cfg.ipv4.dut_iface_ip; flipping it routes the wire
        # frames past the DUT's IP layer rp_filter (martian dst) so no
        # reassembled receipt reaches the data listener → ut_received=0
        # → SCXML hits fail_timeout via udp_ut_received_check.
        "UDP_FIELDS_12|ipv4.dut_iface_ip=10.99.99.99|fail:no_ut_confirmation_for_max_length_udp"
        # §4.6.5.5 UDP_USER_INTERFACE_01 dynamic ports: harness
        # OpCreateUdpReceivePorts request goes to cfg.ipv4.dut_iface_ip;
        # the flip lands the request on a non-routable dst so tc8-dut
        # never replies → SCXML hits fail_timeout.
        "UDP_USER_INTERFACE_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_ut_confirmation_for_create_udp_receive_ports"
        "UDP_USER_INTERFACE_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        "UDP_USER_INTERFACE_06|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        "UDP_USER_INTERFACE_07|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        "UDP_USER_INTERFACE_08|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        # §4.6.5.5 UI_07 strict-axis NEG: stimulus pins src_ip override
        # to the conformant DIface-0 alias (kDutAliasIp4Be=172.16.0.5)
        # via a constant in udp_pilot_common.h, so flipping
        # `ipv4.dut_alias_ip` diverts ONLY the SCXML expectation. DUT
        # still emits with src=alias, harness expected diverges, cond
        # lands on `fail_wrong_src_ip_or_port` — proves the strict-axis
        # cond literal is load-bearing rather than vacuous on the
        # passing path.
        "UDP_USER_INTERFACE_07|ipv4.dut_alias_ip=10.99.99.99|fail:dut_emitted_udp_with_wrong_user_interface_src_ip"
        # §4.6.5.5 UI_08 strict-axis NEG: same pattern as UI_07 but on
        # the destination axis. Stimulus pins target_ip to the AIface-0
        # alias (kTesterAliasIp4Be=172.16.0.4); flipping
        # `ipv4.tester_alias_ip` makes SCXML expect a different dst,
        # forcing the cond to land on `fail_wrong_dst_ip`.
        "UDP_USER_INTERFACE_08|ipv4.tester_alias_ip=10.99.99.99|fail:dut_emitted_udp_with_wrong_user_interface_dst_ip"
        "UDP_Padding_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        # §4.6.5.6 UDP_INTRODUCTION_03: SCXML observes ICMP via the
        # icmp_observed event with `captured.src_ip == expected.dut_iface_ip`
        # filter; flipping ipv4.dut_iface_ip sends the filter out of reach
        # → fail_timeout (no_dut_icmp_port_unreachable_within_listen_window).
        "UDP_INTRODUCTION_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_icmp_port_unreachable_within_listen_window"
        # §4.4.4.1 IPv4_HEADER_05: per-case SCXML conjuncts on
        # `expected.dut_iface_ip` for src_ip filtering; flipping
        # icmpv4.dut_iface_ip sends every transition out of reach →
        # fail_timeout. Proves the src_ip filter is load-bearing.
        "IPv4_HEADER_05|icmpv4.dut_iface_ip=10.99.99.99|fail:no_echo_reply_for_576_byte_datagram"
    )
    # Filter NEG_ROWS to only those whose case_id appears in the
    # positional CASES array (when the user passed any). Keeps the
    # `--negative TCP_HEADER_07` ergonomic for rapid per-case
    # iteration; bare `--negative` (no positional args) still runs
    # the full curated negative set. Default $CASES = SOMEIPSRV_FORMAT_01
    # under the no-arg branch — filter against that single id leaves
    # NEG_ROWS empty for the no-positional case (correct: that case
    # has no negative row).
    if [[ $# -gt 0 ]]; then
        declare -a FILTERED_NEG=()
        for row in "${NEG_ROWS[@]}"; do
            row_id="${row%%|*}"
            for want in "${CASES[@]}"; do
                if [[ "$row_id" == "$want" ]]; then
                    FILTERED_NEG+=("$row")
                    break
                fi
            done
        done
        NEG_ROWS=("${FILTERED_NEG[@]}")
    fi
    distribute "${NEG_ROWS[@]}"
    total=${#NEG_ROWS[@]}
    _tc8_join_pids=()
    for (( W=0; W<WORKERS; W++ )); do
        worker_main "$W" negative &
        _tc8_join_pids+=($!)
    done
    wait "${_tc8_join_pids[@]}"
else
    distribute "${CASES[@]}"
    total=${#CASES[@]}
    _tc8_join_pids=()
    for (( W=0; W<WORKERS; W++ )); do
        worker_main "$W" positive &
        _tc8_join_pids+=($!)
    done
    wait "${_tc8_join_pids[@]}"
fi

fails=()
skips=()
processed=0
for (( W=0; W<WORKERS; W++ )); do
    if [[ -s "$WORK_ROOT/$W/fails" ]]; then
        while IFS= read -r line; do
            fails+=("$line")
        done <"$WORK_ROOT/$W/fails"
    fi
    if [[ -s "$WORK_ROOT/$W/skips" ]]; then
        while IFS= read -r line; do
            skips+=("$line")
        done <"$WORK_ROOT/$W/skips"
    fi
    if [[ -s "$WORK_ROOT/$W/processed" ]]; then
        processed=$(( processed + $(wc -l <"$WORK_ROOT/$W/processed") ))
    fi
done

# Execution-ledger cross-check: every scheduled row must have been
# processed (pass, fail, or skip). A shortfall means a worker died
# mid-bucket — fail the run loudly instead of reporting a clean summary
# over partially-executed work.
if (( processed != total )); then
    echo "smoke-test: FATAL — scheduled ${total} case(s) but only ${processed} were processed; a worker terminated early (crash or stdin-slurping child). Treat every result above as suspect." >&2
    exit 1
fi

junit_emit_xml
if [[ -n "$JUNIT_OUT" ]]; then
    echo "smoke-test: junit report → $JUNIT_OUT"
fi

echo "=========================================="
echo "smoke-test summary [topology=$TOPOLOGY]: ${total} case(s), ${#fails[@]} failure(s), ${#skips[@]} skipped across ${WORKERS} worker(s)"
if [[ ${#skips[@]} -gt 0 ]]; then
    # Skips are not failures, but they must never scroll out of sight:
    # repeat each skipped case + reason in the summary block.
    for _s in "${skips[@]}"; do
        echo "  SKIP ${_s%%|*} — ${_s#*|}"
    done
fi
if [[ ${#fails[@]} -gt 0 ]]; then
    printf '  FAIL %s\n' "${fails[@]}" >&2
    exit 1
fi
echo "smoke-test: all cases passed"
