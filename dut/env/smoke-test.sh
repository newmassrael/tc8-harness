#!/usr/bin/env bash
# End-to-end smoke test:
#   netns setup → tc8-dut in dut ns → harness in tester ns
#   → SOME/IP-SD OfferService (svc=0xffff mth=0x8100 type=NOTIFICATION) captured.
#
# Usage:
#   sudo smoke-test.sh [--workers N] [--dut-first] [--log-dir DIR] \
#                      [--junit-xml PATH] [CASE_ID ...]
#   sudo smoke-test.sh [--workers N] --negative [--junit-xml PATH]
#
# Runs each listed case against a fresh tc8-dut and reports a summary;
# exits non-zero if any case fails. Defaults to SOMEIPSRV_FORMAT_01.
#
# --workers N (default 1) runs N parallel (tc8-dut, harness) pairs, each
# pinned to its own netns pair (tc8-tester-$W / tc8-dut-$W), veth pair
# (veth-tester-$W / veth-dut-$W), and vsomeip tmp directory
# (/tmp/tc8-vsomeip-$W/). Cases are distributed round-robin across
# workers. Each case still provisions a fresh tc8-dut (no cross-case
# state), so round-robin is safe.
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

# Per-worker scratch root. Holds a sentinel subdir per live worker so the
# cleanup trap can tear down exactly the workers that were set up, even
# if a setup-netns.sh invocation fails mid-bring-up. Also holds per-case
# log tempfiles when --log-dir is not provided, and the stdout lock.
WORK_ROOT=/tmp/tc8-workers
STDOUT_LOCK=$WORK_ROOT/stdout.lock

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
TC8_DUT_EXPECT=(
    --expect service_id=0xF4E7
    --expect instance_id=0x0001
    --expect major_version=1
    --expect ttl=3
    --expect minor_version=0
    --expect eventgroup_id=0x0001
    --expect dut_iface_ip=172.16.0.2
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
# Topology endpoint IPs — single source of truth for smoke-test.sh.
# Passed explicitly as TESTER_IP / DUT_IP env to setup-netns.sh in
# `bring_up_worker` (see below), so setup-netns.sh's own defaults are
# overridden and the two files can never drift.
TESTER_IP4=172.16.0.1
DUT_IP4=172.16.0.2
# §4.7 DHCPv4 server emul identity — matches `kDefaultServerIdBe` in
# `src/sce_integration/dhcpv4_default_endpoints.h`. CM_05/_06 pre-pin
# `<this_ip, ARP_TESTER_INJECTED_MAC>` permanent on the DUT side so
# the synthetic gateway resolves without a real responder; if the C++
# constexpr changes, this literal must follow.
DHCPV4_SERVER1_IP4=172.16.0.10
# `arp.dut_real_ip` feeds the stimulus (target_ip of the injected ARP
# Request); `arp.dut_iface_ip` is the SCXML expectation the captured
# DUT Reply's sender_proto_ip is compared against. In positive rows both
# carry the real DUT IP; `--negative` overrides only `arp.dut_iface_ip`
# (ARP_44) to prove the SCXML mismatch path without silencing the DUT.
ARP_DUT_EXPECT_STATIC=(
    --expect "arp.tester_ip=$TESTER_IP4"
    --expect "arp.dut_iface_ip=$DUT_IP4"
    --expect "arp.dut_real_ip=$DUT_IP4"
    --expect "arp.tester_mac=$ARP_TESTER_INJECTED_MAC"
    --expect "arp.tester_mac2=$ARP_TESTER_INJECTED_MAC2"
    --expect "arp.tester_mac3=$ARP_TESTER_INJECTED_MAC3"
)

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
)

DUT_FIRST=0
NEGATIVE=0
LOG_DIR=""
JUNIT_OUT=""
WORKERS=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --workers)   WORKERS="$2"; shift 2 ;;
        --dut-first) DUT_FIRST=1; shift ;;
        --negative)  NEGATIVE=1;  shift ;;
        --log-dir)   LOG_DIR="$2"; shift 2 ;;
        --junit-xml) JUNIT_OUT="$2"; shift 2 ;;
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
    if [[ "$_case" == "DHCPV4_CLIENT_USAGE_01" ]]; then
        NEED_SECOND_VETH=1
        break
    fi
done
# Topology 2 second-pair endpoints — single source of truth for
# smoke-test.sh. Mirror of setup-netns.sh's defaults (172.17.0.0/24).
TESTER_IP4_2=172.17.0.1
DUT_IP4_2=172.17.0.2

[[ $EUID -eq 0 ]] || { echo "smoke-test: must run as root (try: sudo $0)" >&2; exit 1; }
[[ -x "$HARNESS"  ]] || { echo "smoke-test: harness missing: $HARNESS"  >&2; exit 1; }
[[ -x "$TC8_DUT_BIN" ]] || { echo "smoke-test: tc8-dut missing: $TC8_DUT_BIN" >&2; exit 1; }
[[ -f "$VSOMEIP_CFG" ]] || { echo "smoke-test: vsomeip.json missing: $VSOMEIP_CFG" >&2; exit 1; }

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

# Emit Surefire-shape <testsuites><testsuite><testcase>… XML to
# $JUNIT_OUT from per-worker $WORK_ROOT/$W/junit_records files. Runs
# single-threaded after all workers have completed. Cases are grouped
# into <testsuite> blocks by their category prefix (case_id stripped
# of trailing _NN and _neg suffixes), e.g. ARP_07 → suite "ARP",
# IPV4_HEADER_05 → suite "IPV4_HEADER".
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
            sub(/_LINUX_KNOWN_FAIL$/, "", s)
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
            tot_tests++
            if (status == "fail") tot_fails++
        }
        END {
            printf "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" > outfile
            printf "<testsuites name=\"tc8-harness smoke\" tests=\"%d\" failures=\"%d\" time=\"%s\" timestamp=\"%s\">\n",
                tot_tests, tot_fails+0, total_wall, run_ts > outfile
            for (i = 1; i <= ns; i++) {
                sk = suites[i]
                printf "  <testsuite name=\"%s\" tests=\"%d\" failures=\"%d\" time=\"%.3f\">\n",
                    xml_escape(sk), tests_per[sk], fails_per[sk]+0, time_per[sk]+0 > outfile
                for (j = 1; j <= idx[sk]; j++) {
                    printf "    <testcase classname=\"%s\" name=\"%s\" time=\"%s\"",
                        xml_escape(sk), xml_escape(cname[sk, j]), cdur[sk, j] > outfile
                    if (cstatus[sk, j] == "fail") {
                        msg = cvline[sk, j]
                        if (msg == "") msg = "no verdict line"
                        printf "><failure type=\"%s\" message=\"%s\"/></testcase>\n",
                            xml_escape(cmode[sk, j]), xml_escape(msg) > outfile
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
# like /tmp/tc8-vsomeip-$W/tc8-dut — bring_up_worker creates that
# symlink, run_case invokes through it, so argv[0] (and thus
# /proc/PID/cmdline) contains the worker-scoped string.
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

# Bring up a single worker's netns pair and record its sentinel +
# DUT-side MAC. Sentinel file $WORK_ROOT/$W/up is touched BEFORE
# setup-netns.sh starts and left in place until tear_down_worker
# succeeds, so a crash mid-setup is still reachable by the cleanup trap.
bring_up_worker() {
    local W=$1
    mkdir -p "$WORK_ROOT/$W" "/tmp/tc8-vsomeip-$W"
    : >"$WORK_ROOT/$W/up"
    : >"$WORK_ROOT/$W/junit_records"
    env TESTER_NS="tc8-tester-$W" DUT_NS="tc8-dut-$W" \
        VETH_T="veth-tester-$W" VETH_D="veth-dut-$W" \
        TESTER_IP="${TESTER_IP4}/24" DUT_IP="${DUT_IP4}/24" \
        SECOND_VETH="$NEED_SECOND_VETH" \
        VETH_T2="veth-tester2-$W" VETH_D2="veth-dut2-$W" \
        TESTER_IP2="${TESTER_IP4_2}/24" DUT_IP2="${DUT_IP4_2}/24" \
        "$HERE/setup-netns.sh" >/dev/null

    # Per-worker symlinks so each worker's tc8-dut/tc8-harness has a
    # worker-unique argv[0] in /proc/PID/cmdline. kill_worker_procs
    # pkills by that unique string, scoping the kill to this worker
    # only. Without these symlinks, concurrent workers share the real
    # binary path and pkill would fan out across workers.
    ln -sf "$TC8_DUT_BIN" "/tmp/tc8-vsomeip-$W/tc8-dut"
    ln -sf "$HARNESS" "/tmp/tc8-vsomeip-$W/tc8-harness"

    # veth MAC is kernel-assigned per `ip link add` invocation. Capture
    # AFTER setup-netns.sh completes; feed it to ARP_13 expectations for
    # every case this worker runs.
    local mac
    mac=$(ip -n "tc8-dut-$W" link show "veth-dut-$W" \
        | awk '/link\/ether/ { print $2 }')
    [[ -n "$mac" ]] \
        || { echo "smoke-test: failed to read veth-dut-$W MAC" >&2; exit 1; }
    echo "$mac" >"$WORK_ROOT/$W/dut_mac"

    # Symmetric capture for the tester-side veth — needed by §4.5
    # IPv4_AUTOCONF_ADDRESS_SELECTION cases that pin
    # <tester_ip, tester_mac> NUD_PERMANENT on the DUT side to
    # suppress the kernel's UT-Confirmation-driven ARP resolve
    # (see tester_neigh_pin block in run_case).
    local tester_mac
    tester_mac=$(ip -n "tc8-tester-$W" link show "veth-tester-$W" \
        | awk '/link\/ether/ { print $2 }')
    [[ -n "$tester_mac" ]] \
        || { echo "smoke-test: failed to read veth-tester-$W MAC" >&2; exit 1; }
    echo "$tester_mac" >"$WORK_ROOT/$W/tester_mac"

    # Pin the DUT neighbor entry on the tester side as NUD_PERMANENT. The
    # setup-netns.sh reachability ping populates it in NUD_STALE/REACHABLE,
    # but under a long full-suite run (>gc_stale_time) the entry can age
    # out or go through a transitional state that triggers tester-kernel
    # ARP resolution. When the tester kernel broadcasts its own Request,
    # the DUT receives it and learns <tester_ip, real_tester_MAC> via
    # RFC 826 §2.3 reception — which is exactly what Group C ARP_22/28/38
    # pass-criterion ("DUT emits its own ARP Request on cold cache") does
    # NOT want. Pinning the entry as PERMANENT guarantees tester never
    # ARPs for DUT, DUT's cache stays cold until its own egress need, and
    # the pass-guard fires deterministically.
    #
    # Phase 2 (ARP_03..06) is unaffected: those cases verify the DUT-side
    # cache entry learned from a raw tester-injected frame, which sits
    # independently of the tester-side neigh table pinned here.
    ip -n "tc8-tester-$W" neigh replace "$DUT_IP4" \
        lladdr "$mac" nud permanent dev "veth-tester-$W"

    # §4.6.5.4 UDP_FIELDS_04/_05 Topology 2 second-host pin: pin
    # `<172.16.0.3, tester_mac>` on the DUT side as NUD_PERMANENT so the
    # DUT's egress ARP for Host-2-IP resolves to the tester's MAC
    # without a real responder. 172.16.0.3 is intentionally NOT
    # configured as a tester-side alias — Linux's IP layer with
    # ip_forward=0 silently drops the unmatched inbound, while pcap on
    # AF_PACKET ETH_P_ALL still observes the wire frame for the SCXML
    # `udp_observed` event. The pin is unconditional (sticky for the
    # whole worker lifetime); other cases that don't address 172.16.0.3
    # are unaffected. Mirrors `kUdpHost2IpBe` in
    # `src/sce_integration/udp_pilot_common.h` — single source of truth
    # for the literal.
    ip -n "tc8-dut-$W" neigh replace "172.16.0.3" \
        lladdr "$tester_mac" nud permanent dev "veth-dut-$W"
}

tear_down_worker() {
    local W=$1
    # Reap any tc8-dut/harness still running under this worker's
    # symlink path (belt-and-suspenders — run_case/run_negative_case
    # already call kill_worker_procs per case).
    kill_worker_procs "/tmp/tc8-vsomeip-$W/tc8-dut"
    kill_worker_procs "/tmp/tc8-vsomeip-$W/tc8-harness"
    env TESTER_NS="tc8-tester-$W" DUT_NS="tc8-dut-$W" \
        "$HERE/cleanup.sh" >/dev/null 2>&1 || true
    rm -rf "/tmp/tc8-vsomeip-$W" "$WORK_ROOT/$W"
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
            tear_down_worker "$W"
        done
        rm -rf "$WORK_ROOT"
    fi
}
trap cleanup EXIT

# Leftovers from a prior hung run (vsomeip half-init blocks shutdown).
# Broad pkill covers all workers' tc8-dut/harness; harmless when no
# other smoke-test invocation is concurrent.
pkill -9 -f "$TC8_DUT_BIN" 2>/dev/null || true
pkill -9 -f "$HARNESS" 2>/dev/null || true
rm -rf "$WORK_ROOT" /tmp/vsomeip-* /tmp/vsomeip.lck /tmp/tc8-vsomeip-*
mkdir -p "$WORK_ROOT"
: >"$STDOUT_LOCK"

# Parallel bring-up: setup-netns.sh is idempotent and operates on
# distinct names per worker, so concurrent netlink ops don't collide.
# Wall time for N=4: ~0.3 s vs ~1.2 s serial.
for (( W=0; W<WORKERS; W++ )); do
    bring_up_worker "$W" &
done
wait

# Run one case against a specific worker's netns/veth/vsomeip base.
# Writes logs to per-case files under $LOG_DIR (if set) or worker-scoped
# mktemps. Emits a single multi-line block to stdout under flock so
# concurrent workers don't interleave.
#
# Args: worker_id case_id
run_case() {
    local W=$1
    local case_id=$2
    local start_ts=$EPOCHREALTIME
    local tester_ns="tc8-tester-$W"
    local dut_ns="tc8-dut-$W"
    local veth_t="veth-tester-$W"
    local veth_d="veth-dut-$W"
    local vsp="/tmp/tc8-vsomeip-$W/"
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

    # Scope the vsomeip tmp wipe to the sockets + lock file only — NEVER
    # remove the per-worker binary symlinks that kill_worker_procs uses
    # to pattern-match. A concurrent worker's state at
    # /tmp/tc8-vsomeip-OTHER/ is never touched.
    rm -f "/tmp/tc8-vsomeip-$W"/vsomeip-* "/tmp/tc8-vsomeip-$W"/vsomeip.lck 2>/dev/null || true
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
    # there. If the tester's cache were flushed, the subsequent Subscribe
    # stimulus would trigger tester-kernel ARP resolution via a normal
    # ARP Request (sender_hw = kernel MAC, not injected MAC). DUT learns
    # kernel MAC and overwrites the injected entry per RFC 826 §2.3, and
    # ARP_04/06's UDP-egress eth_dst check fails. The NUD_PROBE flakiness
    # on the tester side is addressed via `ucast_solicit=0` in
    # setup-netns.sh instead (keeps cache intact, just disables re-probing).
    ip -n "$dut_ns" neigh flush dev "$veth_d"

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
        toggle_arp_accept=1
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.conf.$veth_d.arp_accept=0" >/dev/null
        ip netns exec "$dut_ns" sysctl -qw "net.ipv4.conf.all.arp_accept=0"     >/dev/null
    fi

    # ARP_39/40 exercise the spec's "DUT learns from a tester-injected
    # ARP frame" path. The tester first lets the DUT broadcast its own
    # ARP Request (cache miss after Subscribe), then injects an ARP
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
    local toggle_arp_ignore=0
    if [[ "$case_id" == "ARP_39" || "$case_id" == "ARP_40" ]]; then
        toggle_arp_ignore=1
        ip netns exec "$tester_ns" sysctl -qw "net.ipv4.conf.$veth_t.arp_ignore=8" >/dev/null
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
        IPV4_AUTOCONF_ADDRESS_SELECTION_*|IPV4_AUTOCONF_CONFLICT_*|IPV4_AUTOCONF_ANNOUNCING_*|IPV4_AUTOCONF_LINKLOCAL_PACKETS_*|IPV4_AUTOCONF_NETWORK_PARTITIONS_*)
            toggle_dut_tester_neigh_pin=1
            local tester_mac_pin
            tester_mac_pin=$(cat "$WORK_ROOT/$W/tester_mac")
            ip -n "$dut_ns" neigh replace "$TESTER_IP4" \
                lladdr "$tester_mac_pin" \
                dev "$veth_d" nud permanent
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
        DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_05|DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_06)
            ip -n "$dut_ns" neigh replace "$DHCPV4_SERVER1_IP4" \
                lladdr "$ARP_TESTER_INJECTED_MAC" \
                dev "$veth_d" nud permanent
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
    if [[ "$case_id" == "ARP_48" || "$case_id" == "ARP_49" ]]; then
        toggle_neigh_gc=1
        # base_reachable_time_ms = 500 puts the kernel's randomised
        # REACHABLE expiry in [250, 749] ms — always before the first
        # stimulus Subscribe reaches the DUT (~1.75 s after harness
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
        # AFTER the second Subscribe at ~2.25 s — order UDP1 → UDP2 →
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
    fi

    # §4.3.3.2 ICMPV4_TYPE_04 compresses Linux's IP fragment reassembly
    # timer from the kernel default (30 s) down to 3 s per netns so the
    # tester-side post-send wait stays in the single-digit seconds
    # range. `net.ipv4.ipfrag_time` is the upper bound on how long the
    # DUT's reassembly context holds a partial datagram before dropping
    # it; lowering it lets the test assert "after the DUT's reassembly
    # timer expired, no Time Exceeded was emitted" without burning 30 s
    # of real time per case.
    #
    # §4.4.4.6 IPV4_FRAGMENTS_02/03/04 explicitly DO NOT get this
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
        ICMPV4_TYPE_04)
            toggle_ipfrag_time=1
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.ipfrag_time=3" >/dev/null
            ;;
        # §4.4.4.7 IPV4_REASSEMBLY_10/_11/_12 — collapse Linux's
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
        IPV4_REASSEMBLY_10|IPV4_REASSEMBLY_11|IPV4_REASSEMBLY_12)
            toggle_ipfrag_time=1
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.ipfrag_time=2" >/dev/null
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
            toggle_syn_linear_timeouts=1
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_syn_linear_timeouts=0" >/dev/null
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
            toggle_data_rto_recovery=1
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_early_retrans=0" >/dev/null
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.tcp_recovery=0" >/dev/null
            ;;
    esac

    # Per-case harness watchdog override — default 7 s is tight for cases
    # whose stimulus wall-time approaches it. Group E uses several seconds
    # of sleeps between subscribes to let the cache age. Default falls
    # back to 7.
    local -A CASE_TIMEOUT_SEC=(
        [ARP_48]=9
        [ARP_49]=11
        # §4.3.3.2 ICMPV4_TYPE_04 — stimulus blocks for 4 s so the
        # per-netns `ipfrag_time=3` reassembly timer elapses before
        # the SCXML listen window opens; SCXML adds 3 s absence
        # observation + 3 s margin.
        [ICMPV4_TYPE_04]=10
        # §4.4.4.6 IPV4_FRAGMENTS_02/03/04 — compound stimulus:
        # phase1 frag-pair (2 × ~0.3 s send) + ~4 s inter-phase wait
        # for DUT reassembly timeout + phase2 frag-pair + 3 s listen
        # window + margin.
        [IPV4_FRAGMENTS_02]=15
        [IPV4_FRAGMENTS_03]=15
        [IPV4_FRAGMENTS_04]=15
        # §4.4.4.7 IPV4_REASSEMBLY_11 — stimulus emits frag 0 (200 ms
        # init), waits 3 s (exceeds the per-netns ipfrag_time=2
        # toggle), emits frag 1; on Linux the bucket has expired by
        # frag 1's arrival, so no Echo Reply and the SCXML 6 s listen
        # window times out. Linux known-fail; runnable on demand
        # against a strict-RFC 791 DUT that reassembles via MAX(TLB,
        # arriving TTL).
        [IPV4_REASSEMBLY_11]=12
        # §4.4.4.7 IPV4_REASSEMBLY_12 — stimulus emits frag 0 (200 ms
        # init), waits 1 s (under the per-netns ipfrag_time=2
        # toggle), emits frag 1; bucket alive at frag 1 → Echo Reply
        # within ~1.5 s + SCXML 5 s listen window + margin.
        [IPV4_REASSEMBLY_12]=10
        # §4.4.4.7 IPV4_REASSEMBLY_10 — synchronous 2-phase stimulus:
        # phase A frag-pair (1 s inter-frag wait, reassembles inside
        # ipfrag_time=2) + 200 ms gap + phase B frag-pair (3 s
        # inter-frag wait, exceeds ipfrag_time → no reply). Total
        # stimulus ~4.6 s + post-start phase_b 3 s deadline + margin.
        [IPV4_REASSEMBLY_10]=12
        # §4.8.6.1 TCP_BASICS_04 — three iterations (SYN/FIN/Data),
        # each with a 5 s SCXML phase deadline (15 s upper bound) +
        # ~600 ms stimulus wall-time + handshake/teardown margin. In
        # the conformant-DUT case all three RSTs land within
        # milliseconds of their stimulus and the case finishes near
        # the stimulus tail, well below this budget; the budget is
        # for the worst-case where every phase deadline runs out.
        [TCP_BASICS_04]=18
        # §4.8.6.1 TCP_BASICS_05 — two iterations (SYN+ACK / ACK),
        # 5 s SCXML phase deadline × 2 = 10 s upper bound + ~400 ms
        # stimulus wall-time + margin.
        [TCP_BASICS_05]=12
        # §4.8.6.1 TCP_BASICS_08 — two phases (ESTABLISHED-close,
        # CLOSE-WAIT-close). Each phase runs a full active-open
        # handshake + close sequence; budget = 5 s × 2 SCXML phase
        # deadlines + handshake/teardown wall-time + UT boot wait.
        [TCP_BASICS_08]=15
        # §4.8.6.1 TCP_BASICS_10 — two phases (FINWAIT-1, FINWAIT-2),
        # each with a FIN-then-ACK 2-state sub-chain (4 SCXML phase
        # deadlines × 5 s). Stimulus wall-time and handshake/teardown
        # margin track BASICS_08 plus the extra sub-state budget.
        [TCP_BASICS_10]=25
        # §4.8.6.1 TCP_BASICS_09 — single LAST-ACK → CLOSED case with
        # a 2-state SCXML chain (FIN observation + closed-port RST).
        # Handshake + close + raw-inject stimulus + 5 s × 2 phase
        # deadlines.
        [TCP_BASICS_09]=15
        # §4.8.6.2 TCP_CHECKSUM_01 — 2-phase SCXML (handshake-ACK
        # consume + DATA-ACK observation), 5 s × 2 = 10 s SCXML
        # upper bound + ~2 s active-OPEN handshake/send/close
        # stimulus. Default 7 s would race-cut the negative path's
        # phase-1 timeout.
        [TCP_CHECKSUM_01]=12
        # §4.8.6.2 TCP_CHECKSUM_02 — 2-phase SCXML (handshake-ACK
        # consume + 5 s absence window), same envelope as
        # CHECKSUM_01 plus a ~200 ms post-inject grace; total still
        # within 12 s.
        [TCP_CHECKSUM_02]=12
        # §4.8.6.2 TCP_CHECKSUM_03 — single-phase SCXML (5 s
        # deadline) + ~2 s active-OPEN handshake / OpSendTcpData
        # stimulus. The default 7 s would race-cut the negative
        # path's deadline.
        [TCP_CHECKSUM_03]=10
        # §4.8.6.2 TCP_CHECKSUM_04 — clock-driven ISN selection.
        # Two consecutive active-OPEN cycles (each ~kTcpUtBootWait
        # + kSnippetCaptureTimeout + 3 × kCycleSettle ≈ 1.5 s + 1.5 s
        # + 750 ms = ~3.75 s of stimulus wall-time) plus an 8 s
        # SCXML deadline. 14 s budget covers both with margin under
        # parallel-worker scheduler jitter.
        [TCP_CHECKSUM_04]=14
        # §4.8.6.3 TCP_UNACCEPTABLE_01 — passive-listen + 3-step
        # raw-inject sequence (SYN / RST / SYN). 2-state SCXML chain
        # (5 s × 2 = 10 s upper bound) + ~2.5 s stimulus wall-time.
        [TCP_UNACCEPTABLE_01]=14
        # §4.8.6.3 TCP_UNACCEPTABLE_02 — passive-listen + SYN + OTW
        # RST + 3 s absence window. 5 s phase-1 + 3 s absence + ~2 s
        # stimulus wall-time = ~10 s upper bound.
        [TCP_UNACCEPTABLE_02]=12
        # §4.8.6.3 TCP_UNACCEPTABLE_05 — two passive-listen phases
        # with distinct DUT ports (SYN+ACK / bare ACK to LISTEN).
        # 5 s × 2 phase deadlines + ~3 s stimulus + handshake margin.
        [TCP_UNACCEPTABLE_05]=14
        # §4.8.6.3 TCP_UNACCEPTABLE_07 — single passive-listen +
        # SYN+ACK inject. 5 s deadline + ~2 s stimulus.
        [TCP_UNACCEPTABLE_07]=10
        # §4.8.6.3 TCP_UNACCEPTABLE_06 — active-OPEN + OTW SYN
        # inject. 2-state SCXML (handshake-ACK + OTW-SYN ACK) + ~2 s
        # active-OPEN stimulus.
        [TCP_UNACCEPTABLE_06]=14
        # §4.8.6.3 TCP_UNACCEPTABLE_04 — single active-OPEN phase
        # (CASE 1 OTW SEQ only; CASE 2 bad-ACK is Linux-deviated in
        # ESTABLISHED — see SCXML preamble). 2-state ACK chain
        # (5 s × 2) + ~2 s active-OPEN stimulus.
        [TCP_UNACCEPTABLE_04]=14
        # §4.8.6.3 TCP_UNACCEPTABLE_14 — two active-OPEN phases with
        # tester FIN driving DUT to CLOSE-WAIT. Each phase has a
        # 3-state ACK chain (handshake / close / data). 5 s × 6
        # phase deadlines + ~5 s stimulus.
        [TCP_UNACCEPTABLE_14]=36
        # §4.8.6.3 TCP_UNACCEPTABLE_03 — passive-listen + SYN +
        # libpcap-snippet ISN_d learning + bad-ACK inject. Single-
        # state SCXML (5 s) + ~3 s stimulus wall-time (UT boot + 0.5 s
        # snippet capture + raw inject + close).
        [TCP_UNACCEPTABLE_03]=10
        # §4.8.6.3 TCP_UNACCEPTABLE_08 — two active-OPEN phases with
        # iptables RST suppression + per-phase libpcap-snippet ISN_d
        # learning + bad-ACK inject. 2-state SCXML (5 s × 2) +
        # ~4 s stimulus.
        [TCP_UNACCEPTABLE_08]=15
        # §4.8.6.3 TCP_UNACCEPTABLE_09 — two active-OPEN phases with
        # iptables ACK suppression + UT close driving DUT into
        # FIN-WAIT-1 + bad-segment inject. 3-state SCXML × 2 phases
        # (5 s × 6 deadlines) + ~4 s stimulus wall-time.
        [TCP_UNACCEPTABLE_09]=36
        # §4.8.6.3 TCP_UNACCEPTABLE_10 — single active-OPEN + UT
        # close + natural FIN-WAIT-2 collapse + OTW-SEQ inject (CASE 1
        # only; CASE 2 silent-drops on Linux per SCXML preamble).
        # 3-state SCXML (5 s × 3 deadlines) + ~3 s stimulus wall-time.
        [TCP_UNACCEPTABLE_10]=20
        # §4.8.6.3 TCP_UNACCEPTABLE_12 — two active-OPEN phases with
        # function-scoped TesterAutoAckDrop pinning DUT in LAST-ACK
        # across each phase + tester shutdown(WR) + UT close +
        # CASE-distinct probe (CASE 1 OTW SEQ + CASE 2 unacc ACK).
        # 8 SCXML deadlines × 5 s upper bound + ~6 s cumulative
        # active-OPEN + close + post-FIN settle stimulus.
        [TCP_UNACCEPTABLE_12]=50
        # §4.8.6.6 TCP_FLAGS_INVALID_01 — passive-listen + SYN probe
        # (phase 1) + SYN+RST inject (phase 2 absence) + LISTEN-
        # survival SYN re-probe (phase 3, detached thread). 5 s
        # phase-1 + 3 s phase-2 absence + 5 s phase-3 + ~3 s stimulus
        # wall-time (kTcpUtBootWait + 2 sync emits + detached thread
        # gap before SCXML enters phase 3).
        [TCP_FLAGS_INVALID_01]=18
        # §4.8.6.6 TCP_FLAGS_INVALID_02 — passive-listen + SYN+ACK
        # inject (phase 1, DUT-RST observation) + LISTEN-survival
        # SYN re-probe (phase 2, sync). 5 s phase-1 + 5 s phase-2 +
        # ~2 s stimulus wall-time.
        [TCP_FLAGS_INVALID_02]=14
        # §4.8.6.6 TCP_FLAGS_INVALID_03/04 — single SYN-SENT phase
        # (active-OPEN + ISN_d snippet + spec-asserted ACK+RST or
        # bare-RST inject + 3 s absence). 5 s SYN observation + 3 s
        # absence + ~2 s stimulus wall-time.
        [TCP_FLAGS_INVALID_03]=12
        [TCP_FLAGS_INVALID_04]=12
        # §4.8.6.6 TCP_FLAGS_INVALID_05/06 — two SYN-SENT phases on
        # distinct port quads (kBasicsActiveLocalPort + 22..25). Phase
        # 1 sync + phase 2 deferred via scheduleAfterStateEntry. Per
        # phase: 5 s SYN obs + 3 s absence; total 16 s + ~3 s
        # cumulative active-OPEN + snippet + raw-inject stimulus.
        [TCP_FLAGS_INVALID_05]=22
        [TCP_FLAGS_INVALID_06]=22
        # §4.8.6.X TCP_HEADER_01 — active-OPEN + UT OpSendTcpData +
        # DUT data segment observation. Same envelope as CHECKSUM_03
        # (5 s SCXML deadline + ~3 s active-OPEN + OpSendTcpData
        # stimulus).
        [TCP_HEADER_01]=12
        # §4.8.6.X TCP_HEADER_02 — active-OPEN + queryTcpSeqRange +
        # raw-inject in-window data + DUT ACK with expected ack_num.
        # 2-state SCXML (5 s × 2 deadlines) + ~3 s active-OPEN
        # stimulus.
        [TCP_HEADER_02]=14
        # §4.8.6.X TCP_HEADER_05/06 — same shape as HEADER_02 with
        # explicit reserved_override (0 / 0xF). RFC 4413 §4.2.3
        # "DUT MUST ignore Reserved field" assertion.
        [TCP_HEADER_05]=14
        [TCP_HEADER_06]=14
        # §4.8.6.X TCP_HEADER_07/08/09 — active-OPEN + raw-inject
        # malformed data + 3 s absence (data_offset < 5 / data_offset
        # > actual / checksum=0). 2-state SCXML (5 s handshake + 3 s
        # absence) + ~3 s active-OPEN stimulus.
        # §4.8.6.X TCP_HEADER_04 — active-OPEN + raw-inject in-window
        # data with wrong source port + 3 s absence on EST quad.
        # 4-tuple miss falls into tcp_v4_send_reset on the wrong-port
        # quad; EST socket sees nothing.
        [TCP_HEADER_04]=12
        # §4.8.6.X TCP_HEADER_11 — active-OPEN + raw-inject SYN with
        # IP dst = 224.0.0.1 + multicast L2 + 3 s absence; Linux's
        # PACKET_HOST gate at tcp_v4_rcv silent-drops before any TCP
        # processing (RFC 1122 §4.2.3.10).
        [TCP_HEADER_11]=12
        [TCP_HEADER_07]=12
        [TCP_HEADER_08]=12
        [TCP_HEADER_09]=12
        # §4.8.6.9 TCP_MSS_OPTIONS_11 — active-OPEN; SCXML asserts the
        # DUT's outgoing SYN carries a kind=2 MSS option (captured.mss
        # > 0). Same envelope as BASICS_06 (5 s deadline + ~3 s
        # active-OPEN stimulus).
        [TCP_MSS_OPTIONS_11]=10
        # §4.8.6.9 TCP_MSS_OPTIONS_12 — same shape with stricter guard
        # captured.mss != 536. Veth MTU 1500 → MSS 1460 satisfies the
        # prerequisite without netns adjustment.
        [TCP_MSS_OPTIONS_12]=10
        # §4.8.6.9 TCP_MSS_OPTIONS_02 — UT OpenTcpPassive +
        # driveRawPassiveHandshake (TesterAutoRstDrop scope + raw-inject
        # SYN with [NOP NOP NOP EOL] + snippet-learnt ISN_d + raw-
        # inject ACK + UT OpQueryTcpEstablished). 5 s SCXML deadline +
        # ~3 s handshake + EST query stimulus.
        [TCP_MSS_OPTIONS_02]=12
        # §4.8.6.9 TCP_MSS_OPTIONS_03 — same shape with SYN options
        # [0xFD 0x04 0xAA 0xBB] (RFC 4727 kind=253 unimplemented).
        [TCP_MSS_OPTIONS_03]=12
        # §4.8.6.9 TCP_MSS_OPTIONS_01 — 3-phase compound: ilen=0
        # malformed SYN injection (close), ilen=5 malformed SYN
        # injection (close), then a well-formed verification handshake
        # to confirm the DUT process survived. 8 s SCXML deadline +
        # ~6 s cumulative malformed-inject + verify stimulus.
        [TCP_MSS_OPTIONS_01]=18
        # §4.8.6.9 TCP_MSS_OPTIONS_05 — 2-phase active-OPEN compound
        # (ilen=0 / ilen=5 malformed MSS in SYN+ACK). Each phase has a
        # 6 s SCXML deadline + ~2 s active-OPEN+inject stimulus.
        [TCP_MSS_OPTIONS_05]=20
        # §4.8.6.9 TCP_MSS_OPTIONS_10 — passive open with empty SYN
        # options + UT bulk send via OpSendTcpDataPattern. SCXML 6 s +
        # ~3 s handshake + send stimulus.
        [TCP_MSS_OPTIONS_10]=12
        # §4.8.6.9 TCP_MSS_OPTIONS_06 — 2-phase passive compound
        # (Mv=200 / Mv=2000 advertised in SYN). Each phase: 6 s SCXML
        # deadline + ~3 s handshake+bulk-send.
        [TCP_MSS_OPTIONS_06]=20
        # §4.8.6.9 TCP_MSS_OPTIONS_09 — 2-phase active-OPEN compound
        # (Mv=200 / Mv=2000 advertised in SYN+ACK). Each phase: 6 s
        # SCXML deadline + ~2 s active-OPEN+inject+bulk-send.
        [TCP_MSS_OPTIONS_09]=20
        # §4.8.6.1 TCP_BASICS_17 — RFC 793 §3.4 simultaneous-OPEN.
        # DUT active OPEN + tester raw-SYN simultaneously triggers
        # SYN-RCVD path; DUT emits SYN+ACK; tester ACK closes the
        # handshake; UT verifies ESTABLISHED. 6 s SCXML + ~2 s
        # stimulus.
        [TCP_BASICS_17]=10
        # §4.8.6.1 TCP_BASICS_13 — single FW2 → TIME-WAIT prelude +
        # within-2*MSL replay FIN (state-entry observer, 0 wall-time
        # gap). 4 SCXML states × 5 s + ~3 s stimulus wall-time.
        [TCP_BASICS_13]=10
        # §4.8.6.1 TCP_BASICS_11 — FW2 → TIME-WAIT prelude + 72 s
        # wall-time wait (kTimeWaitFullWait = 2*MSL + 20 % for the
        # Linux DUT whose TIME-WAIT timer is hardcoded 60 s) + replay
        # FIN → DUT closed-port RST. SCXML's listening_replay_rst has
        # 78 s deadline; total ≈ 3 s prelude + 1 s SCXML processing +
        # 72 s wait + ~1 s observation. 90 s budget absorbs harness
        # teardown jitter.
        [TCP_BASICS_11]=90
        # §4.8.6.3 TCP_UNACCEPTABLE_11 — two active-OPEN phases with
        # function-scoped TesterAutoAckDrop pinning DUT in FW1 across
        # each phase + driveCloseToClosing (raw-inject FIN+ACK with
        # non-acking ack → DUT FW1 → CLOSING) + CASE-distinct probe
        # (CASE 1 OTW SEQ + CASE 2 unacc ACK). 8 SCXML deadlines × 5 s
        # upper bound + ~6 s cumulative prelude wall-time.
        [TCP_UNACCEPTABLE_11]=50
        # §4.8.6.3 TCP_UNACCEPTABLE_13 — two FW2 → TIME-WAIT phases
        # (CASE 1 OTW SEQ + CASE 2 unacc ACK), each driving a 4-state
        # ACK chain. 8 SCXML deadlines × 5 s upper bound + ~6 s
        # cumulative prelude wall-time.
        [TCP_UNACCEPTABLE_13]=15
        # §4.8.6.6 TCP_FLAGS_INVALID_14 — two FW2 → TIME-WAIT phases
        # (FIN with OTW SEQ + data with OTW SEQ), each driving a
        # 4-state ACK chain. Same envelope as UNACCEPTABLE_13.
        [TCP_FLAGS_INVALID_14]=15
        # §4.8.6.6 TCP_FLAGS_INVALID_07 — five passive-listen phases with
        # raw-inject SYN driving DUT into SYN-RCVD per phase + ISN_d
        # learning via TcpFrameSnippet + CASE-distinct OTW probe (SYN /
        # SYN+ACK / ACK / FIN / data). 5 SCXML deadlines × 5 s upper
        # bound + ~8 s cumulative passive-open + raw-inject + close
        # stimulus.
        [TCP_FLAGS_INVALID_07]=40
        # §4.8.6.6 TCP_FLAGS_INVALID_08 — five active-OPEN phases with
        # a CASE-distinct OTW probe per phase (SYN / SYN+ACK / ACK /
        # FIN / data). Per phase: handshake + queryTcpSeqRange +
        # raw-inject probe + DUT empty ACK observation. 10 SCXML
        # deadlines × 5 s upper bound + ~10 s cumulative active-OPEN
        # stimulus.
        [TCP_FLAGS_INVALID_08]=70
        # §4.8.6.6 TCP_FLAGS_INVALID_11 — five active-OPEN phases with
        # tester shutdown(SHUT_WR) per phase driving DUT into
        # CLOSE-WAIT, then CASE-distinct OTW probe (SYN / SYN+ACK /
        # ACK / FIN / data). 15 SCXML deadlines × 5 s upper bound +
        # ~12 s cumulative active-OPEN + close stimulus.
        [TCP_FLAGS_INVALID_11]=90
        # §4.8.6.6 TCP_FLAGS_INVALID_10 — five active-OPEN phases with
        # UT close per phase driving DUT through FIN-WAIT-1 → tester
        # kernel auto-ACK → FIN-WAIT-2, then CASE-distinct OTW probe.
        # 15 SCXML deadlines × 5 s upper bound + ~13 s cumulative
        # active-OPEN + close + post-FIN settle stimulus.
        [TCP_FLAGS_INVALID_10]=95
        # §4.8.6.6 TCP_FLAGS_INVALID_09 — five active-OPEN phases with
        # function-scoped TesterAutoAckDrop pinning DUT in FIN-WAIT-1
        # across each phase's probe observation, then CASE-distinct
        # OTW probe with ack_num = rcv_nxt - 1.
        [TCP_FLAGS_INVALID_09]=95
        # §4.8.6.6 TCP_FLAGS_INVALID_13 — five active-OPEN phases with
        # tester shutdown(SHUT_WR) → CW + UT close → LAST-ACK
        # (TesterAutoAckDrop pinning), then CASE-distinct OTW probe.
        # 20 SCXML deadlines × 5 s upper bound + ~16 s cumulative
        # active-OPEN + tester-FIN + close + post-FIN settle stimulus.
        [TCP_FLAGS_INVALID_13]=110
        # §4.8.6.6 TCP_FLAGS_INVALID_12 — five active-OPEN phases with
        # function-scoped TesterAutoAckDrop pinning DUT in FIN-WAIT-1
        # across each phase + driveCloseToClosing (raw-inject FIN+ACK
        # with non-acking ack → DUT FW1 → CLOSING) + CASE-distinct OTW
        # probe (SYN / SYN+ACK / ACK / FIN / data). 20 SCXML deadlines
        # × 5 s upper bound + ~14 s cumulative active-OPEN + close +
        # raw-inject + silentlyCloseTesterFd stimulus.
        [TCP_FLAGS_INVALID_12]=110
        # §4.8.6.6 TCP_FLAGS_INVALID_15 — eight wst phases (SYN-RCVD /
        # EST / FW1 / FW2 / CW / CLOSING / LA / TW), each driving DUT
        # to its target state and raw-injecting RST(OTW SEQ); 3 s
        # absence window per phase observes whether DUT emits RST or
        # pure ACK (challenge ACK) on the 4-tuple. 17 SCXML obs states
        # × 5 s + 8 absence states × 3 s + ~28 s cumulative prelude
        # wall-time. Empirically Linux 6.5 silent-drops OTW RST per
        # tcp_validate_incoming RFC 5961 §3.2 (challenge ACK only when
        # seq is in window).
        [TCP_FLAGS_INVALID_15]=80
        # §4.8.6.1 TCP_BASICS_14 — CLOSING → TIME-WAIT prelude
        # (driveCloseToTimeWaitClosing: UT close + ack-suppressed
        # raw-inject FIN+ACK + raw-inject ACK + TCP_REPAIR-silent
        # close) + within-2*MSL replay FIN. 4 SCXML states × 5 s +
        # ~3 s prelude wall-time.
        [TCP_BASICS_14]=12
        # §4.8.6.1 TCP_BASICS_12 — CLOSING → TIME-WAIT prelude +
        # 72 s wait + replay FIN → DUT closed-port RST. SCXML's
        # listening_replay_rst has 78 s deadline; total ≈ 3 s prelude
        # + 1 s SCXML processing + 72 s wait + ~1 s observation. 90 s
        # budget absorbs harness teardown jitter (matches BASICS_11).
        [TCP_BASICS_12]=90
        # §4.8.6.7 TCP_FLAGS_PROCESSING_11 — single-iter active-OPEN
        # on (kBasicsActiveLocalPort + 50, kBasicsActiveRemotePort
        # + 50) + UT EST query + raw-inject duplicate third-leg ACK
        # (seq=snd_nxt, ack=rcv_nxt). 5 s handshake_ack deadline +
        # 3 s silence absence + ~3 s prelude wall-time.
        [TCP_FLAGS_PROCESSING_11]=15
        # §4.8.6.7 TCP_FLAGS_PROCESSING_06 — TIME-WAIT FIN replay
        # 1.5*MSL: driveTcpToTimeWaitFw2 prelude on +51 quad +
        # first replay FIN + 45 s wait + second replay FIN; 5 s
        # deadlines on prelude states + 50 s on the second replay
        # state to absorb the wall-time wait.
        [TCP_FLAGS_PROCESSING_06]=65
        # §4.8.6.7 TCP_FLAGS_PROCESSING_08 — three FIN-vs-non-EST
        # phases: CLOSED (kBasicsClosedPort, expect RST seq=0),
        # LISTEN (kBasicsListenPort + 14, 3 s absence), SYN-SENT
        # (kBasicsActiveLocalPort + 52, DUT SYN trigger + 3 s
        # absence; SYN retx tolerated). 5 s + 3 s + 5 s + 3 s
        # SCXML deadlines + ~3 s prelude wall-time.
        [TCP_FLAGS_PROCESSING_08]=20
        # §4.8.6.7 TCP_FLAGS_PROCESSING_07 — four URG-only-ignore
        # phases: CW (+53), CLOSING (+54), LA (+55), TW (+56).
        # 13 prelude observation states × 5 s + 4 absence states ×
        # 3 s + ~14 s cumulative prelude wall-time. URG-only is
        # silent across all 4 states per Linux's tcp_validate_incoming
        # (!th->ack early discard) + tcp_timewait_state_process.
        [TCP_FLAGS_PROCESSING_07]=90
        # §4.8.6.7 TCP_FLAGS_PROCESSING_09 — three FIN+ACK-no-state-
        # change phases: CW (+57, valid ack), CLOSING (+58, invalid
        # ack), LA (+59, invalid ack). 11 prelude states × 5 s +
        # 3 absence × 3 s + ~10 s prelude wall-time.
        [TCP_FLAGS_PROCESSING_09]=70
        # §4.8.6.7 TCP_FLAGS_PROCESSING_05 — two SYN-RCVD-with-
        # in-window-stp phases: SYN (listen +10, prelude tester
        # +72, verify tester +73) + SYN+ACK (listen +11, prelude
        # +74, verify +75). 4 listening states × 5 s + ~3 s
        # prelude wall-time per phase.
        [TCP_FLAGS_PROCESSING_05]=30
        # §4.8.6.7 TCP_FLAGS_PROCESSING_02 — five RST→CLOSED
        # phases: SYN-RCVD (listen +12 / tester +76), EST (+60),
        # FW1 (+61), FW2 (+62), CW (+63). 12 prelude states × 5 s
        # + 5 verify_rst states × 5 s + ~10 s prelude wall-time.
        # Per phase a verify-probe ACK on the killed 4-tuple
        # elicits DUT RST as wire-observable proof of CLOSED.
        [TCP_FLAGS_PROCESSING_02]=110
        # §4.8.6.8 TCP_CLOSING_03 — EST RST(with payload) → CLOSED.
        # Active-OPEN +71 quad → spec RST with 16-byte payload →
        # 3 s spec_silence absence → verify-probe ACK → DUT RST
        # proves CLOSED. 5 s + 3 s + 5 s SCXML deadlines + ~3 s
        # prelude wall-time.
        [TCP_CLOSING_03]=20
        # §4.8.6.8 TCP_CLOSING_09 — EST + tester FIN → CW + DUT data
        # send. Active-OPEN +72 quad → shutdown(WR) → DUT FIN-ACK →
        # UT sendTcpData(16B) → DUT PSH+ACK → 3 s remain-in-CW
        # absence asserts no DUT FIN/RST. 4 × 5 s SCXML observation
        # deadlines + 3 s absence + ~3 s prelude wall-time.
        [TCP_CLOSING_09]=25
        # §4.8.6.8 TCP_CLOSING_07 — FW1 + RECEIVE + DATA → ACK +
        # remain in FW1. Active-OPEN +73 quad → AckDrop (long-life via
        # 120 s scheduled keepalive) → UT close → DUT FIN+ACK (no
        # peer-ACK) → raw inject 16 B data with non-acking ack →
        # DUT data-ACK → UT recv → byte match → 3 s remain-in-FW1
        # absence (FIN re-tx tolerated). 4 × 5 s observation + 3 s
        # absence + ~3 s prelude.
        [TCP_CLOSING_07]=30
        # §4.8.6.8 TCP_CLOSING_08 — FW2 + RECEIVE + DATA → ACK +
        # remain in FW2. Active-OPEN +74 quad → UT shutdown(WR) →
        # tester kernel auto-ACK drives DUT FW1→FW2 (NO AckDrop) →
        # raw inject 16 B data → DUT data-ACK → UT recv → byte match
        # → 3 s remain-in-FW2 absence (no FIN re-tx since tester
        # already acked). 4 × 5 s observation + 3 s absence + ~3 s
        # prelude.
        [TCP_CLOSING_08]=30
        # §4.8.6.5 TCP_CALL_ABORT_02 — EST + UT abort → DUT RST
        # → CLOSED. Active-OPEN +90 quad → SO_LINGER {1,0} + close
        # → verify-probe ACK on killed 4-tuple → DUT closed-port
        # RST. 3 × 5 s SCXML observation deadlines + ~3 s prelude.
        [TCP_CALL_ABORT_02]=20
        # §4.8.6.4 TCP_CALL_RECEIVE_05 — EST + tester FIN+data →
        # CW + UT recv. Active-OPEN +94 quad → raw inject PSH+FIN+
        # ACK with 16-byte payload → DUT pure ACK (acks data+FIN)
        # → UT recv drains bytes → 3 s remain-in-CW absence. 3 × 5 s
        # observation + 3 s absence + ~3 s prelude.
        [TCP_CALL_RECEIVE_05]=20
        # §4.8.6.4 TCP_CALL_RECEIVE_04 — 3 iterations
        # (EST/FW1/FW2). Each phase: distinct port quad (+95/+96/
        # +97), 4 × 32 B raw-inject + single 128 B UT recv. Phase
        # 2 holds shared_ptr<TesterAutoAckDrop> long-life so DUT
        # remains in FW1 across the inject window. SCXML chain has
        # 8 listening states × 5 s + ~10 s prelude wall-time.
        [TCP_CALL_RECEIVE_04]=60
        # §4.8.6.5 TCP_CALL_ABORT_03 — 3 iterations
        # (CLOSING/LAST-ACK/TIME-WAIT). Phases on +91/+92/+93.
        # Each phase: handshake_ack (5s) → settle (5s, prelude +
        # abort egress absorbed) → verify_rst (5s, verify-probe ACK
        # draws closed-port RST). 9 × 5 s + ~10 s prelude wall-time.
        [TCP_CALL_ABORT_03]=70
        # §4.8.6.18 TCP_ACKNOWLEDGEMENT_03 — passive raw-handshake on
        # listen 13030 + raw-inject 4 B PSH+ACK + DUT pure ACK with
        # ack_num covering payload. Single 5 s SCXML deadline + ~3 s
        # handshake / data inject / close stimulus.
        [TCP_ACKNOWLEDGEMENT_03]=12
        # §4.8.6.18 TCP_ACKNOWLEDGEMENT_02 — active-OPEN +130 quad +
        # UT OpSendTcpData (DUT sends 4 B) + queryTcpSeqRange post-
        # auto-ACK + raw-inject piggyback ACK+4 B + DUT ACK with
        # expected ack_num. 2 × 5 s SCXML deadlines + ~3 s prelude.
        [TCP_ACKNOWLEDGEMENT_02]=14
        # §4.8.6.18 TCP_ACKNOWLEDGEMENT_04 — active-OPEN +131 quad +
        # UT OpSendTcpData + tester kernel auto-ACK (Length=0) + 3 s
        # absence of DUT RST + UT close + DUT FIN observation.
        # 5 s handshake + 3 s absence + 5 s FIN + ~3 s prelude.
        [TCP_ACKNOWLEDGEMENT_04]=20
        # §4.8.6.13 TCP_NAGLE_02 — active-OPEN +132 quad +
        # TesterAutoAckDrop + 2× UT OpSendTcpData (10 B each) + 3 s
        # absence asserting Nagle holds the 2nd seg + raw-inject ACK
        # releases the 2nd seg. 5 s + 3 s + 5 s SCXML deadlines +
        # ~5 s stimulus wall-time.
        [TCP_NAGLE_02]=20
        # §4.8.6.13 TCP_NAGLE_03 — active-OPEN +133 quad +
        # TesterAutoAckDrop + UT OpSendTcpData (10 B) ×2 + UT
        # OpSendTcpDataPattern (1450 B) so cumulative buffered
        # equals MSS. SCXML asserts the DUT-emitted aggregate has
        # payload_len > 100 B and seq != first_seg_seq. 5 s + 6 s
        # SCXML deadlines + ~3 s stimulus wall-time.
        [TCP_NAGLE_03]=18
        # §4.8.6.19 TCP_CONTROL_FLAGS_05 — active-OPEN +140 quad +
        # queryTcpSeqRange post-handshake + raw-inject URG+PSH+ACK
        # (4 B payload, urgent_pointer=4) + DUT pure ACK with
        # ack_num covering the URG payload. 2 × 5 s SCXML deadlines
        # + ~3 s prelude.
        [TCP_CONTROL_FLAGS_05]=14
        # §4.8.6.19 TCP_CONTROL_FLAGS_08 — passive listen 13041 +
        # tester +91, RFC 793 §3.4 figure 9 old-duplicate-SYN
        # recovery: SYN(SEQ1) → DUT SYN,ACK → SYN+RST(SEQ1+1) → DUT
        # back to LISTEN → SYN(SEQ2) → DUT SYN,ACK. 2 × 5 s SCXML
        # deadlines + ~2 s stimulus.
        [TCP_CONTROL_FLAGS_08]=14
        # §4.8.6.14 TCP_URGENT_PTR_04 — active-OPEN +142 quad +
        # raw-inject URG+PSH+ACK (6 B "ABCDEF", urgent_pointer=3)
        # + UT OpReceiveTcpDataOob — recv(MSG_OOB) returns 1 byte
        # 'C', proving urgent data is delivered separately from
        # the trailing non-urgent bytes (RFC 793 §3.7). 5 s + 1 s
        # SCXML deadlines + ~3 s prelude.
        [TCP_URGENT_PTR_04]=12
        # §4.8.6.10 TCP_OUT_OF_ORDER_03 — active-OPEN +143 quad +
        # 4× raw-inject data segments (SEG0, SEG_GAP1, SEG_GAP2,
        # SEG_FILL) leaving a 4 B gap. DUT cumulative ACK does not
        # advance past the gap until SEG_FILL closes it. 3 × 5 s
        # SCXML deadlines + ~3 s prelude.
        [TCP_OUT_OF_ORDER_03]=20
        # §4.8.6.7 TCP_FLAGS_PROCESSING_10 — active-OPEN +144 quad +
        # TesterAutoAckDrop + 2× UT OpSendTcpData (4 B each) so the
        # 1st seg stays unacked and Nagle holds the 2nd small SEND.
        # scheduleAfterStateEntry raw-injects a piggyback PSH+ACK
        # (ack covers seg 1 + 4 B payload). DUT must release seg 2
        # piggyback-acking the tester payload within 0.5 sec. 5 s +
        # 3 s + 0.5 s SCXML deadlines + ~3 s prelude.
        [TCP_FLAGS_PROCESSING_10]=15
        # §4.8.6.10 TCP_OUT_OF_ORDER_01 — active-OPEN +145 quad + 1×
        # raw-inject MSS-sized PSH+ACK (1460 B). DUT quickack mode
        # (post-handshake pingpong=0) emits an immediate pure ACK with
        # ack_num covering the segment. Spec asserts < 0.5 sec; phase 2
        # SCXML deadline 500 ms strict. 5 s phase 1 + 0.5 s phase 2 +
        # ~3 s prelude.
        [TCP_OUT_OF_ORDER_01]=12
        # §4.8.6.10 TCP_OUT_OF_ORDER_02 — active-OPEN +146 quad + 2×
        # raw-inject 100 B PSH+ACK consecutively (no inter-segment
        # pacing). DUT emits cumulative ACK covering both within
        # 500 ms; intermediate seg0-only ACK (in quickack mode) is
        # tolerated implicitly via expected_ack_num equality. 5 s +
        # 0.5 s SCXML deadlines + ~3 s prelude.
        [TCP_OUT_OF_ORDER_02]=12
        # §4.8.6.10 TCP_OUT_OF_ORDER_05 — active-OPEN +147 quad +
        # 10× raw-inject MSS-sized PSH+ACK (5 ms inter-segment pacing).
        # 5-ACK consume chain (5 chained SCXML phases) asserts ≥ 5
        # DUT pure ACKs land. 5 s phase 1 + 5*1 s consume + ~3 s
        # prelude = 13 s SCXML budget; raised to 18 s to absorb
        # burst-window jitter under parallel workers.
        [TCP_OUT_OF_ORDER_05]=18
        # §4.8.6.12 TCP_PROBING_WINDOWS_02 — active-OPEN +148 quad +
        # raw-inject 1 B PSH+ACK with window=0x8000 (MSB set, RFC 793
        # §3.1 unsigned) to drive Linux's tcp_ack_update_window +
        # 100 ms settle + UT OpSendTcpData (4 B). DUT must emit a
        # data segment proving the MSB-set window was honoured as
        # unsigned 32768. 5 s phase 1 + 3 s phase 2 + ~3 s prelude.
        [TCP_PROBING_WINDOWS_02]=14
        # §4.8.6.12 TCP_PROBING_WINDOWS_03 — active-OPEN +149 quad +
        # 3 MSS-fill SENDs (seg1/seg2/seg3) + raw-inject ACK at
        # seg3_seq with window=0 (acks seg2 only → useable window
        # negative) + 4th SEND absence guard. 4-state SCXML: 5 s × 3
        # data segment phases + 4 s absence window + ~3 s prelude.
        [TCP_PROBING_WINDOWS_03]=24
        # §4.8.6.12 TCP_PROBING_WINDOWS_05 — active-OPEN +150 quad +
        # raw-inject window=0 ACK after seg1 + second SEND (queued
        # behind snd_wnd=0) → DUT enters persist mode and emits a
        # zero-window probe after first persist RTO. 2-state SCXML:
        # 5 s seg1 phase + 6 s probe phase + ~3 s prelude.
        [TCP_PROBING_WINDOWS_05]=18
        # §4.8.6.12 TCP_PROBING_WINDOWS_04 — active-OPEN +151 quad +
        # 3-probe consume chain with per-probe ACK injection via
        # scheduleAfterStateEntry. 4-state SCXML: 5 s seg1 + 4 s
        # probe1 + 6 s probe2 + 10 s probe3 (Linux backoff doubles
        # each round) + ~3 s prelude.
        [TCP_PROBING_WINDOWS_04]=32
        # §4.8.6.12 TCP_PROBING_WINDOWS_06 — active-OPEN +152 quad +
        # 3-probe consume chain WITHOUT per-probe ACK; Linux's
        # icsk_backoff doubles each probe naturally. 4-state SCXML:
        # 5 s seg1 + 4 s probe1 + 4 s probe2 + 6 s probe3 + ~3 s
        # prelude.
        [TCP_PROBING_WINDOWS_06]=24
        # §4.8.6.11 TCP_RETRANSMISSION_TO_06 — active-OPEN +153 quad
        # with no tester listener + TesterAutoRstDrop suppressing
        # auto-RSTs. SCXML 2-state: 5 s first_syn + 2.5 s syn_retx
        # + ~2 s prelude. Strict timing assertion via
        # `frame_delta_us()` window [800 ms, 1500 ms] gating Linux's
        # TCP_TIMEOUT_INIT = 1 s.
        [TCP_RETRANSMISSION_TO_06]=12
        # §4.8.6.11 TCP_RETRANSMISSION_TO_05 — active-OPEN +155 quad
        # observing 3 SYN retransmits with strictly-doubling
        # `frame_delta_us` gates (initial RTO 800-1500 ms, retx2 >
        # 1500 ms, retx3 > 3500 ms). 4-state SCXML: 5 + 2.5 + 3.5 +
        # 5.5 = 16.5 s phase budget + ~2 s prelude.
        [TCP_RETRANSMISSION_TO_05]=22
        # §4.8.6.11 TCP_RETRANSMISSION_TO_04 — active-OPEN +154 quad
        # ESTABLISHED + SEND + TesterAutoAckDrop blocking auto-ACKs
        # so DUT data RTO loop fires. 4-state SCXML observing 3
        # retransmits with strictly-doubling `frame_delta_us` gates
        # (initial 80-400 ms, retx2 > 300 ms, retx3 > 600 ms). 5 +
        # 1 + 1.5 + 2 = 9.5 s phase + ~3 s prelude.
        [TCP_RETRANSMISSION_TO_04]=15
        # §4.8.6.11 TCP_RETRANSMISSION_TO_03 — active-OPEN +156 quad
        # 2-phase Karn doubling preservation, kernel-side TCP_INFO
        # observation (Phase 9 2026-04-29). Wall budget: prelude ~2 s
        # + phase 1 poll (median 250 ms, p95 ~1 s, hard 3 s) + Karn ACK
        # + phase 2 poll (sub-second, hard 1 s) + scheduler tick. Worst
        # case ~6 s; 8 s carries 33 % safety margin without bloating
        # the smoke envelope.
        [TCP_RETRANSMISSION_TO_03]=8
        # §4.8.6.17 TCP_SEQUENCE_01/03/04 — passive listen 13160/63/64 +
        # tester +160/+163/+164. driveRawPassiveHandshake emits SYN
        # (seq=tester_isn ∈ {kTesterInitialSeq, 0, 0xFFFFFFFF}) and
        # observes DUT SYN,ACK with ack_num == tester_isn + 1. RFC 793
        # §3.1 modulo-32 wraparound for _04. Single 5 s SCXML deadline +
        # ~3 s stimulus.
        [TCP_SEQUENCE_01]=10
        [TCP_SEQUENCE_03]=10
        [TCP_SEQUENCE_04]=10
        # §4.8.6.17 TCP_SEQUENCE_02 — active-OPEN +161 quad +
        # TesterAutoRstDrop + DUT-SYN snippet capture + raw-inject
        # SYN,ACK with seq=kTesterInitialSeq, ack=ISN_d+1 + DUT pure
        # ACK with ack_num == kTesterInitialSeq+1. 6 s SCXML + ~3 s
        # prelude.
        [TCP_SEQUENCE_02]=12
        # §4.8.6.17 TCP_SEQUENCE_05 — passive listen 13165 + tester
        # +165 + driveRawPassiveHandshake + 3× 4 B PSH+ACK at 100 ms
        # gaps + 3 sequential DUT cumulative ACKs at +5/+9/+13. Outer
        # TesterAutoRstDrop covers post-handshake data flow. 3 × 5 s
        # SCXML deadlines + ~3 s prelude.
        [TCP_SEQUENCE_05]=20
        # §4.8.6.15 TCP_CONNECTION_ESTAB_02 — 3 passive listeners
        # 13173/74/75 + tester +173/+174/+175. 3 raw-inject SYNs at
        # 50 ms gaps; 3 DUT SYN,ACK observations on the matching
        # 4-tuples. Outer TesterAutoRstDrop. 3 × 5 s SCXML + ~3 s
        # prelude.
        [TCP_CONNECTION_ESTAB_02]=20
        # §4.8.6.15 TCP_CONNECTION_ESTAB_03 — 3 active opens at
        # +176/+177/+178 quads, each with a tester listener that
        # absorbs the DUT SYN and lets the kernel auto-handshake.
        # SCXML observes 3 DUT third-leg ACKs. 3 × 6 s + ~3 s prelude.
        [TCP_CONNECTION_ESTAB_03]=22
        # §4.8.6.15 TCP_CONNECTION_ESTAB_07 — passive close path on
        # listen 13179. UT passive open + tester connect +
        # shutdown(SHUT_WR) → DUT auto-ACK; UT close → DUT FIN.
        # 2 × 6 s SCXML + ~3 s stimulus.
        [TCP_CONNECTION_ESTAB_07]=15
        # §4.8.6.15 TCP_CONNECTION_ESTAB_01 — single passive listen
        # 13170 + 3 raw-inject SYNs from +170/+171/+172. SCXML 3-state
        # observing 3 DUT SYN,ACKs distinguished by dst_port. Outer
        # TesterAutoRstDrop. 3 × 5 s SCXML + ~3 s prelude.
        [TCP_CONNECTION_ESTAB_01]=20
        # §4.5.6.2 IPV4_AUTOCONF_ADDRESS_SELECTION_01/03/05/06/07/08
        # — UT OpStartLLAutoconf with fast envelope. First Probe
        # lands at ~1500 ms initial wait + 200 ms dhcp_timeout +
        # 200 ms PROBE_WAIT ≈ 1.9 s. SCXML 4 s deadline. 8 s gives
        # ~2 s margin against worker scheduling jitter.
        [IPV4_AUTOCONF_ADDRESS_SELECTION_01]=8
        [IPV4_AUTOCONF_ADDRESS_SELECTION_03]=8
        [IPV4_AUTOCONF_ADDRESS_SELECTION_05]=8
        [IPV4_AUTOCONF_ADDRESS_SELECTION_06]=8
        [IPV4_AUTOCONF_ADDRESS_SELECTION_07]=8
        [IPV4_AUTOCONF_ADDRESS_SELECTION_08]=8
        # §4.5.6.2 IPV4_AUTOCONF_ADDRESS_SELECTION_09/_10 — RFC 3927
        # cadence defaults (PROBE_WAIT 1 s, PROBE_MIN..MAX 1..2 s).
        # Probe3 lands at ~1.5 + 0.2 + 1 + 2 × uniform(1, 2) =
        # 4.7..6.7 s. SCXML 12 s deadline gives ~5 s margin; 15 s
        # case_timeout absorbs stimulus + post-Probe3 settle.
        [IPV4_AUTOCONF_ADDRESS_SELECTION_09]=15
        [IPV4_AUTOCONF_ADDRESS_SELECTION_10]=15
        # §4.5.6.2 ADDRESS_SELECTION_*_NEG fault-injection self-
        # validation (Session 3). Cluster A negatives reuse the fast
        # envelope (first Probe ~1.9 s, 4 s SCXML deadline). _10_NEG
        # uses the fast envelope with probe_min=probe_max=100 ms so
        # Probe2 lands ~100 ms after Probe1; 6 s SCXML deadline. 8 s
        # for cluster A, 9 s for cadence — ~2-3 s margin.
        [IPV4_AUTOCONF_ADDRESS_SELECTION_01_NEG]=8
        [IPV4_AUTOCONF_ADDRESS_SELECTION_05_NEG]=8
        [IPV4_AUTOCONF_ADDRESS_SELECTION_06_NEG]=8
        [IPV4_AUTOCONF_ADDRESS_SELECTION_07_NEG]=8
        [IPV4_AUTOCONF_ADDRESS_SELECTION_08_NEG]=8
        [IPV4_AUTOCONF_ADDRESS_SELECTION_10_NEG]=9
        # §4.5.6.2 ADDRESS_SELECTION_11/_12/_13 probing-window CONFLICT
        # (Session 4). Tester observes DUT Probe1 (~1.9 s), injects
        # conflict ARP, DUT must re-pick. Re-pick wall:
        #   1.9 s (Probe1 of X) + ~50 ms (state-entry observer +
        #   wire) + remaining Probes/ANNOUNCE_WAIT of X (~700 ms) +
        #   PROBE_WAIT (200 ms) of Y + Probe1 of Y ≈ 2.85 s typical.
        # 12 s SCXML window absorbs slow DUT detection + listener
        # join latency; 15 s case_timeout gives ~3 s margin.
        [IPV4_AUTOCONF_ADDRESS_SELECTION_11]=15
        [IPV4_AUTOCONF_ADDRESS_SELECTION_12]=15
        [IPV4_AUTOCONF_ADDRESS_SELECTION_13]=15
        # §4.5.6.2 ADDRESS_SELECTION_14 conflict-resolution
        # (Session 5). 10 conflict cycles followed by a full
        # rate_limit silence window:
        #   ~1.9 s Probe1 (LL_1) + 9 × ~250 ms re-pick cycles
        #   ≈ 4 s of conflict cycles + 3 s rate_limit silence
        #   = ~7 s wall.
        # 12 s SCXML deadline absorbs scheduling jitter; 15 s
        # case_timeout gives 3 s margin.
        [IPV4_AUTOCONF_ADDRESS_SELECTION_14]=15
        # §4.5.6.2 ADDRESS_SELECTION_15 rate-limit-persistence
        # (Session 6). Same 10-cycle phase as _14, then a full
        # rate_limit silence window, post-silence Probe + 11th
        # conflict, then ANOTHER full rate_limit silence window:
        #   ~1.7 s Probe1 + ~2.5 s conflict cycles + 3 s silence_1
        #   + ~0.3 s rate-limit recovery + Probe11 + 3 s silence_2
        #   ≈ 10.5 s wall.
        # 15 s SCXML deadline absorbs scheduling jitter; 18 s
        # case_timeout gives ~3 s margin against worker contention.
        [IPV4_AUTOCONF_ADDRESS_SELECTION_15]=18
        # §4.5.6.2 ADDRESS_SELECTION_16 claim-condition Reply
        # (Session 7). Wall budget: ~1.5 s initial wait + ~1.4 s
        # PROBE/ANNOUNCE + scheduled closure at 3.5 s + ~50 ms DUT
        # responder poll tick ≈ 3.6 s for the Reply. 8 s SCXML
        # deadline; 12 s case_timeout adds 4 s margin against
        # worker scheduling jitter.
        [IPV4_AUTOCONF_ADDRESS_SELECTION_16]=12
        # §4.5.6.4 CONFLICT_06..10 defender always-cease cluster
        # (Session 8). Wall budget: ~1.5 s initial wait + ~2.85 s
        # to first DUT Announce (pre_claim → post_claim transition)
        # + ~10 ms UT-query + ~50 ms DUT responder tick + 200 ms
        # probe_wait + ~250 ms first re-pick Probe ≈ 4.85 s. 6 s
        # pre_claim + 4 s post_claim = 10 s SCXML budget; 13 s
        # case_timeout adds 3 s margin against worker contention.
        [IPV4_AUTOCONF_CONFLICT_06]=13
        [IPV4_AUTOCONF_CONFLICT_07]=13
        [IPV4_AUTOCONF_CONFLICT_08]=13
        [IPV4_AUTOCONF_CONFLICT_09]=13
        [IPV4_AUTOCONF_CONFLICT_10]=13
        # §4.5.6.4 CONFLICT_11 broadcast-Reply assertion (Session 8).
        # Same wall envelope as ADDRESS_SELECTION_16 (claim-condition
        # Request → broadcast Reply); 12 s case_timeout matches.
        [IPV4_AUTOCONF_CONFLICT_11]=12
        # §4.5.6.3 ANNOUNCING_01..05 — fast envelope, observe DUT's
        # first (or first two) Announce(s) after Probe phase. Wall
        # budget: ~1.5 s initial + 200 ms dhcp + 200 ms PROBE_WAIT +
        # ~600 ms 3 Probes + 200 ms ANNOUNCE_WAIT (+ 200 ms
        # ANNOUNCE_INTERVAL for _05) ≈ 2.7..2.9 s. SCXML 4 s deadline;
        # 8 s case_timeout matches the cluster A field-invariant
        # precedent.
        [IPV4_AUTOCONF_ANNOUNCING_01]=8
        [IPV4_AUTOCONF_ANNOUNCING_02]=8
        [IPV4_AUTOCONF_ANNOUNCING_03]=8
        [IPV4_AUTOCONF_ANNOUNCING_04]=8
        [IPV4_AUTOCONF_ANNOUNCING_05]=8
        # §4.5.6.3 ANNOUNCING NEG cluster — same fast envelope as
        # _01..04, OpStartLLAutoconfBuggy with Announce-shape flavors;
        # SCXML deadline + case_timeout match the positive cluster.
        [IPV4_AUTOCONF_ANNOUNCING_01_NEG]=8
        [IPV4_AUTOCONF_ANNOUNCING_02_NEG]=8
        [IPV4_AUTOCONF_ANNOUNCING_03_NEG]=8
        [IPV4_AUTOCONF_ANNOUNCING_04_NEG]=8
        # §4.5.6.3 ANNOUNCING_06 — RFC 3927 cadence defaults
        # (ANNOUNCE_INTERVAL = 2000 ms ± 50 ms). Wall budget at RFC
        # cadence: ~1.5 s initial + 200 ms dhcp + 1 s PROBE_WAIT +
        # ~3 s 3 Probes + 2 s ANNOUNCE_WAIT + 2 s ANNOUNCE_INTERVAL
        # ≈ 9.7 s. SCXML 12 s deadline; 15 s case_timeout absorbs
        # stimulus + post-Announce settle and worker scheduling jitter.
        [IPV4_AUTOCONF_ANNOUNCING_06]=15
        # §4.5.6.5 LINKLOCAL_PACKETS_04 — fast envelope two-Announce
        # gate then 3 s absence window for an arbitrary-target
        # AIFACE-LL Request. Wall budget: ~2.9 s through Announce 2 +
        # ~50 ms inject + 3 s absence + harness margin ≈ 6 s. 10 s
        # case_timeout carries comfortable buffer for worker jitter.
        [IPV4_AUTOCONF_LINKLOCAL_PACKETS_04]=10
        # §4.5.6.6 NETWORK_PARTITIONS_01 — fast envelope two-Announce
        # gate, 3 s reply window, then 3 s no-periodic absence window.
        # Wall budget: ~2.9 s through Announce 2 + UT-query (~10s of ms)
        # + Reply (~50 ms responder tick) + 3 s absence ≈ 6 s. 12 s
        # case_timeout matches CONFLICT_11 / ADDRESS_SELECTION_16's
        # claim-condition cluster.
        [IPV4_AUTOCONF_NETWORK_PARTITIONS_01]=12
        # §4.7.6.1/.2 DHCPV4_CLIENT_PROTOCOL_01/02 + SUMMARY_04
        # passive-observation cluster (Session 1, 2026-04-28). Stimulus
        # is the §4.5 fast OpStartLLAutoconf which 1-shots a
        # DHCPDISCOVER ~1.7 s after the RPC (1.5 s initial wait +
        # 200 ms dhcp_timeout). SCXML 4 s deadline; 8 s case_timeout
        # mirrors the §4.5 cluster A field-invariant precedent and
        # gives ~2 s margin against worker scheduling jitter.
        [DHCPV4_CLIENT_PROTOCOL_01]=8
        [DHCPV4_CLIENT_PROTOCOL_02]=8
        [DHCPV4_CLIENT_SUMMARY_04]=8
        # §4.7.6.3 ALLOCATING_01 + §4.7.6.7 CONSTRUCTING_MESSAGES_01/03
        # passive carry-over cluster (Session 2, 2026-04-28). Same
        # single-DISCOVER stimulus shape as PROTOCOL_01/02 / SUMMARY_04;
        # no server emulation needed, server-emul-free observation cases
        # before the lifecycle infra lands.
        [DHCPV4_CLIENT_ALLOCATING_01]=8
        [DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_01]=8
        [DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_03]=8
        # §4.7.6.1 SUMMARY_01 + §4.7.6.2 PROTOCOL_03 lifecycle cluster
        # (Session 2, 2026-04-28). Stimulus: OpStartDhcpClient (0x10)
        # kicks tc8-dut full DISCOVER → OFFER → REQUEST → ACK lifecycle
        # against the tester-side server emul. SCXML budget: 6 s
        # listening_for_discover (initial wait + DISCOVER) + 4 s
        # listening_for_request (OFFER → REQUEST round-trip) = 10 s
        # SCXML deadline; 14 s case_timeout = 4 s margin against worker
        # scheduling jitter at --workers 4.
        [DHCPV4_CLIENT_SUMMARY_01]=14
        [DHCPV4_CLIENT_PROTOCOL_03]=14
        # §4.7.6.7 CONSTRUCTING_MESSAGES_04 + §4.7.6.3 ALLOCATING_05 +
        # §4.7.6.8 REQUEST_01 — REQUEST shape invariant cluster
        # (Session 4, 2026-04-28). Same lifecycle envelope as SUMMARY_01
        # / PROTOCOL_03 (DISCOVER → tester OFFER → REQUEST observation),
        # so the 14 s case_timeout carries unchanged.
        [DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_04]=14
        [DHCPV4_CLIENT_ALLOCATING_05]=14
        [DHCPV4_CLIENT_REQUEST_01]=14
        # §4.7.6.3 ALLOCATING_03 + §4.7.6.8 REQUEST_02 — REQUEST option
        # echo cluster (Session 4, 2026-04-28). Same lifecycle envelope
        # as the Stage 1 cases; pass criterion is `option_be32_equals`
        # against `expected.server_id_be` (Option 54) /
        # `expected.offered_ip_be` (Option 50).
        [DHCPV4_CLIENT_ALLOCATING_03]=14
        [DHCPV4_CLIENT_REQUEST_02]=14
        # §4.7.6.1 SUMMARY_03 — 576-octet padded OFFER ingest (Session 4,
        # 2026-04-28). Same envelope as SUMMARY_01; OFFER builder pads
        # with RFC 2131 §3 PADs before END so the IPv4 datagram is
        # exactly 576 B (RFC 791 minimum reassembly).
        [DHCPV4_CLIENT_SUMMARY_03]=14
        # §4.7.6.1 SUMMARY_02 — multi-server xid filter (Session 4,
        # 2026-04-28). Two server emuls on Listening_for_request entry:
        # SERVER-1 with xid_offset=+1 (mismatched, MUST be discarded),
        # SERVER-2 matched-xid + distinct server_id. Pass = REQUEST
        # Option 54 = SERVER-2 ID.
        [DHCPV4_CLIENT_SUMMARY_02]=14
        # §4.7.6.8 DHCPv4_CLIENT_REQUEST_06..08 RENEWING (Session 6a,
        # 2026-04-28). 1.5 s pilot + ~150 ms DISCOVER/OFFER/REQUEST/ACK
        # + 3 s T1 wait + RENEWING REQUEST observation ≈ 5 s typical.
        # SCXML deadlines 6 + 4 + 8 = 18 s cumulative; 14 s case_timeout
        # matches REQUEST_01/02 budget against worker scheduling jitter.
        [DHCPV4_CLIENT_REQUEST_06]=14
        [DHCPV4_CLIENT_REQUEST_07]=14
        [DHCPV4_CLIENT_REQUEST_08]=14
        # §4.7.6.8 DHCPv4_CLIENT_REQUEST_09..12 REBINDING (Session 6a,
        # 2026-04-28). Adds the T2 wait (5 s post-BOUND for the REBINDING
        # REQUEST emit) and state 4 deadline 6 s on top of the RENEWING
        # lifecycle; typical pass wall ≈ 7 s. 14 s case_timeout = 7 s
        # margin against worker contention.
        [DHCPV4_CLIENT_REQUEST_09]=14
        [DHCPV4_CLIENT_REQUEST_10]=14
        [DHCPV4_CLIENT_REQUEST_11]=14
        [DHCPV4_CLIENT_REQUEST_12]=14
        # §4.7.6.7/.8 RENEWING REQUEST shape (Session 6b). Same pass
        # wall as REQUEST_06..08 (RENEWING template, T1=3 s pass at ~5 s
        # typical). 14 s case_timeout matches the RENEWING budget.
        [DHCPV4_CLIENT_REACQUISITION_01]=14
        [DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_02]=14
        # §4.7.6.8 REBINDING REQUEST shape (Session 6b). Same pass wall
        # as REQUEST_09..12 (REBINDING template, T2=5 s pass at ~7 s
        # typical).
        [DHCPV4_CLIENT_REACQUISITION_02]=14
        # §4.7.6.3 ALLOCATING_09 + §4.7.6.8 REACQUISITION_08 (Session 6b)
        # `dhcpv4_post_bound_discover` template. ALLOCATING_09 pass wall
        # ≈ 4 s (NAK on RENEWING REQUEST → INIT restart → DISCOVER #2);
        # REACQUISITION_08 pass wall ≈ 7 s (no T1/T2 reply → lease
        # expiry at +6 s → INIT restart). 14 s case_timeout covers both.
        [DHCPV4_CLIENT_ALLOCATING_09]=14
        [DHCPV4_CLIENT_REACQUISITION_08]=14
        # §4.7.6.8 REACQUISITION_03/_04 timing (Session 6b). Same SCXML
        # lifecycle as REQUEST_06/_09 (RENEWING / REBINDING templates);
        # additional pass-criterion is the ACK→REQUEST interval bound.
        [DHCPV4_CLIENT_REACQUISITION_03]=14
        [DHCPV4_CLIENT_REACQUISITION_04]=14
        # §4.7.6.3 ALLOCATING_10 + §4.7.6.8 REACQUISITION_05 retx
        # (Session 6b). Promoted lease (kRetransmissionLeaseSeconds=12s)
        # → T1=6s, T2=10s, retx interval=2s. Pass wall ≈ 1.5s pilot +
        # 8s (T1 + retx) + jitter = ~10s. 14 s case_timeout leaves
        # 4 s margin.
        [DHCPV4_CLIENT_ALLOCATING_10]=14
        [DHCPV4_CLIENT_REACQUISITION_05]=14
        # §4.7.6.8 REACQUISITION_06 REBINDING retx (Session 6b). Same
        # 12 s lease; T2=10s, retx interval=1s. Pass wall ≈ 1.5s
        # pilot + 11s (T2 + retx) + jitter = ~13s. 18 s case_timeout
        # leaves 5 s margin.
        [DHCPV4_CLIENT_REACQUISITION_06]=18
        # §4.7.6.8 REACQUISITION_07 lease-release UDP absence (Session 6b).
        # 1.5s pilot + 6s lease + 3s absence window = ~10.5s typical.
        [DHCPV4_CLIENT_REACQUISITION_07]=14
        # §4.7.6.9 INITIALIZATION_ALLOCATION Stage A (Session 9, 2026-04-28).
        # _02 (DISCOVER ciaddr=0) and _03 (DISCOVER chaddr=DUT MAC) reuse
        # the §4.5 OpStartLLAutoconf 1-shot DISCOVER stimulus — same 8 s
        # case_timeout as PROTOCOL_01/02 / SUMMARY_04. _06 (REQUEST xid ==
        # DISCOVER xid) uses the SUMMARY_01 lifecycle envelope (DISCOVER
        # → tester OFFER → REQUEST observation) — same 14 s case_timeout
        # as SUMMARY_01 / PROTOCOL_03.
        [DHCPV4_CLIENT_INITIALIZATION_ALLOCATION_02]=8
        [DHCPV4_CLIENT_INITIALIZATION_ALLOCATION_03]=8
        [DHCPV4_CLIENT_INITIALIZATION_ALLOCATION_06]=14
        # §4.7.6.9 INITIALIZATION_ALLOCATION Stage B (Session 9). Same
        # 2-state DISCOVER → absence-window envelope: _04 injects a
        # mismatched-xid OFFER (xid_offset=+1), _05 injects a stray ACK
        # (msg_type=5) — both expected to be silently discarded by the
        # DUT's SELECTING-phase pollForReply. SCXML budget: 6 s + 4 s =
        # 10 s deadline; 14 s case_timeout matches REQUEST_06 budget.
        [DHCPV4_CLIENT_INITIALIZATION_ALLOCATION_04]=14
        [DHCPV4_CLIENT_INITIALIZATION_ALLOCATION_05]=14
        # §4.7.6.9 INITIALIZATION_ALLOCATION_01 Stage C (Session 9). Full
        # post_bound_discover envelope + DUT-side [1, 10] s desync wait
        # between NAK ingest and restart DISCOVER per RFC 2131 §4.4.1.
        # Wall: 1.5 s pilot + ~150 ms DISCOVER/OFFER/REQUEST/ACK + 3 s T1
        # + RENEWING REQUEST + NAK + [1, 10] s desync + DISCOVER ≈ [6, 15] s.
        # 22 s case_timeout = ~7 s margin against 10 s desync upper bound
        # plus worker scheduling jitter at --workers 4.
        [DHCPV4_CLIENT_INITIALIZATION_ALLOCATION_01]=22
        # §4.7.6.9 INITIALIZATION_ALLOCATION_08/_09/_10 Stage D (Session 9).
        # Cross-protocol BPF (ArpAndDhcpv4) — DUT firmware emits ARP
        # Probe + Announce/DECLINE post-BOUND. Wall: 1.5 s pilot +
        # ~150 ms DISCOVER/OFFER/REQUEST/ACK + Probe (≤50 ms) + listen
        # (1500 ms for _10) + Announce/DECLINE (~50 ms) ≈ 3.2 s. 14 s
        # case_timeout matches REQUEST_06 budget.
        [DHCPV4_CLIENT_INITIALIZATION_ALLOCATION_08]=14
        [DHCPV4_CLIENT_INITIALIZATION_ALLOCATION_09]=14
        [DHCPV4_CLIENT_INITIALIZATION_ALLOCATION_10]=14
        # §4.7.6.3 ALLOCATING_07 Stage A (Session 10). Same Stage D
        # cross-protocol envelope + 5th SCXML state observing the
        # restart DISCOVER #2. Pass wall ≈ INIT_ALLOC_09 (3.2 s) +
        # ~50 ms instant-restart DISCOVER ≈ 3.3 s. 14 s case_timeout
        # leaves ~10 s margin against worker scheduling jitter.
        [DHCPV4_CLIENT_ALLOCATING_07]=14
        # §4.7.6.3 ALLOCATING_08 Stage B (Session 10). RFC 2131 §3.1
        # SHOULD: ≥10 s wait between DECLINE and DISCOVER #2. Wall:
        # ALLOCATING_07 (3.2 s) + [10, 11] s desync + jitter ≈ [13.2, 14.5] s.
        # 22 s case_timeout = ~7 s margin against 11 s upper bound +
        # jitter (matches INIT_ALLOC_01's 10 s desync budget).
        [DHCPV4_CLIENT_ALLOCATING_08]=22
        # §4.5.6.1 IPV4_AUTOCONF_INTRO_01 (Session 3, 2026-04-28).
        # Cross-protocol DHCPv4 lifecycle + post-bind ARP-Probe absence
        # window. SCXML budget: 6 s listening_for_discover + 4 s
        # listening_for_request + 4 s listening_for_no_arp_probe = 14 s
        # cumulative deadline. Typical wall: 1.5 s pilot + ~100 ms
        # DISCOVER + ~100 ms REQUEST + 4 s absence = ~6 s pass case;
        # 18 s case_timeout = 4 s margin against worker scheduling
        # jitter at --workers 4.
        [IPV4_AUTOCONF_INTRO_01]=18
        # §4.7.6.7 CONSTRUCTING_MESSAGES_05/_06 (Session 11, 2026-04-28).
        # Cross-protocol UdpAndDhcpv4 lifecycle. SCXML budget: 6 + 4 + 6
        # = 16 s; typical pass wall: 1.5 s pilot + ~100 ms DISCOVER +
        # ~100 ms REQUEST + 400 ms relay before OpTriggerSendUdp +
        # ~50 ms egress ≈ 2.2 s. 18 s case_timeout = ~2 s margin against
        # worker scheduling jitter at --workers 4 plus pcap settle.
        [DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_05]=18
        [DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_06]=18
        # §4.7.6.7 CONSTRUCTING_MESSAGES_12/_13 (Session 12, 2026-04-29).
        # Exponential-backoff retransmission cluster. CM_12 fast-envelope
        # (cap=3200 ms): pass at DISCOVER 6 ≈ 6.2 s + 1.5 s pilot ≈
        # 7.7 s; 14 s case_timeout = 6 s margin. CM_13 spec defaults
        # (4 s/8 s intervals): pass at DISCOVER 3 ≈ 12 s + 1.5 s pilot
        # ≈ 13.5 s; 22 s case_timeout = ~8 s margin (matches INIT_ALLOC
        # _01's 22 s budget for similarly long timing cases).
        [DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_12]=14
        [DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_13]=22
        # §4.7.6.5 USAGE_01 Topology 2 multi-iface lifecycle:
        # 1.5 s pilot wait + DISCOVER#1 ~immediate + s2 entry observer
        # fires emitStartDhcpClient(iface_index=1) (no pilot wait) +
        # DISCOVER#2 ~immediate. SCXML: s1=6 s deadline + s2=6 s
        # deadline. Pass envelope ≈ 1.5+0.1+0.1 = 1.7 s wall but the
        # DUT's secondary `Dhcpv4Client::start()` thread must spin up
        # an AF_PACKET socket on veth-dut2-W, which adds variable
        # vsomeip-base-state cost on the worker. 14 s case_timeout
        # gives ~12 s margin against worst-case spin-up.
        [DHCPV4_CLIENT_USAGE_01]=14
        # §4.6 UDP cases: 1.5 s pilot UT-bind wait + 0.2 s probe + 0.2 s
        # gap + UT request + 5 s SCXML deadline = ~7 s typical envelope.
        # Default 7 s is tight under --workers 4 scheduler jitter; 10 s
        # gives ~3 s margin without bloating overall wall time. Applied
        # to every new §4.6 case (+ IPV4_HEADER_05) since they share the
        # UT-driven envelope.
        [UDP_INTRODUCTION_01]=10
        [UDP_INTRODUCTION_02]=10
        [UDP_INTRODUCTION_03]=10
        [UDP_FIELDS_01]=10
        [UDP_FIELDS_02]=10
        [UDP_FIELDS_03]=10
        [UDP_FIELDS_04]=15
        [UDP_FIELDS_05]=15
        [UDP_FIELDS_06]=10
        [UDP_FIELDS_07]=10
        [UDP_FIELDS_08]=10
        [UDP_FIELDS_09]=10
        [UDP_FIELDS_10]=10
        # §4.6.5.4 UDP_FIELDS_12 max-length: 1.5 s pilot wait + ~50 ms
        # 45-fragment burst + 500 ms reassembly settle + UT round-trip
        # + 5 s SCXML deadline ≈ 7.5 s envelope. 12 s = ~4 s margin.
        [UDP_FIELDS_12]=12
        [UDP_FIELDS_13]=10
        [UDP_FIELDS_14]=10
        [UDP_FIELDS_15]=10
        [UDP_FIELDS_16]=10
        [UDP_USER_INTERFACE_01]=10
        [UDP_USER_INTERFACE_02]=10
        [UDP_USER_INTERFACE_03]=10
        [UDP_USER_INTERFACE_04]=10
        [UDP_USER_INTERFACE_05]=10
        [UDP_USER_INTERFACE_06]=10
        [UDP_USER_INTERFACE_07]=10
        [UDP_USER_INTERFACE_08]=10
        [UDP_INVALID_ADDRESSES_01]=10
        [UDP_INVALID_ADDRESSES_02]=10
        # §5.1.5.4 SOMEIPSRV_SD_BEHAVIOR cluster — SD timing observation.
        # _01: 3+1+2 = 6 s SCXML budget + ~2 s tc8-dut boot wait ≈ 8 s.
        # _02: 4+3+3 = 10 s SCXML + boot ≈ 12 s.
        # _03: 5.5+4 = 9.5 s SCXML + scheduler-driven Find emit at +4.5 s
        #      runs in parallel with phase 1; total ≈ 11 s.
        # _04: 3+4 = 7 s SCXML + +2.5 s scheduled Find ≈ 9 s.
        [SOMEIPSRV_SD_BEHAVIOR_01]=12
        [SOMEIPSRV_SD_BEHAVIOR_02]=14
        [SOMEIPSRV_SD_BEHAVIOR_03]=14
        [SOMEIPSRV_SD_BEHAVIOR_04]=12
        # §5.1.6 SOMEIP_ETS_037 stimulus chains FindServiceBoot (~2.5 s)
        # + TCP hold open (~1.5 s) + resetInterface UDP (~50 ms) + 2 s
        # post-reset TCP_INFO observation window ≈ 6.1 s. SCXML phase 3
        # adds 200 ms after phase 2 fires on the buffered Method
        # Response. 12 s case_timeout keeps a 6 s margin for worker
        # contention and pcap-buffered replay.
        [SOMEIP_ETS_037]=12
        # §5.1.6 SOMEIP_ETS_086/_087 stimulus chains FindServiceBoot
        # (~2.5 s) + SubscribeEventgroupBoot (~2.5 s) ≈ 5 s before
        # SCXML start. Negative service_id flip keeps SCXML in phase 1
        # for the full 6 s deadline; positive lands within ~250 ms via
        # the buffered cyclic OfferService + DUT's 250 ms TestEventUINT8
        # broadcast. 12 s case_timeout covers the NEG envelope (5+6+1)
        # and gives the smoke wait_budget ((12+3)*5*0.2 = 15 s) room
        # to read the verdict line before kill.
        [SOMEIP_ETS_086]=12
        [SOMEIP_ETS_087]=12
        # §5.1.6 SOMEIP_ETS_121 mirrors _087 envelope — same stimulus
        # (FindServiceBoot + SubscribeEventgroupBoot eg 0x05) and 3-state
        # SCXML 6+6+4 = 16 s. 12 s case_timeout suffices because Phase 1
        # closes within ~250 ms on the buffered cyclic OfferService.
        [SOMEIP_ETS_121]=12
        # §5.1.6 SOMEIP_ETS_123 stimulus chain ≈ 5 s (FindServiceBoot +
        # 2.5 s gap before raw Subscribe emit) + 2-state SCXML 6+5 = 11 s.
        # 17 s envelope keeps a 1 s margin so phase 2 deadline (the pass-
        # by-silence path) drains cleanly.
        [SOMEIP_ETS_123]=17
        # §5.1.6 SOMEIP_ETS_124 mirrors _123 envelope (same stimulus
        # chain + 2-state SCXML 6+5 = 11 s).
        [SOMEIP_ETS_124]=17
        # §5.1.6 SOMEIP_ETS_125 mirrors _123 envelope.
        [SOMEIP_ETS_125]=17
        # §5.1.6 SOMEIP_ETS_127 stimulus chain ≈ 2.5 s (10 emits at 100 ms
        # cadence after 1.5 s initial wait); 1-state SCXML 8 s deadline.
        # 14 s envelope keeps a 3 s margin so the unicast OfferService has
        # time to land in pcap before phase 1 closes.
        [SOMEIP_ETS_127]=14
        # §5.1.6 SOMEIP_ETS_128 stimulus chain ≈ 3.5 s (burst A 1.5+0.9 s +
        # burst B 0.9 s); 2-state SCXML 6+6 = 12 s. 18 s envelope.
        [SOMEIP_ETS_128]=18
        # §5.1.6 SOMEIP_ETS_130 stimulus chain ≈ 1.5 s; 1-state SCXML 6 s.
        # Default 7 s envelope is borderline; 12 s keeps margin.
        [SOMEIP_ETS_130]=12
        # §5.1.6 SOMEIP_ETS_134 mirrors _123 envelope (Subscribe-axis with
        # SOME/IP Length + OptionsLen both cut; 2-state SCXML 6+5 = 11 s).
        [SOMEIP_ETS_134]=17
        # §5.1.6 SOMEIP_ETS_135 mirrors _134 envelope (OptionsLen lies smaller).
        [SOMEIP_ETS_135]=17
        # §5.1.6 SOMEIP_ETS_136 mirrors _134 envelope (option-body Length 4 vs 9).
        [SOMEIP_ETS_136]=17
        # §5.1.6 SOMEIP_ETS_137 mirrors _134 envelope (2 misaligned options).
        [SOMEIP_ETS_137]=17
        # §5.1.6 SOMEIP_ETS_138 mirrors _134 envelope (OptionsLen 40 oversized).
        [SOMEIP_ETS_138]=17
        # §5.1.6 SOMEIP_ETS_139 mirrors _134 envelope (OptionsLen 2 too short).
        [SOMEIP_ETS_139]=17
        # §5.1.6 SOMEIP_ETS_140 mirrors _134 envelope (non-existing eg-id 0x00FE).
        [SOMEIP_ETS_140]=17
        # §5.1.6 SOMEIP_ETS_141 mirrors _134 envelope (non-existing instance 0x0099).
        [SOMEIP_ETS_141]=17
        # §5.1.6 SOMEIP_ETS_142 mirrors _134 envelope (non-existing major 0x09).
        [SOMEIP_ETS_142]=17
        # §5.1.6 SOMEIP_ETS_143 mirrors _134 envelope (non-existing service 0x9999).
        [SOMEIP_ETS_143]=17
        # §5.1.6 SOMEIP_ETS_144 mirrors _134 envelope (Endpoint reserved bytes set).
        [SOMEIP_ETS_144]=17
        # §5.1.6 SOMEIP_ETS_153 mirrors _134 envelope (SOME/IP Length lies smaller).
        [SOMEIP_ETS_153]=17
        # §5.1.6 SOMEIP_ETS_154 mirrors _134 envelope (invalid IPv4 in EndpointOption).
        [SOMEIP_ETS_154]=17
        # §5.1.6 SOMEIP_ETS_162/_163 mirror _154 envelope (Subscribe with
        # unallowed Endpoint IPv4 — DUT-self / 111.111.111.111 variants).
        [SOMEIP_ETS_162]=17
        [SOMEIP_ETS_163]=17
        # §5.1.6 SOMEIP_ETS_109/_110/_111/_112/_113/_119 mirror _134 envelope
        # (Subscribe wire-shape mutations: port=0 / IP=32.0.0.0 / Length-cut /
        # IPv4Option Length=0 / OptionsLen=0 / wrong l4proto).
        [SOMEIP_ETS_109]=17
        [SOMEIP_ETS_110]=17
        [SOMEIP_ETS_111]=17
        [SOMEIP_ETS_112]=17
        [SOMEIP_ETS_113]=17
        [SOMEIP_ETS_119]=17
        # §5.1.6 SOMEIP_ETS_115/_116/_174/_178 mirror _134 envelope (Subscribe
        # wire-shape mutations: #Opt1 overcount / unknown option type 0x77 ×2 /
        # wrong SOME/IP Method ID).
        [SOMEIP_ETS_115]=17
        [SOMEIP_ETS_116]=17
        [SOMEIP_ETS_174]=17
        [SOMEIP_ETS_178]=17
        # §5.1.6 SOMEIP_ETS_171 unicast FindService — single-state SCXML
        # (phase 1 6 s + ~3.6 s stimulus = 10 s envelope, take 13 s margin).
        [SOMEIP_ETS_171]=13
        # §5.1.6 SOMEIP_ETS_176 trailing payload (counted + uncounted) —
        # 3-state SCXML 6+6+6 = 18 s + ~4.5 s stimulus = 23 s envelope.
        [SOMEIP_ETS_176]=27
        # §5.1.6 SOMEIP_ETS_177 trailing payload (uncounted) — 2-state SCXML
        # 6+6 = 12 s + ~3 s stimulus = 15 s envelope.
        [SOMEIP_ETS_177]=18
        # §5.1.6 SOMEIP_ETS_117 (two same-type options) mirrors _134 envelope.
        [SOMEIP_ETS_117]=17
        # §5.1.6 SOMEIP_ETS_175 (extra unreferenced Configuration Option) —
        # 2-state SCXML 6+6 + ~2.5 s stimulus = 14.5 s envelope.
        [SOMEIP_ETS_175]=18
        # §5.1.6 SOMEIP_ETS_118 (FindService with options ×10) — 1-state
        # SCXML 6 s + 1.5 s warmup + ~1 s emit cadence = 8.5 s envelope.
        [SOMEIP_ETS_118]=12
        # §5.1.6 SOMEIP_ETS_173 (unicast Subscribe ×2 with index/num overrides)
        # — 3-state SCXML 6+6+6 + ~3.5 s stimulus = 21.5 s envelope.
        [SOMEIP_ETS_173]=25
        # §5.1.6 SOMEIP_ETS_107 multi-entry Stop+Subscribe — 3-state SCXML
        # 6+6+6 + ~4 s stimulus = 22 s envelope.
        [SOMEIP_ETS_107]=25
        # §5.1.6 SOMEIP_ETS_108 Subscribe → StopSubscribe → absence — 4-state
        # SCXML 6+5+3+5 + ~5.5 s stimulus = 24.5 s envelope.
        [SOMEIP_ETS_108]=28
        # §5.1.6 SOMEIP_ETS_114 multi-entry shortened EntriesLen — mirrors _134.
        [SOMEIP_ETS_114]=17
        # §5.1.6 SOMEIP_ETS_120 Subscribe with alternate IPs — 2-state SCXML
        # 6+6 + ~2.5 s stimulus = 14.5 s envelope.
        [SOMEIP_ETS_120]=18
        # §5.1.6 SOMEIP_ETS_166 TestFieldUINT8 get/set/get — 4-state SCXML
        # 6+5+5+5 + ~3.5 s stimulus = 24.5 s envelope.
        [SOMEIP_ETS_166]=27
        # §5.1.6 SOMEIP_ETS_106 ClientServiceSubscribe — 2-state SCXML
        # 6+12 + ~5 s stimulus = 23 s envelope.
        [SOMEIP_ETS_106]=27
        # §5.1.6 SOMEIP_ETS_164 SuspendInterface 4-state SCXML 6+5+5+10 = 26 s
        # + ~10 s stimulus = 36 s envelope.
        [SOMEIP_ETS_164]=40
        # §5.1.6 SOMEIP_ETS_167/_168 4-state SCXML 6+5+5+5 = 21 s + ~3.5 s
        # stimulus = 24.5 s envelope.
        [SOMEIP_ETS_167]=27
        [SOMEIP_ETS_168]=27
        # §5.1.6 SOMEIP_ETS_103/_104/_105 GetLastValueOfEvent* — 2-state SCXML
        # 6+8 + ~5 s stimulus = 19 s envelope.
        [SOMEIP_ETS_103]=22
        [SOMEIP_ETS_104]=22
        [SOMEIP_ETS_105]=22
        # §5.1.6 SOMEIP_ETS_155 stimulus 5.5 s + 3-state SCXML 6+6+6 = 18 s
        # → 25 s envelope keeps ~1 s margin.
        [SOMEIP_ETS_155]=25
        # §5.1.6 SOMEIP_ETS_146 stimulus 7 s (FindServiceBoot 2.5 + 4 RPCs
        # paced ~3.5 s + 3 s post-reset wait) + 4-state SCXML 6+5+5+8 = 24 s
        # → 32 s envelope keeps ~1 s margin.
        [SOMEIP_ETS_146]=32
        # §5.1.6 SOMEIP_ETS_147 mirrors _086 (Subscribe eg 0x02 + observe
        # MSB-set notification). 3-state SCXML 6+6+4 = 16 s; 22 s envelope.
        [SOMEIP_ETS_147]=22
        # §5.1.6 SOMEIP_ETS_148/_149/_151 mirror _147 (eg 0x02 lift).
        [SOMEIP_ETS_148]=22
        [SOMEIP_ETS_149]=22
        [SOMEIP_ETS_151]=22
        # §5.1.6 SOMEIP_ETS_150 mirrors _147 but on eg 0x06.
        [SOMEIP_ETS_150]=22
        # §5.1.6 SOMEIP_ETS_152 SD session_id wrap. Background-thread
        # burst (kickStimulus returns at once) drives ~480 acks/sec; the
        # 65,535 wrap reaches in ~140 s wall. SCXML phase 1 6 s + phase 2
        # 180 s = 186 s; 200 s envelope = 14 s margin for stimulus warm-up
        # and pcap drain. wait_budget cap raised below from 500 to 1100
        # iters (220 s wall) so the smoke poll loop covers the envelope.
        [SOMEIP_ETS_152]=200
        # §5.1.6 SOMEIP_ETS_088 stimulus chains FindServiceBoot (~2.5 s)
        # + multi-entry SubscribeEventgroup (~500 ms) ≈ 3 s. SCXML
        # phases 6+4+4+4 = 18 s; 22 s envelope keeps a 1 s margin for
        # contention.
        [SOMEIP_ETS_088]=22
        # §5.1.6 SOMEIP_ETS_092 stimulus chain ≈ 5 s; SCXML 6+4 = 10 s.
        # 17 s envelope.
        [SOMEIP_ETS_092]=17
        # §5.1.6 SOMEIP_ETS_095 stimulus chain ≈ 5 s; SCXML
        # phases 6+3+4+2 = 15 s. 22 s envelope keeps a 2 s margin
        # for the post-ttl absence-window pcap drain.
        [SOMEIP_ETS_095]=22
        # §5.1.6 SOMEIP_ETS_100 stimulus chain ≈ 3 s; SCXML 4-phase
        # 6+5+3+4 = 18 s envelope spans Server warm-up + first
        # FindService observation + Repetition-Phase burst absorption
        # + Main-Phase absence window. 24 s case_timeout keeps a 3 s
        # margin for pcap drain after the Main-Phase absence window
        # closes.
        [SOMEIP_ETS_100]=24
        # §5.1.6 SOMEIP_ETS_101 mirrors _100 (4-phase 6+5+3+4 = 18 s)
        # plus a StopOfferService stimulus emit. 24 s envelope keeps the
        # same 3 s margin.
        [SOMEIP_ETS_101]=24
        # §5.1.6 SOMEIP_ETS_098 SCXML 6+5 = 11 s + ~3 s stimulus +
        # OfferService emit. 16 s envelope keeps a 2 s margin.
        [SOMEIP_ETS_098]=16
        # §5.1.6 SOMEIP_ETS_099 SCXML 6+5 = 11 s + ~3 s stimulus. 16 s
        # envelope keeps a 2 s margin (default 7 s would silently kill
        # the harness mid-Phase 2).
        [SOMEIP_ETS_099]=16
        # §5.1.6 SOMEIP_ETS_096 stimulus chain ≈ 5 s (FindServiceBoot
        # + Subscribe-with-TCP-option emit); SCXML 6+5 = 11 s. 17 s
        # envelope keeps a 1 s margin.
        [SOMEIP_ETS_096]=17
        # §5.1.6 SOMEIP_ETS_091 stimulus chain ≈ 3 s (FindServiceBoot
        # only — pure-observation case); SCXML 6+6 = 12 s. 17 s
        # envelope keeps a 2 s margin for the second cyclic
        # OfferService to land inside phase 2's deadline.
        [SOMEIP_ETS_091]=17
        # §5.1.6 SOMEIP_ETS_097 stimulus chain ≈ 8 s (FindServiceBoot
        # 2.5 s + 2 method requests 1 s + 0.8 s sleep + 0.5 s offer1 +
        # 1.5 s sleep + 0.2 s offer2 + 3 s accept window). SCXML
        # 6+12+6 = 24 s. 30 s envelope keeps a 2 s margin so the
        # accept-timeout path can drain into phase 3's deadline.
        [SOMEIP_ETS_097]=30
        # §5.1.6 SOMEIP_ETS_094 stimulus chain ≈ 6 s (FindServiceBoot
        # 2.5 s + SubscribeBoot 2.5 s) + SCXML 6+6+4+5+1.5+4 = 26.5 s
        # worst case. 35 s envelope keeps margin for the second cyclic
        # OfferService landing into phase 1 + scheduler-jitter on the
        # two FindService emits.
        [SOMEIP_ETS_094]=35
        # §5.1.6 SOMEIP_ETS_084 stimulus chain ≈ 5 s (FindServiceBoot
        # 2.5 s + 2 method requests 1 s + 0.8 s sleep + offer 0.5 s)
        # + SCXML 6+12+10 = 28 s. 32 s envelope keeps margin for the
        # scheduler-driven deactivate emit + DUT proxy stop() roundtrip.
        [SOMEIP_ETS_084]=32
        # §5.1.6 SOMEIP_ETS_081 stimulus chain ≈ 5 s (FindServiceBoot
        # 2.5 s + 2 method requests 1 s + 0.8 s sleep + offer1 0.5 s)
        # + SCXML 6+12+12 = 30 s. 35 s envelope keeps margin for the
        # scheduler-driven reboot offer + DUT TCP renewal handshake.
        [SOMEIP_ETS_081]=35
        # §5.1.6 SOMEIP_ETS_082 mirrors _081 envelope (same 3-state SCXML
        # 6+12+12 + ~5 s stimulus + scheduler-driven reboot offer).
        [SOMEIP_ETS_082]=35
        # §5.1.6 SOMEIP_ETS_093 stimulus chain ≈ 4 s (FindServiceBoot +
        # 3 scheduler-driven FindService+Subscribe pairs each ~0.4 s) +
        # SCXML 6+6+6+6 = 24 s. 30 s envelope keeps margin for the per-
        # phase Subscribe Ack drain.
        [SOMEIP_ETS_093]=30
        # §5.1.6 SOMEIP_ETS_089 stimulus chain ≈ 4 s (FindServiceBoot +
        # suspendInterface Method Request) + SCXML 6+6+8 = 20 s. 25 s
        # envelope keeps margin for the 2 s suspend duration + post-
        # resume cyclic OfferService landing in phase 3.
        [SOMEIP_ETS_089]=25
        [UDP_DATAGRAMLENGTH_01]=10
        [UDP_MESSAGEFORMAT_02]=10
        [UDP_PADDING_02]=10
        [IPV4_HEADER_05]=10
        # §5.1.5.3 SD_MESSAGE_09 — three-phase SCXML (6 + 6 + 4 = 16 s
        # SCXML upper bound) + FindService + Subscribe stimulus
        # (~3 s). Mirrors BASIC_03 wall-time profile.
        [SOMEIPSRV_SD_MESSAGE_09]=22
        # §4.8.6.11 RETRANSMISSION_TO_08/_09 — kernel TCP_INFO poll-
        # until-plateau loop with 35 s budget per case. Linux DUT
        # never reaches the spec's 2*MSL=60s plateau because the
        # kernel's TCP_RTO_MAX=120s cap exceeds it; the case
        # consistently verdicts `fail:rto_below_2_msl_did_not_plateau`
        # at the budget cap. Case envelope = 35 s budget + handshake
        # + UT round-trip + SCXML evaluate.
        [TCP_RETRANSMISSION_TO_08]=45
        [TCP_RETRANSMISSION_TO_09]=45
    )
    local case_timeout=${CASE_TIMEOUT_SEC[$case_id]:-7}

    local -a expect_args=(
        "${TC8_DUT_EXPECT[@]}"
        "${ARP_DUT_EXPECT_STATIC[@]}"
        --expect "arp.dut_iface_mac=$dut_mac"
        --expect "arp.dut_real_mac=$dut_mac"
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
    local case_overrides="${CASE_EXPECT_OVERRIDES[$case_id]:-}"
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
    case "${CASE_VSOMEIP_VARIANT[$case_id]:-}" in
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
    # second `PcapSource` on TIface-1 (veth-tester2-W) so DUT-emitted
    # DISCOVERs from DIface-1 reach the same pipeline as DIface-0's.
    # Stimulus injection still uses the primary iface (UT server
    # listens INADDR_ANY → dispatches by iface_index byte).
    if [[ "$case_id" == "DHCPV4_CLIENT_USAGE_01" ]]; then
        extra_args+=(--interface-secondary "veth-tester2-$W")
    fi

    # Order matters: harness first, then tc8-dut. SD Session ID starts
    # at 0x0001 for the very first OfferService after vsomeip SD init —
    # if tc8-dut starts first, pcap opens after that initial
    # OfferService has already been sent, and FORMAT_02
    # (session_id==0x0001) fails because the first captured frame is a
    # later repetition (0x0002+). --dut-first inverts this for negative
    # tests.
    #
    # Exec via the per-worker symlink paths so kill_worker_procs can
    # scope its pkill to this worker's processes only.
    local hp dp
    if [[ "$DUT_FIRST" == "1" ]]; then
        ip netns exec "$dut_ns" env \
            COMMONAPI_CONFIG="$CAPI_CFG" \
            VSOMEIP_CONFIGURATION="$dut_vsomeip_cfg" \
            VSOMEIP_APPLICATION_NAME=tc8-dut \
            VSOMEIP_BASE_PATH="$vsp" \
            "${dut_extra_env[@]}" \
            "$mock_dut_link" >"$dlog" 2>&1 &
        dp=$!

        sleep 1.5

        ip netns exec "$tester_ns" "$harness_link" test \
            --case "$case_id" -i "$veth_t" -t "$case_timeout" \
            "${expect_args[@]}" "${extra_args[@]}" >"$hlog" 2>&1 &
        hp=$!
    else
        ip netns exec "$tester_ns" "$harness_link" test \
            --case "$case_id" -i "$veth_t" -t "$case_timeout" \
            "${expect_args[@]}" "${extra_args[@]}" >"$hlog" 2>&1 &
        hp=$!

        sleep 0.5

        ip netns exec "$dut_ns" env \
            COMMONAPI_CONFIG="$CAPI_CFG" \
            VSOMEIP_CONFIGURATION="$dut_vsomeip_cfg" \
            VSOMEIP_APPLICATION_NAME=tc8-dut \
            VSOMEIP_BASE_PATH="$vsp" \
            "${dut_extra_env[@]}" \
            "$mock_dut_link" >"$dlog" 2>&1 &
        dp=$!
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
    kill_worker_procs "$mock_dut_link"

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
    # the ARP_39/40 toggle above; same trap-cleanup safety net via
    # netns destroy.
    if [[ $toggle_arp_ignore -eq 1 ]]; then
        ip netns exec "$tester_ns" sysctl -qw "net.ipv4.conf.$veth_t.arp_ignore=0" >/dev/null
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

    {
        echo "=========================================="
        echo "[w$W] ${case_id}"
        echo "=========================================="
        echo "---- harness output ----"
        cat "$hlog"
        echo "---- tc8-dut output (tail) ----"
        tail -20 "$dlog"
        echo "--------------------------------"
        if grep -q 'verdict  : pass' "$hlog"; then
            echo "[w$W] PASS ${case_id}"
        else
            echo "[w$W] FAIL ${case_id} did not return pass verdict"
        fi
    } | emit_block

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
    local wrong_token=$3
    local expected_reason=$4
    local start_ts=$EPOCHREALTIME
    local tester_ns="tc8-tester-$W"
    local dut_ns="tc8-dut-$W"
    local veth_t="veth-tester-$W"
    local veth_d="veth-dut-$W"
    local vsp="/tmp/tc8-vsomeip-$W/"
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

    rm -f "/tmp/tc8-vsomeip-$W"/vsomeip-* "/tmp/tc8-vsomeip-$W"/vsomeip.lck 2>/dev/null || true
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
    # for IPV4_REASSEMBLY_10/_12 lands on fail_*_echo_id (id flip)
    # before any timer-coupled outcome differs, so the toggle does not
    # change the verdict — but symmetric sysctl state across run_case
    # / run_negative_case is the project convention (see ICMPV4_TYPE_04
    # below and the cross-cutting "mirror run_case sysctl toggles"
    # commit 9b726a0). _11 carries no negative row (positive path
    # already lands on fail_timeout on Linux); the toggle is gated on
    # case-id so its absence in NEG_ROWS leaves the run_negative_case
    # branch a no-op for that id.
    local toggle_ipfrag_time=0
    case "$case_id" in
        ICMPV4_TYPE_04)
            toggle_ipfrag_time=1
            ip netns exec "$dut_ns" sysctl -qw "net.ipv4.ipfrag_time=3" >/dev/null
            ;;
        IPV4_REASSEMBLY_10|IPV4_REASSEMBLY_11|IPV4_REASSEMBLY_12)
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

    # Rebuild the expect array: keep every baseline entry whose key does
    # not match the wrong token's key, then append the wrong value. The
    # baseline combines SOME/IP and ARP tokens so this loop handles
    # negatives for either protocol without per-protocol branching.
    local -a baseline=(
        "${TC8_DUT_EXPECT[@]}"
        "${ARP_DUT_EXPECT_STATIC[@]}"
        --expect "arp.dut_iface_mac=$dut_mac"
        --expect "arp.dut_real_mac=$dut_mac"
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
    case "${NEG_CASE_VSOMEIP_VARIANT[$case_id]:-}" in
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
    local neg_case_overrides="${NEG_CASE_EXPECT_OVERRIDES[$case_id]:-}"
    if [[ -n "$neg_case_overrides" ]]; then
        for tok in $neg_case_overrides; do
            override+=(--expect "$tok")
        done
    fi

    # Mirror run_case's per-case harness watchdog override. ARP_48/49
    # negatives still walk the same stimulus wall-time as positives
    # (~5 s) because the wrong-eth_dst guard fires on UDP1 (which
    # happens regardless of the cache-expiry path). `-t 7` is too tight
    # for ARP_49.
    # No DHCPv4 negative-row entries today (S1 lands positive cases
    # only; S2 onward will add server-emul-dependent negatives).
    local -A NEG_CASE_TIMEOUT_SEC=(
        [ARP_48]=9
        [ARP_49]=11
        # §4.4.4.7 IPV4_REASSEMBLY_12 — same shape as positive
        # (1 s inter-fragment wait + Echo Reply + 5 s SCXML listen);
        # negative echo_id flip still sees the reply but lands on
        # fail_echo_id within the listen window, so the envelope
        # matches the positive ~6.5 s wall-time + margin.
        [IPV4_REASSEMBLY_12]=10
        # §5.1.5 multi-instance / multi-service NEG envelopes:
        # SD_MESSAGE_02 NEG hits phase 1 timeout (6 s) + stimulus
        # envelope (~3.5 s for two emitFindServiceBoot calls) ≈ 9.5 s.
        # RPC_14 NEG passes phase 1 (~3 s) then waits phase 2 deadline
        # (6 s); + phase 1 wall-time + stimulus ≈ 12 s. RPC_17 NEG
        # same shape with phase 2 deadline 8 s + TCP linger ≈ 14 s.
        [SOMEIPSRV_SD_MESSAGE_02]=12
        [SOMEIPSRV_RPC_14]=14
        [SOMEIPSRV_RPC_17]=18
        # §5.1.6 SOMEIP_ETS_086/_087 NEG: stimulus chain + SCXML phase 1
        # full 6 s deadline (≈11 s envelope) needs the same 12 s budget
        # as the positive path so the wait_budget covers the verdict
        # line print.
        [SOMEIP_ETS_086]=12
        [SOMEIP_ETS_087]=12
        # §5.1.6 SOMEIP_ETS_121 NEG mirrors positive envelope (12 s).
        [SOMEIP_ETS_121]=12
        # §5.1.6 SOMEIP_ETS_123 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_123]=17
        # §5.1.6 SOMEIP_ETS_124 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_124]=17
        # §5.1.6 SOMEIP_ETS_125 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_125]=17
        # §5.1.6 SOMEIP_ETS_127 NEG mirrors positive envelope (14 s).
        [SOMEIP_ETS_127]=14
        # §5.1.6 SOMEIP_ETS_128 NEG mirrors positive envelope (18 s).
        [SOMEIP_ETS_128]=18
        # §5.1.6 SOMEIP_ETS_130 NEG mirrors positive envelope (12 s).
        [SOMEIP_ETS_130]=12
        # §5.1.6 SOMEIP_ETS_134 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_134]=17
        # §5.1.6 SOMEIP_ETS_135 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_135]=17
        # §5.1.6 SOMEIP_ETS_136 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_136]=17
        # §5.1.6 SOMEIP_ETS_137 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_137]=17
        # §5.1.6 SOMEIP_ETS_138 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_138]=17
        # §5.1.6 SOMEIP_ETS_139 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_139]=17
        # §5.1.6 SOMEIP_ETS_140 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_140]=17
        # §5.1.6 SOMEIP_ETS_141 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_141]=17
        # §5.1.6 SOMEIP_ETS_142 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_142]=17
        # §5.1.6 SOMEIP_ETS_143 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_143]=17
        # §5.1.6 SOMEIP_ETS_144 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_144]=17
        # §5.1.6 SOMEIP_ETS_153 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_153]=17
        # §5.1.6 SOMEIP_ETS_154 NEG mirrors positive envelope (17 s).
        [SOMEIP_ETS_154]=17
        # §5.1.6 SOMEIP_ETS_162/_163 NEG mirror positive envelope (17 s).
        [SOMEIP_ETS_162]=17
        [SOMEIP_ETS_163]=17
        # §5.1.6 SOMEIP_ETS_109/_110/_111/_112/_113/_119 NEG mirror positive
        # envelope (17 s).
        [SOMEIP_ETS_109]=17
        [SOMEIP_ETS_110]=17
        [SOMEIP_ETS_111]=17
        [SOMEIP_ETS_112]=17
        [SOMEIP_ETS_113]=17
        [SOMEIP_ETS_119]=17
        # §5.1.6 SOMEIP_ETS_115/_116/_174/_178 NEG mirror positive envelope.
        [SOMEIP_ETS_115]=17
        [SOMEIP_ETS_116]=17
        [SOMEIP_ETS_174]=17
        [SOMEIP_ETS_178]=17
        # §5.1.6 SOMEIP_ETS_171/_176/_177 NEG mirror positive envelopes.
        [SOMEIP_ETS_171]=13
        [SOMEIP_ETS_176]=27
        [SOMEIP_ETS_177]=18
        # §5.1.6 SOMEIP_ETS_117/_118/_173/_175 NEG mirror positive envelopes.
        [SOMEIP_ETS_117]=17
        [SOMEIP_ETS_118]=12
        [SOMEIP_ETS_173]=25
        [SOMEIP_ETS_175]=18
        # §5.1.6 SOMEIP_ETS_107/_108/_114/_120 NEG mirror positive envelopes.
        [SOMEIP_ETS_107]=25
        [SOMEIP_ETS_108]=28
        [SOMEIP_ETS_114]=17
        [SOMEIP_ETS_120]=18
        # §5.1.6 SOMEIP_ETS_166 NEG mirrors positive envelope.
        [SOMEIP_ETS_166]=27
        # §5.1.6 SOMEIP_ETS_106 NEG mirrors positive envelope.
        [SOMEIP_ETS_106]=27
        # §5.1.6 SOMEIP_ETS_164 NEG mirrors positive envelope.
        [SOMEIP_ETS_164]=40
        # §5.1.6 SOMEIP_ETS_167/_168 NEG mirror positive envelopes.
        [SOMEIP_ETS_167]=27
        [SOMEIP_ETS_168]=27
        # §5.1.6 SOMEIP_ETS_103/_104/_105 NEG mirror positive envelopes.
        [SOMEIP_ETS_103]=22
        [SOMEIP_ETS_104]=22
        [SOMEIP_ETS_105]=22
        # §5.1.6 SOMEIP_ETS_155 NEG mirrors positive envelope (25 s).
        [SOMEIP_ETS_155]=25
        # §5.1.6 SOMEIP_ETS_146 NEG mirrors positive envelope (32 s).
        [SOMEIP_ETS_146]=32
        # §5.1.6 SOMEIP_ETS_147 NEG mirrors positive envelope (22 s).
        [SOMEIP_ETS_147]=22
        # §5.1.6 SOMEIP_ETS_148..151 NEG mirror positive envelope (22 s).
        [SOMEIP_ETS_148]=22
        [SOMEIP_ETS_149]=22
        [SOMEIP_ETS_150]=22
        [SOMEIP_ETS_151]=22
        # §5.1.6 SOMEIP_ETS_152 NEG: service_id flip lands phase 1
        # OfferService gate at the 6 s deadline; the long-tail positive
        # envelope (200 s) is unnecessary on the failure path because the
        # background-thread burst keeps emitting but no Subscribe Acks
        # come back. 12 s envelope = 6 s phase-1 deadline + 6 s pcap
        # drain margin matches BASIC_03 NEG shape.
        [SOMEIP_ETS_152]=12
        # §5.1.6 SOMEIP_ETS_088/_092/_095 NEG: same stimulus chain as
        # positive lands phase 1 service_id miss → 6 s phase 1 deadline
        # + stimulus ≈ 11 s; the long-tail positive envelopes (22 s for
        # _088/_095, 17 s for _092) carry forward to NEG so the smoke
        # wait_budget covers the verdict line.
        [SOMEIP_ETS_088]=22
        [SOMEIP_ETS_092]=17
        [SOMEIP_ETS_095]=22
        # §5.1.6 SOMEIP_ETS_098..101 NEG: stimulus chain + SCXML phase 1's
        # full 6 s deadline ≈ 11 s. Positive envelopes for _100/_101 are
        # 24 s (4-phase 6+5+3+4) — NEG lands on phase 1 first so doesn't
        # need that, but the lifted envelope keeps the smoke wait_budget
        # generous for verdict-line drain.
        [SOMEIP_ETS_098]=16
        [SOMEIP_ETS_099]=16
        [SOMEIP_ETS_100]=24
        [SOMEIP_ETS_101]=24
        # §5.1.6 SOMEIP_ETS_096 NEG mirrors positive (17 s) — service_id
        # flip lands on phase 1's 6 s OfferService deadline.
        [SOMEIP_ETS_096]=17
        # §5.1.6 SOMEIP_ETS_091 NEG mirrors positive (17 s) — service_id
        # flip lands on phase 1's 6 s OfferService deadline.
        [SOMEIP_ETS_091]=17
        # §5.1.6 SOMEIP_ETS_097 NEG mirrors positive (30 s) — service_id
        # flip lands on phase 1's 6 s OfferService deadline before the
        # TCP refuse/accept stimulus chain matters.
        [SOMEIP_ETS_097]=30
        # §5.1.6 SOMEIP_ETS_094 NEG mirrors positive (35 s) — service_id
        # flip lands on phase 1's 6 s OfferService deadline before the
        # multi-phase reboot-detection chain matters.
        [SOMEIP_ETS_094]=35
        # §5.1.6 SOMEIP_ETS_084 NEG mirrors positive (32 s) — service_id
        # flip lands on phase 1's 6 s OfferService deadline before the
        # client-mode subscribe/unsubscribe chain matters.
        [SOMEIP_ETS_084]=32
        # §5.1.6 SOMEIP_ETS_081 NEG mirrors positive (35 s) — service_id
        # flip lands on phase 1's 6 s OfferService deadline before the
        # client-mode TCP renewal chain matters.
        [SOMEIP_ETS_081]=35
        # §5.1.6 SOMEIP_ETS_082 NEG mirrors positive (35 s) — service_id
        # flip lands on phase 1's 6 s OfferService deadline before the
        # client-mode UDP re-subscribe chain matters.
        [SOMEIP_ETS_082]=35
        # §5.1.6 SOMEIP_ETS_093 NEG mirrors positive (30 s) — service_id
        # flip lands on phase 1's 6 s OfferService deadline before the
        # multicast/unicast Subscribe-Ack chain matters.
        [SOMEIP_ETS_093]=30
        # §5.1.6 SOMEIP_ETS_089 NEG mirrors positive (25 s) — service_id
        # flip lands on phase 1's 6 s OfferService deadline before the
        # suspendInterface stimulus matters.
        [SOMEIP_ETS_089]=25
        # §5.1.6 SOMEIP_ETS_037 NEG: same stimulus chain as positive
        # (~6.1 s) but lands on phase 1's 6 s OfferService deadline
        # instead of advancing through phase 2/3. 12 s envelope mirrors
        # the positive entry.
        [SOMEIP_ETS_037]=12
        # §4.8.6.2 — same 2-phase/single-phase SCXML envelopes as the
        # positive runs; the negative path lands on the FIRST phase's
        # timeout, but stimulus + handshake + 5 s deadline still
        # exceeds the default 7 s budget under scheduler jitter.
        [TCP_CHECKSUM_01]=12
        [TCP_CHECKSUM_02]=12
        [TCP_CHECKSUM_03]=10
        [TCP_CHECKSUM_04]=14
        # §4.8.6.3 — every UNACCEPTABLE pass-guard gates on
        # `captured.src_ip == expected.dut_iface_ip`, so the negative
        # IP flip lands on phase 1's timeout uniformly. The negative
        # path only walks phase 1's deadline + stimulus wall-time
        # (~5 s + ~2-4 s) — significantly less than the positive
        # budget which must accommodate full multi-phase walks.
        [TCP_UNACCEPTABLE_01]=10
        [TCP_UNACCEPTABLE_02]=10
        [TCP_UNACCEPTABLE_05]=10
        [TCP_UNACCEPTABLE_07]=10
        [TCP_UNACCEPTABLE_06]=10
        [TCP_UNACCEPTABLE_04]=10
        [TCP_UNACCEPTABLE_14]=12
        [TCP_UNACCEPTABLE_03]=10
        [TCP_UNACCEPTABLE_08]=12
        # §4.8.6.6 — phase-1 src_ip-conjunct unreachable on the IP
        # flip drives the negative path to phase-1's 5 s deadline +
        # ~2 s stimulus; the default 7 s is tight under jitter.
        [TCP_FLAGS_INVALID_01]=10
        [TCP_FLAGS_INVALID_02]=10
        # §4.8 TIME-WAIT cluster — negative path lands on the first
        # listening state's 5 s deadline + active-OPEN handshake +
        # kTcpUtBootWait. The 90 s positive envelopes for BASICS_11/12
        # collapse to ~10 s on the negative side because the post-
        # prelude wall-time wait is unreachable.
        [TCP_BASICS_11]=12
        [TCP_BASICS_12]=12
        [TCP_BASICS_13]=10
        [TCP_BASICS_14]=12
        [TCP_UNACCEPTABLE_11]=12
        [TCP_UNACCEPTABLE_12]=12
        [TCP_UNACCEPTABLE_13]=10
        [TCP_FLAGS_INVALID_14]=10
        [TCP_FLAGS_INVALID_12]=12
        [TCP_FLAGS_INVALID_07]=12
        [TCP_FLAGS_INVALID_08]=12
        [TCP_FLAGS_INVALID_11]=12
        [TCP_FLAGS_INVALID_10]=12
        [TCP_FLAGS_INVALID_09]=12
        [TCP_FLAGS_INVALID_13]=12
        [TCP_FLAGS_INVALID_15]=12
        # §4.8.6.6 TCP_FLAGS_INVALID_03..06 — negative path lands on
        # the first listening_(p1_)dut_syn state's 5 s deadline +
        # kTcpUtBootWait + active-OPEN stimulus. The IP flip makes
        # the SYN observation src_ip-conjunct unreachable; later
        # phases / absence windows are unreachable.
        [TCP_FLAGS_INVALID_03]=10
        [TCP_FLAGS_INVALID_04]=10
        [TCP_FLAGS_INVALID_05]=10
        [TCP_FLAGS_INVALID_06]=10
        # §4.8.6.X TCP_HEADER_01/02 — IP flip drives src_ip-conjunct
        # unreachable on the first listening state, lands on the 5 s
        # deadline. Same envelope as CHECKSUM_03 / FLAGS_INVALID_08
        # negative arm.
        [TCP_HEADER_01]=10
        [TCP_HEADER_02]=10
        [TCP_HEADER_05]=10
        [TCP_HEADER_06]=10
        [TCP_HEADER_04]=10
        [TCP_HEADER_07]=10
        [TCP_HEADER_08]=10
        [TCP_HEADER_09]=10
        [TCP_HEADER_11]=10
        [TCP_MSS_OPTIONS_11]=10
        [TCP_MSS_OPTIONS_12]=10
        [TCP_MSS_OPTIONS_02]=12
        [TCP_MSS_OPTIONS_03]=12
        [TCP_MSS_OPTIONS_01]=18
        [TCP_MSS_OPTIONS_05]=20
        [TCP_MSS_OPTIONS_10]=12
        [TCP_MSS_OPTIONS_06]=20
        [TCP_MSS_OPTIONS_09]=20
        [TCP_BASICS_17]=10
        [TCP_FLAGS_PROCESSING_11]=10
        [TCP_FLAGS_PROCESSING_06]=10
        [TCP_FLAGS_PROCESSING_08]=10
        [TCP_FLAGS_PROCESSING_07]=12
        [TCP_FLAGS_PROCESSING_09]=12
        [TCP_FLAGS_PROCESSING_05]=10
        [TCP_FLAGS_PROCESSING_02]=12
        [TCP_ACKNOWLEDGEMENT_03]=10
        [TCP_ACKNOWLEDGEMENT_02]=10
        [TCP_ACKNOWLEDGEMENT_04]=10
        [TCP_NAGLE_02]=12
        [TCP_NAGLE_03]=12
        [TCP_CONTROL_FLAGS_05]=10
        [TCP_CONTROL_FLAGS_08]=10
        [TCP_URGENT_PTR_04]=10
        [TCP_OUT_OF_ORDER_03]=10
        [TCP_FLAGS_PROCESSING_10]=10
        [TCP_OUT_OF_ORDER_01]=10
        [TCP_OUT_OF_ORDER_02]=10
        [TCP_OUT_OF_ORDER_05]=10
        [TCP_PROBING_WINDOWS_02]=10
        [TCP_PROBING_WINDOWS_03]=15
        [TCP_PROBING_WINDOWS_05]=12
        [TCP_PROBING_WINDOWS_04]=12
        [TCP_PROBING_WINDOWS_06]=12
        [TCP_RETRANSMISSION_TO_06]=8
        [TCP_RETRANSMISSION_TO_05]=8
        [TCP_RETRANSMISSION_TO_04]=8
        [TCP_RETRANSMISSION_TO_03]=8
        # §4.6 UDP NEG cases: ipv4.dut_iface_ip flip drives every guard
        # out of reach so the case lands on fail_timeout (5 s SCXML
        # deadline + 1.5 s UT-bind wait + stimulus + margin = ~7 s
        # envelope). 10 s budget mirrors the positive cases.
        [UDP_FIELDS_01]=10
        [UDP_FIELDS_02]=10
        [UDP_FIELDS_04]=15
        [UDP_FIELDS_05]=15
        [UDP_FIELDS_06]=10
        [UDP_FIELDS_07]=10
        [UDP_FIELDS_12]=12
        [UDP_FIELDS_13]=10
        [UDP_FIELDS_14]=10
        [UDP_USER_INTERFACE_01]=10
        [UDP_USER_INTERFACE_05]=10
        [UDP_USER_INTERFACE_06]=10
        [UDP_USER_INTERFACE_07]=10
        [UDP_USER_INTERFACE_08]=10
        [UDP_PADDING_02]=10
        [UDP_INTRODUCTION_03]=10
        [IPV4_HEADER_05]=10
    )
    local case_timeout=${NEG_CASE_TIMEOUT_SEC[$case_id]:-7}

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
        #   ARP_03/05: override arp.tester_ip so the stimulus injects a
        #     *wrong* sender_proto_ip; DUT's cache stays cold for the real
        #     tester_ip; DUT unicast Nack reply then triggers a real ARP
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
        # Phase 3b CLI split (`arp.dut_real_ip` / `arp.dut_real_mac` feed
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
        "IPV4_HEADER_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_within_listen_window"
        "IPV4_HEADER_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_with_expected_source_address"
        "IPV4_VERSION_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_within_listen_window"
        "IPV4_TTL_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_within_listen_window"
        # IPV4_VERSION_01 / TTL_05 share ipv4_positive_reply's fail
        # reason (same as HEADER_03's timeout string). Also override
        # dut_iface_ip to force the pass path out of reach.
        "IPV4_VERSION_01|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_with_expected_source_address"
        "IPV4_TTL_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_with_expected_source_address"
        # IPV4_CHECKSUM_05: overriding dut_iface_ip takes the pass+fail
        # branches (both gated on src_addr match) out of reach; lands on
        # fail_timeout, proving the SCXML's src_addr conjunct is
        # load-bearing.
        "IPV4_CHECKSUM_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_ipv4_packet_within_listen_window"
        # §4.3.3.2 ICMPV4_TYPE_22: override icmpv4.dut_iface_ip so the
        # SCXML's `captured.src_ip == expected.dut_iface_ip` conjunct
        # goes out of reach; the DUT still emits the Echo Reply but
        # the src_ip comparison rejects it, landing the case on
        # fail_timeout. Proves the src_ip guard is load-bearing (same
        # pattern as the IPv4 positive-reply rows above).
        "ICMPV4_TYPE_22|icmpv4.dut_iface_ip=10.99.99.99|fail:no_echo_reply_within_listen_window"
        # §4.3.3.2 ICMPV4_TYPE_18: override icmpv4.dut_iface_ip — the
        # SCXML's pass guard (type=3 AND code=2 AND src_ip match) and
        # the fail_wrong_code guard (type=3 AND code!=2 AND src_ip
        # match) both conjunct on src_ip, so both go out of reach.
        # The DUT still emits Destination Unreachable but the case
        # lands on fail_timeout.
        "ICMPV4_TYPE_18|icmpv4.dut_iface_ip=10.99.99.99|fail:no_dest_unreachable_within_listen_window"
        # §4.3.3.1 ICMPV4_ERROR_02: override icmpv4.dut_iface_ip —
        # both pass (pointer==22 + src_ip match) and fail_wrong_pointer
        # (pointer!=22 + src_ip match) guards conjunct on src_ip, so
        # both go out of reach. The DUT still emits Parameter Problem
        # but the case lands on fail_timeout. Proves the src_ip guard
        # is load-bearing. ERROR_03 / TYPE_04 are absence-shape and
        # have no load-bearing guard that a simple override moves
        # out of reach without masquerading as pass-on-timeout, so
        # they carry no negative row (shared limitation with
        # TYPE_05/10/16 and ERROR_04/05).
        "ICMPV4_ERROR_02|icmpv4.dut_iface_ip=10.99.99.99|fail:no_parameter_problem_within_listen_window"
        # §4.3.3.2 ICMPV4_TYPE_11: override icmpv4.dut_iface_ip — pass
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
        "ICMPV4_TYPE_11|icmpv4.dut_iface_ip=10.99.99.99|fail:no_timestamp_reply_within_listen_window"
        # §4.3.3.2 ICMPV4_TYPE_12: override icmpv4.echo_id — pass
        # conjuncts on `captured.echo_id == expected.echo_id`, so
        # flipping the expected value out of band drives the SCXML
        # into fail_id_mismatch (the explicit mismatch branch fires
        # before fail_seq_mismatch since the id check has higher
        # specificity). Proves the identifier-echo invariant the
        # spec asserts is load-bearing in the SCXML — not just
        # "any Timestamp Reply".
        "ICMPV4_TYPE_12|icmpv4.echo_id=0xFFFE|fail:timestamp_reply_identifier_not_echoed"
        # No row for `parameter_problem_pointer_not_option_or_pointer_byte`:
        # that fail reason fires only when the DUT's Pointer value is
        # neither 20 nor 22 — no CLI override flips Linux's pointer
        # emission off {20}, so reaching that branch requires a non-
        # conformant DUT (same class as ARP_46/47's hardcoded-constant
        # guards).
        # §4.4.4.6 IPV4_FRAGMENTS_01: flipping icmpv4.echo_id moves
        # the pass conjunct (echo_id match) out of reach so the SCXML
        # lands on fail_echo_id (the explicit mismatch branch fires
        # before fail_data_mismatch since it has higher specificity).
        # Proves the echo_id match is load-bearing in the reassembly
        # path — not just "any DUT reply".
        "IPV4_FRAGMENTS_01|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch"
        # §4.4.4.6 IPV4_FRAGMENTS_02/03/04: flipping icmpv4.echo_id
        # moves phase 2's pass conjunct out of reach — the DUT's
        # reassembled Echo Reply has the real kIcmpEchoId in its
        # header, but the SCXML compares against the wrong expected.
        # Lands on fail_echo_id with the case-specific reason string
        # (compound template's 3-way phase-2 fail split mirrors
        # FRAGMENTS_01's diagnostic granularity). Proves the phase 2
        # echo_id conjunct is load-bearing across all three
        # compound consumers.
        "IPV4_FRAGMENTS_02|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_after_id_retry"
        "IPV4_FRAGMENTS_03|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_after_src_retry"
        "IPV4_FRAGMENTS_04|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_after_protocol_retry"
        # §4.4.4.6 IPV4_FRAGMENTS_05: override ipv4.dut_iface_ip so the
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
        "IPV4_FRAGMENTS_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        # §4.4.4.7 IPV4_REASSEMBLY_04: flipping icmpv4.echo_id moves the
        # pass conjunct (echo_id match on the unordered-reassembly Echo
        # Reply) out of reach. The DUT still reassembles by offset key
        # and emits Echo Reply with the real kIcmpEchoId, but the SCXML
        # compares against the wrong expected → lands on fail_echo_id
        # with the unordered-reassembly reason string. Proves the
        # echo_id match is load-bearing on the out-of-order path —
        # complements FRAGMENTS_01's same-axis check on the in-order
        # 2-fragment path. _06/_07/_09 (pure absence) carry no negative
        # row — their SCXML guards have no flippable conjunct, see the
        # ICMPV4_TYPE_10/16 precedent.
        "IPV4_REASSEMBLY_04|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_after_unordered_reassembly"
        # §4.4.4.7 IPV4_REASSEMBLY_12: same axis as REASSEMBLY_04 —
        # flipping icmpv4.echo_id sends the pass conjunct out of reach
        # so the SCXML lands on fail_echo_id with the low-TTL reason
        # string. Proves the echo_id match is load-bearing on the
        # Low-TTL reassembly path.
        "IPV4_REASSEMBLY_12|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_after_low_ttl_reassembly"
        # §4.4.4.7 IPV4_REASSEMBLY_11 carries no negative row — the
        # case's positive path already lands on fail_timeout on Linux
        # (ipfrag_time=2 dut_ns toggle + 3 s inter-fragment wait =
        # bucket expired before frag 1, no Echo Reply). An echo_id
        # flip would land on the same fail_timeout, providing zero
        # diagnostic variance. Same precedent as _13 (overlap drop)
        # and _06/_07/_09 (pure absence): no flippable conjunct that
        # can be observed when no reply lands.
        # §4.4.4.7 IPV4_REASSEMBLY_10: flipping icmpv4.echo_id sends
        # phase_a's pass conjunct out of reach. The DUT reassembles
        # Phase A (inside ipfrag_time=2 s) and emits Echo Reply with
        # the real id=0x1234, but the SCXML compares against 0xFFFE →
        # lands on fail_phase_a_echo_id. Phase B's hypothetical reply
        # is unreachable since phase_a's terminal final state already
        # ended the case. Proves the phase_a echo_id match is load-
        # bearing on the within-timer reassembly path.
        "IPV4_REASSEMBLY_10|icmpv4.echo_id=0xFFFE|fail:echo_id_mismatch_phase_a_within_timer"
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
        "TCP_RETRANSMISSION_TO_06|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_first_syn"
        "TCP_RETRANSMISSION_TO_05|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_first_syn"
        "TCP_RETRANSMISSION_TO_04|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_first_data_segment"
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
        "UDP_PADDING_02|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_originated_udp_within_listen_window"
        # §4.6.5.6 UDP_INTRODUCTION_03: SCXML observes ICMP via the
        # icmp_observed event with `captured.src_ip == expected.dut_iface_ip`
        # filter; flipping ipv4.dut_iface_ip sends the filter out of reach
        # → fail_timeout (no_dut_icmp_port_unreachable_within_listen_window).
        "UDP_INTRODUCTION_03|ipv4.dut_iface_ip=10.99.99.99|fail:no_dut_icmp_port_unreachable_within_listen_window"
        # §4.4.4.1 IPV4_HEADER_05: per-case SCXML conjuncts on
        # `expected.dut_iface_ip` for src_ip filtering; flipping
        # icmpv4.dut_iface_ip sends every transition out of reach →
        # fail_timeout. Proves the src_ip filter is load-bearing.
        "IPV4_HEADER_05|icmpv4.dut_iface_ip=10.99.99.99|fail:no_echo_reply_for_576_byte_datagram"
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
    for (( W=0; W<WORKERS; W++ )); do
        worker_main "$W" negative &
    done
    wait
else
    distribute "${CASES[@]}"
    total=${#CASES[@]}
    for (( W=0; W<WORKERS; W++ )); do
        worker_main "$W" positive &
    done
    wait
fi

fails=()
for (( W=0; W<WORKERS; W++ )); do
    if [[ -s "$WORK_ROOT/$W/fails" ]]; then
        while IFS= read -r line; do
            fails+=("$line")
        done <"$WORK_ROOT/$W/fails"
    fi
done

junit_emit_xml
if [[ -n "$JUNIT_OUT" ]]; then
    echo "smoke-test: junit report → $JUNIT_OUT"
fi

echo "=========================================="
echo "smoke-test summary: ${total} case(s), ${#fails[@]} failure(s) across ${WORKERS} worker(s)"
if [[ ${#fails[@]} -gt 0 ]]; then
    printf '  FAIL %s\n' "${fails[@]}" >&2
    exit 1
fi
echo "smoke-test: all cases passed"
