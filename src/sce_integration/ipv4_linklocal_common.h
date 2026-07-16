#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <variant>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "tc8/captured_event.h"
#include "tc8/protocol_frames/arp_frame.h"
#include "tc8/rfc3927_constants.h"
#include "tc8/upper_tester_protocol.h"

#include "sce_integration/arp_captured.h"
#include "sce_integration/test_case_traits.h"  // IStimulusScheduler
#include "sce_integration/test_config.h"
#include "stimulus/arp_builder.h"
#include "stimulus/upper_tester_client.h"

namespace tc8::sce::linklocal {

using ::tc8::sce::IStimulusScheduler;

// §4.5 IPv4 Link-Local Autoconfiguration pilot. Every §4.5 case body
// opens with the precondition pair "DUT bring up iface" → "DUT sends
// DHCPDISCOVER" → DUT begins LL probing — collapsed tc8-dut-side
// into one OpStartLLAutoconf RPC (see
// `tc8/upper_tester_protocol.h::OpStartLLAutoconf` for the wire
// shape).

// Fast timing envelope. Default knobs sum to a ~1.5 s wall window:
//   DHCP fail (200) → PROBE_WAIT (200) → 3 Probes spaced 200..300 ms
//   → ANNOUNCE_WAIT (200) → 2 Announces spaced 200 ms
// = ~200 + 200 + 600 + 200 + 200 = ~1.4 s before the second Announce.
// Cases that observe FIRST Probe broadcast (ADDRESS_SELECTION_03)
// land verdicts inside ~500 ms of stimulus emission; ANNOUNCING /
// NETWORK_PARTITIONS cases that need the Announce phase land within
// ~1.5 s.
//
// Cadence cases (ADDRESS_SELECTION_09/_10) override these to RFC
// defaults (PROBE_WAIT 1000, PROBE_MIN 1000, PROBE_MAX 2000,
// ANNOUNCE_WAIT 2000, ANNOUNCE_INTERVAL 2000) so the spec-mandated
// cadence is what the SCXML guards measure.
inline constexpr std::uint16_t kFastDhcpTimeoutMs       = 200;
inline constexpr std::uint16_t kFastProbeWaitMs         = 200;
inline constexpr std::uint16_t kFastProbeMinMs          = 200;
inline constexpr std::uint16_t kFastProbeMaxMs          = 300;
inline constexpr std::uint16_t kFastAnnounceWaitMs      = 200;
inline constexpr std::uint16_t kFastAnnounceIntervalMs  = 200;

// RFC 3927 §2.2.1 RATE_LIMIT_INTERVAL fast envelope. The spec
// default (`tc8::rfc3927::kRateLimitIntervalMs` = 60 000 ms) is too
// long for §4.5.6.2 _14's 12 s SCXML deadline; this 3 000 ms override
// shrinks the silence window so 10 conflict cycles (~3 s) + one
// full silence window (3 s) fit with comfortable margin against
// worker scheduling jitter. Cases that never reach the conflict cap
// (everything but _14/_15) pass `tc8::rfc3927::kRateLimitIntervalMs`
// unchanged — the parameter has no effect on the success path.
inline constexpr std::uint16_t kFastRateLimitMs         = 3000;

// §4.5.6.4 CONFLICT_06..09 inter-conflict gap. Spec procedure step 10
// fixes the second conflict at DEFEND_INTERVAL/2 (= 5 s) after the
// first; with always-cease (RFC 3927 §2.5 method 1) the second
// conflict is a no-op (committed_address_be_ already cleared by then),
// so the harness uses an empirical 150 ms gap instead — long enough
// for the DUT's 50 ms responder tick + worker wakeup to register the
// first conflict before the second arrives, while keeping cluster A's
// wall budget tight under the 13 s case_timeout. Not a spec constant;
// purely a harness pacing knob, hence here rather than in
// rfc3927_constants.h.
inline constexpr auto kDefenderConflictGapMs =
    std::chrono::milliseconds(150);

// RFC 3927 §2.2.1 cadence defaults. ADDRESS_SELECTION_09/_10 measure
// the cadence itself, so the tc8-dut emits Probes at the spec
// rates: PROBE_WAIT 1 s, PROBE_MIN..PROBE_MAX 1..2 s. dhcp_timeout
// stays at the fast 200 ms because the DHCP fail simulation isn't
// part of the cadence assertion.
inline constexpr std::uint16_t kRfcDhcpTimeoutMs       = 200;
inline constexpr std::uint16_t kRfcProbeWaitMs         = 1000;
inline constexpr std::uint16_t kRfcProbeMinMs          = 1000;
inline constexpr std::uint16_t kRfcProbeMaxMs          = 2000;
inline constexpr std::uint16_t kRfcAnnounceWaitMs      = 2000;
inline constexpr std::uint16_t kRfcAnnounceIntervalMs  = 2000;

// Default initial wait before kicking the LL state machine. tc8-dut
// UT socket bind lags vsomeip startup by several hundred ms on
// smoke-test workers — same value used by udp_pilot_common's
// kUdpPilotInitialWait, kept as a separate constant so future
// pilot-specific tuning is independent.
inline constexpr auto kLLPilotInitialWait =
    std::chrono::milliseconds(1500);


// Issue an OpStartLLAutoconf RPC to the tc8-dut. The RPC itself is
// fire-and-forget for the SCXML's purposes — the verdict comes from
// observing the DUT's own DHCPDISCOVER + ARP traffic. `tester_src_port`
// names the source port the UT request carries; tc8-dut's
// Confirmation reply returns to that port (default 20100).
inline void emitStartLLAutoconf(const ::tc8::TestConfig& cfg,
                                 std::string_view iface,
                                 std::uint16_t dhcp_timeout_ms,
                                 std::uint16_t probe_wait_ms,
                                 std::uint16_t probe_min_ms,
                                 std::uint16_t probe_max_ms,
                                 std::uint16_t announce_wait_ms,
                                 std::uint16_t announce_interval_ms,
                                 std::uint16_t rate_limit_interval_ms = ::tc8::rfc3927::kRateLimitIntervalMs,
                                 std::uint16_t tester_src_port = ::tc8::ut::kTesterSrcPort,
                                 const std::array<std::uint8_t, 6>& dut_mac = {},
                                 std::chrono::milliseconds initial_wait =
                                     kLLPilotInitialWait) {
    if (initial_wait.count() > 0) {
        std::this_thread::sleep_for(initial_wait);
    }
    const auto req = ::tc8::stimulus::buildStartLLAutoconfRequest(
        /*req_id=*/1,
        dhcp_timeout_ms, probe_wait_ms,
        probe_min_ms,    probe_max_ms,
        announce_wait_ms, announce_interval_ms,
        rate_limit_interval_ms);
    ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, req);
}

// Convenience wrapper: kick LL with the fast envelope. Used by every
// observation-only §4.5 case. Cadence cases call
// emitStartLLAutoconfRfcDefaults instead.
inline void emitStartLLAutoconfFast(const ::tc8::TestConfig& cfg,
                                     std::string_view iface,
                                     const std::array<std::uint8_t, 6>& dut_mac) {
    emitStartLLAutoconf(
        cfg, iface,
        kFastDhcpTimeoutMs, kFastProbeWaitMs,
        kFastProbeMinMs,    kFastProbeMaxMs,
        kFastAnnounceWaitMs, kFastAnnounceIntervalMs,
        ::tc8::rfc3927::kRateLimitIntervalMs,
        /*tester_src_port=*/::tc8::ut::kTesterSrcPort, dut_mac);
}

// Convenience wrapper: kick LL with RFC 3927 cadence defaults. Used
// by ADDRESS_SELECTION_09/_10. Wall envelope ~7 s for Probe3, ~9 s
// for first Announce. Pair with a 12 s SCXML deadline.
inline void emitStartLLAutoconfRfcDefaults(
        const ::tc8::TestConfig& cfg,
        std::string_view iface,
        const std::array<std::uint8_t, 6>& dut_mac) {
    emitStartLLAutoconf(
        cfg, iface,
        kRfcDhcpTimeoutMs, kRfcProbeWaitMs,
        kRfcProbeMinMs,    kRfcProbeMaxMs,
        kRfcAnnounceWaitMs, kRfcAnnounceIntervalMs,
        ::tc8::rfc3927::kRateLimitIntervalMs,
        /*tester_src_port=*/::tc8::ut::kTesterSrcPort, dut_mac);
}

// §4.5.6.2 _14 fast envelope: standard fast cadence + 3 s
// rate_limit_interval. Wall budget for one case: 10 conflicts ~3 s
// + 3 s silence + ~1 s harness overhead = ~7 s, comfortably under
// the 12 s SCXML deadline.
inline void emitStartLLAutoconfFastConflict(
        const ::tc8::TestConfig& cfg,
        std::string_view iface,
        const std::array<std::uint8_t, 6>& dut_mac) {
    emitStartLLAutoconf(
        cfg, iface,
        kFastDhcpTimeoutMs, kFastProbeWaitMs,
        kFastProbeMinMs,    kFastProbeMaxMs,
        kFastAnnounceWaitMs, kFastAnnounceIntervalMs,
        kFastRateLimitMs,
        /*tester_src_port=*/::tc8::ut::kTesterSrcPort, dut_mac);
}

// §4.5.6.2 fault-injection variant. Issue OpStartLLAutoconfBuggy with
// the fast envelope and the `flavor` byte that drives tc8-dut's
// per-flavor Probe-field mutation. Used by the cluster A negative
// cases (`*_neg`) so each fail_state branch in the SCXML is reached
// by a deterministic stimulus, closing the self-reference trap.
inline void emitStartLLAutoconfBuggy(
        const ::tc8::TestConfig& cfg,
        std::string_view iface,
        const std::array<std::uint8_t, 6>& dut_mac,
        std::uint8_t flavor,
        std::chrono::milliseconds initial_wait = kLLPilotInitialWait) {
    if (initial_wait.count() > 0) {
        std::this_thread::sleep_for(initial_wait);
    }
    const auto req = ::tc8::stimulus::buildStartLLAutoconfBuggyRequest(
        /*req_id=*/1,
        kFastDhcpTimeoutMs, kFastProbeWaitMs,
        kFastProbeMinMs,    kFastProbeMaxMs,
        kFastAnnounceWaitMs, kFastAnnounceIntervalMs,
        ::tc8::rfc3927::kRateLimitIntervalMs,
        flavor);
    ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        /*tester_src_port=*/::tc8::ut::kTesterSrcPort, req);
}

// §4.5.6.2 _14/_15 fault-injection variant: OpStartLLAutoconfBuggy with
// the fast-conflict envelope (rate_limit_interval = 3 s, matching the
// positive _14/_15's emitStartLLAutoconfFastConflict) plus the `flavor`
// byte that drives tc8-dut's rate-limit conflict mutation. The 3 s
// silence window fits the _14/_15 SCXML 12-15 s deadline; the 60 s
// default would overrun it.
inline void emitStartLLAutoconfBuggyConflict(
        const ::tc8::TestConfig& cfg,
        std::string_view iface,
        const std::array<std::uint8_t, 6>& dut_mac,
        std::uint8_t flavor,
        std::chrono::milliseconds initial_wait = kLLPilotInitialWait) {
    if (initial_wait.count() > 0) {
        std::this_thread::sleep_for(initial_wait);
    }
    const auto req = ::tc8::stimulus::buildStartLLAutoconfBuggyRequest(
        /*req_id=*/1,
        kFastDhcpTimeoutMs, kFastProbeWaitMs,
        kFastProbeMinMs,    kFastProbeMaxMs,
        kFastAnnounceWaitMs, kFastAnnounceIntervalMs,
        kFastRateLimitMs,
        flavor);
    ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        /*tester_src_port=*/::tc8::ut::kTesterSrcPort, req);
}

// §4.5.6.2 cadence-violation helper for IPv4_AUTOCONF_ADDRESS_SELECTION_10_NEG.
// Re-uses the standard 0x0C OpStartLLAutoconf opcode — cadence
// violation is a parameter (probe_min/max), not a code path, so
// fault-injection is unnecessary. 100 ms / 100 ms drives Probe2 ~
// 1.4 s + 100 ms after stimulus call, well under the [950 ms, 2050
// ms] tolerance window the positive _10 asserts.
inline constexpr std::uint16_t kCadenceViolationProbeMinMs = 100;
inline constexpr std::uint16_t kCadenceViolationProbeMaxMs = 100;

inline void emitStartLLAutoconfFastCadence(
        const ::tc8::TestConfig& cfg,
        std::string_view iface,
        const std::array<std::uint8_t, 6>& dut_mac) {
    emitStartLLAutoconf(
        cfg, iface,
        kFastDhcpTimeoutMs, kFastProbeWaitMs,
        kCadenceViolationProbeMinMs, kCadenceViolationProbeMaxMs,
        kFastAnnounceWaitMs, kFastAnnounceIntervalMs,
        ::tc8::rfc3927::kRateLimitIntervalMs,
        /*tester_src_port=*/::tc8::ut::kTesterSrcPort, dut_mac);
}

// Dispatch helper: ARP-only variant. Mirror of
// udp_pilot_common::dispatchUdpFrame for ARP captures. Calls
// `snapshotFired()` only when the SM advances, matching the
// inter-frame-delta convention `CapturedFrameTiming` owns — which is
// also what puts the witnessing delta on the trace for the cadence
// cases that gate on `frame_delta_us()` bounds.
template <typename SM>
inline void dispatchArpFrame(typename SM::CapturedType& c, SM& sm,
                              const ::tc8::CapturedEvent& ev) {
    const auto* f = std::get_if<::tc8::ArpFrame>(&ev);
    if (f == nullptr) return;
    ::tc8::fillArpCapturedFromFrame(c, *f);
    const auto state_before = sm.getCurrentState();
    sm.raiseExternal(SM::PolicyType::Event::Arp_observed);
    sm.step();
    const auto state_after = sm.getCurrentState();
    if (state_after != state_before) {
        c.snapshotFired();
    }
}

// §4.5.6.2 ADDRESS_SELECTION_11/_12/_13 conflict-ARP variant. The 3
// cases differ only in the conflict frame's opcode + sender_ip
// shape — DUT-side conflict-detection logic (RFC 3927 §2.2.1) and
// SCXML re-pick assertion are identical across all three.
enum class ConflictArpVariant : std::uint8_t {
    // _11: ARP Request, sender_proto_ip = DUT's tentative LL,
    // target_proto_ip = 255.255.255.255 (per spec step 8). Fires
    // RFC 3927 §2.2.1 clause (a): any ARP whose sender_proto_ip
    // equals the address being probed.
    Request = 0,
    // _12: ARP Reply (opcode 2), same sender_ip semantics. Same
    // clause (a) hit since the predicate is opcode-agnostic.
    Reply = 1,
    // _13: ARP Probe shape — opcode 1, sender_proto_ip = 0,
    // target_proto_ip = DUT's tentative LL, sender_hw != DUT MAC.
    // Fires clause (b): "any ARP Probe where target_ip is the
    // address being probed for and sender_hw is not the host's".
    Probe = 2,
};

// Build + emit a conflict ARP frame on `iface` claiming
// `dut_tentative_ll_be` against the DUT. `variant` selects the wire
// shape per RFC 3927 §2.2.1. sender_hw is `kTesterInjectedMac`
// (locally-administered, distinct from any real iface MAC) so the
// DUT's listener correctly classifies the frame as third-party.
inline int emitConflictArp(std::string_view iface,
                            std::uint32_t dut_tentative_ll_be,
                            ConflictArpVariant variant) {
    ::tc8::stimulus::ArpFrameSpec spec{};
    spec.eth_dst   = ::tc8::stimulus::kEthBroadcast;
    spec.sender_hw = ::tc8::stimulus::kTesterInjectedMac;
    switch (variant) {
        case ConflictArpVariant::Request:
            spec.opcode        = 0x0001;
            spec.sender_ip_be  = dut_tentative_ll_be;
            spec.target_hw     = ::tc8::stimulus::kEthZero;
            // Spec step 8: Destination IP = 255.255.255.255.
            spec.target_ip_be  = 0xFFFFFFFFU;
            break;
        case ConflictArpVariant::Reply:
            spec.opcode        = 0x0002;
            spec.sender_ip_be  = dut_tentative_ll_be;
            // Reply convention: target_hw populated. Use DUT MAC so
            // the frame looks like a legitimate Reply addressed at
            // the DUT — the actual conflict signal is sender_ip.
            spec.target_hw     = ::tc8::stimulus::kEthZero;
            spec.target_ip_be  = 0xFFFFFFFFU;
            break;
        case ConflictArpVariant::Probe:
            spec.opcode        = 0x0001;
            spec.sender_ip_be  = 0;
            spec.target_hw     = ::tc8::stimulus::kEthZero;
            spec.target_ip_be  = dut_tentative_ll_be;
            break;
    }
    const auto frame = ::tc8::stimulus::buildArpFrame(spec);
    return ::tc8::stimulus::sendRawEthernet(frame, iface);
}

// Dispatch wrapper that also snapshots the FIRST observed DUT
// Probe's `target_proto_ip` into
// `captured.first_probe_target_proto_ip`. Snapshot fires on the
// transition out of the wait-state, so the SCXML's re-pick guard
// (`target_proto_ip != first_probe_target_proto_ip`) has the
// reference value pinned exactly when the conflict-injection
// observer needs it. Used by §4.5.6.2 _11/_12/_13 only — other §4.5
// cases use `dispatchArpFrame` unchanged.
template <typename SM>
inline void dispatchArpFrameWithFirstProbeSnapshot(
    typename SM::CapturedType& c, SM& sm,
    const ::tc8::CapturedEvent& ev) {
    const auto* f = std::get_if<::tc8::ArpFrame>(&ev);
    if (f == nullptr) return;
    ::tc8::fillArpCapturedFromFrame(c, *f);
    const auto state_before = sm.getCurrentState();
    sm.raiseExternal(SM::PolicyType::Event::Arp_observed);
    sm.step();
    const auto state_after = sm.getCurrentState();
    if (state_after != state_before) {
        c.snapshotFired();
        // First time we leave the wait-probe state, pin the probed
        // target IP. Subsequent transitions leave the value alone so
        // the post-conflict re-pick comparison stays anchored to
        // probe1.
        if (c.first_probe_target_proto_ip == 0) {
            c.first_probe_target_proto_ip = c.target_proto_ip;
        }
    }
}

// Schedule a conflict-ARP injection to fire when SCXML lands on
// `target_state_id`. Reads `c.first_probe_target_proto_ip` at fire
// time so the conflict frame claims exactly the DUT's tentative LL
// (per TC8 spec step 7-8). The `Captured&` reference is valid for
// the runner's lifetime — `TestRunner` owns the captured context
// and the scheduler queue is drained from the same thread that
// invokes dispatch, so the read happens on the wire-emit thread
// after the transition has already populated the field.
template <typename Captured>
inline void scheduleConflictArpOnStateEntry(
    IStimulusScheduler& scheduler,
    int target_state_id,
    std::string_view iface,
    ConflictArpVariant variant,
    Captured& c) {
    std::string iface_copy(iface);
    scheduler.scheduleAfterStateEntry(
        target_state_id,
        [iface_copy, variant, &c]() {
            emitConflictArp(iface_copy,
                             c.first_probe_target_proto_ip,
                             variant);
        });
}

// §4.5.6.2 ADDRESS_SELECTION_14/_15 dispatch knobs. Packed into a
// struct so the helper signature stays at 4 args (Captured, SM, ev,
// spec) regardless of how many tunables _14/_15/future _16-derived
// cases need. SM-templated because `conflicts_complete_event` is
// the SCXML's per-case Event enum.
template <typename SM>
struct RepeatedConflictDispatchSpec {
    using Event = typename SM::PolicyType::Event;

    // Egress iface for the conflict-ARP emit. Threaded through from
    // TestRunner's 4-arg dispatch overload; wire-derived state stays
    // in Captured, runtime context is a dispatch argument.
    std::string_view iface;

    // SCXML state holding the cycle self-loop. Helper emits conflict
    // when post-step state matches AND counter < max_conflicts.
    int cycle_state_id;

    // Synthetic event raised after the `max_conflicts`'th emit so the
    // SCXML can advance cycle → silence_watch. Cycle is a self-loop
    // (no natural state change to observe) so the helper drives the
    // advance.
    Event conflicts_complete_event;

    // Wire shape of each tester-injected conflict frame.
    ConflictArpVariant variant;

    // RFC 3927 §2.2.1 cap on probing-window conflicts before the host
    // enters rate-limit mode. Hard-coded as `kMaxConflicts=10` for the
    // current cluster but stays parameterized in case a future case
    // varies it.
    std::uint32_t max_conflicts;

    // _15 only: SCXML state the post-silence-1 Probe is awaited in.
    // Helper keys the single post-silence emit on
    // `state_before == wait_repick_state_id`. Pass `-1` to disable
    // the post-silence branch (used by _14 which has no second cycle).
    int wait_repick_state_id = -1;

    // _15 only: SCXML state the post-silence emit guards on. Helper
    // emits the post-silence conflict ONLY when the SCXML's
    // wait_repick → success transition fires (state_after matches).
    // Pairs with `wait_repick_state_id`; both must be set together
    // for the post-silence branch to engage. Catches the "DUT picked
    // a stale LL" path (SCXML routes to a fail state, helper stays
    // silent rather than emitting a wasted conflict on a doomed case).
    int post_silence_success_state_id = -1;
};

// §4.5.6.2 ADDRESS_SELECTION_14/_15 dispatch helper. On every
// observed DUT-emitted ARP Probe, drives the SCXML one transition
// AND, if the post-transition state is `spec.cycle_state_id`,
// injects a conflict ARP against the just-observed
// `target_proto_ip` and bumps `c.repeated_conflicts_emitted`. After
// the `spec.max_conflicts`'th emit it raises
// `spec.conflicts_complete_event` so SCXML can advance from `cycle`
// to `silence_watch` (the cycle state self-loop never changes
// state, so a state-entry observer cannot drive this — the dispatch
// path is the only place "another probe arrived" is observable).
//
// _15 only: when a Probe arrives while SCXML was in
// `spec.wait_repick_state_id` AND the SCXML's success transition
// (state_after == `spec.post_silence_success_state_id`) fires, inject
// ONE more conflict ARP. SCXML transitions out of wait_repick on the
// `arp_observed` event alone (no synthetic event needed) so the emit
// rides alongside the natural transition rather than driving it.
// Both spec fields default to `-1` (disabled) for _14 callers.
//
// Side-effect on `c.previous_observed_probe_target_ip`: written
// AFTER the SCXML step on every observed Probe. The cycle and
// wait_repick guards compare the next probe's `target_proto_ip`
// against this value to assert the DUT picks a fresh LL each
// iteration (TC8 spec step 11 / step 58). Initial 0 lets the first
// transition listening → cycle pass unconditionally.
template <typename SM>
inline void dispatchArpFrameWithRepeatedConflictEmit(
    typename SM::CapturedType& c, SM& sm,
    const ::tc8::CapturedEvent& ev,
    const RepeatedConflictDispatchSpec<SM>& spec) {
    const auto* f = std::get_if<::tc8::ArpFrame>(&ev);
    if (f == nullptr) return;
    ::tc8::fillArpCapturedFromFrame(c, *f);
    const auto state_before = sm.getCurrentState();
    sm.raiseExternal(SM::PolicyType::Event::Arp_observed);
    sm.step();
    const auto state_after = sm.getCurrentState();
    if (state_after != state_before) {
        c.snapshotFired();
    }
    if (static_cast<int>(state_after) == spec.cycle_state_id &&
        c.is_arp_probe() &&
        c.repeated_conflicts_emitted < spec.max_conflicts) {
        emitConflictArp(spec.iface, c.target_proto_ip, spec.variant);
        c.repeated_conflicts_emitted += 1;
        if (c.repeated_conflicts_emitted == spec.max_conflicts) {
            sm.raiseExternal(spec.conflicts_complete_event);
            sm.step();
        }
    }
    // _15 post-silence emit: gated on the success-transition
    // landing (state_after == post_silence_success_state_id) so a
    // doomed case (DUT picked a stale LL → SCXML routes to a fail
    // state) leaves the wire silent.
    if (spec.wait_repick_state_id >= 0 &&
        spec.post_silence_success_state_id >= 0 &&
        static_cast<int>(state_before) == spec.wait_repick_state_id &&
        static_cast<int>(state_after) == spec.post_silence_success_state_id &&
        c.is_arp_probe()) {
        emitConflictArp(spec.iface, c.target_proto_ip, spec.variant);
    }
    // Snapshot the just-observed Probe's target for the next cycle's
    // freshness guard. Non-Probe frames leave the field unchanged so
    // the comparison stays anchored to the most recent Probe.
    if (c.is_arp_probe()) {
        c.previous_observed_probe_target_ip = c.target_proto_ip;
    }
}

// §4.5.6.2 ADDRESS_SELECTION_16: synchronous OpQueryLLAddress over
// UDP — opens a transient SOCK_DGRAM, sends the 0x0D request to
// DUT:30600, waits up to `timeout` for the Confirmation, and returns
// the committed LL address (network byte order). Returns 0 on any RPC failure (socket,
// send, recv timeout, malformed response) so the caller can fail the
// scheduled stimulus closure deterministically without raising into
// SCXML — the closure simply skips the ARP Request emit and the
// SCXML's `deadline_exceeded` path becomes the verdict.
inline std::uint32_t queryLLAddressSync(
    const ::tc8::TestConfig& cfg,
    std::uint8_t  req_id  = 1,
    std::chrono::milliseconds timeout = std::chrono::milliseconds(1000)) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return 0;
    timeval tv{};
    tv.tv_sec  = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in remote{};
    remote.sin_family      = AF_INET;
    remote.sin_addr.s_addr = cfg.ipv4.dut_iface_ip;
    remote.sin_port        = htons(::tc8::ut::kPort);

    const auto payload =
        ::tc8::stimulus::buildQueryLLAddressRequest(req_id);
    if (::sendto(fd, payload.data(), payload.size(), 0,
                 reinterpret_cast<sockaddr*>(&remote), sizeof(remote))
        != static_cast<ssize_t>(payload.size())) {
        ::close(fd);
        return 0;
    }

    std::uint8_t buf[16];
    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    const ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0,
                                  reinterpret_cast<sockaddr*>(&peer), &peer_len);
    ::close(fd);
    // Expected: <opcode|0x80> <req_id> <status=0x00> <linklocal_addr:u32 BE>.
    if (n < 7) return 0;
    if (buf[0] != static_cast<std::uint8_t>(
            ::tc8::ut::OpQueryLLAddress | ::tc8::ut::kResponseBit)) return 0;
    if (buf[1] != req_id)                        return 0;
    if (buf[2] != ::tc8::ut::kStatusOk)          return 0;
    // Bytes 3..6 are the LL address in network byte order on the wire.
    // Copy them verbatim into a uint32 — the codebase convention
    // treats `*_be` as a uint32 whose memory bytes are the NBO wire
    // bytes (so on LE the low byte holds the first wire octet).
    std::uint32_t addr_be = 0;
    std::memcpy(&addr_be, buf + 3, 4);
    return addr_be;
}

// §4.5.6.2 ADDRESS_SELECTION_16: build + emit the tester's
// claim-condition ARP Request. Spec step 9 fixes
//   sender_proto_ip = <AIFACE-0-IP-LINKLOCAL-ADDR> (= tester_ll_be),
//   target_proto_ip = <DIFACE-0-IP-LINKLOCAL-ADDR> (= committed LL),
//   sender_hw       = <MAC-ADDR1> (= kTesterInjectedMac).
// eth_dst is broadcast (RFC 826 ARP Request convention) — DUT's
// AF_PACKET responder sees the frame regardless of L2 dst, and
// broadcast keeps the helper drop-in across topologies that may
// not pre-learn the DUT's MAC. `tester_ll_be` is sourced from
// `cfg.arp.tester_linklocal_ip` so OEM-lab topologies can override
// without touching the helper.
inline int emitArpRequestForDefenderTest(
    std::string_view iface,
    std::uint32_t    target_ll_be,
    std::uint32_t    tester_ll_be) {
    ::tc8::stimulus::ArpFrameSpec spec{};
    spec.eth_dst       = ::tc8::stimulus::kEthBroadcast;
    spec.opcode        = 0x0001;
    spec.sender_hw     = ::tc8::stimulus::kTesterInjectedMac;
    spec.sender_ip_be  = tester_ll_be;
    spec.target_hw     = ::tc8::stimulus::kEthZero;
    spec.target_ip_be  = target_ll_be;
    const auto frame = ::tc8::stimulus::buildArpFrame(spec);
    return ::tc8::stimulus::sendRawEthernet(frame, iface);
}

// §4.5.6.5 LINKLOCAL_PACKETS_04 arbitrary link-local target. RFC 3927
// RFC 3927 §2.1 reserves 169.254.0.0/24 and 169.254.255.0/24 — a host claiming
// a link-local address MUST NOT pick from those ranges, so 169.254.0.1
// is by construction never a DUT-claimed address. Spec step 9 calls for
// "<ARBITRARY-IP-LINKLOCAL-ADDR>"; pinning a reserved-range value here
// avoids the 1-in-64254 chance that a randomly-picked tester arbitrary
// would collide with the DUT's randomly-picked LL on a given run while
// still satisfying the "in 169.254/16" framing of the spec.
//
// Stored in the `*_be` convention used elsewhere in this header: the
// uint32_t's bytes (low to high on a little-endian host) match the
// network-order wire bytes A9 FE 00 01.
inline constexpr std::uint32_t kArbitraryReservedLinkLocalIpBe =
    static_cast<std::uint32_t>(169U)        |
    (static_cast<std::uint32_t>(254U) << 8) |
    (static_cast<std::uint32_t>(0U)   << 16)|
    (static_cast<std::uint32_t>(1U)   << 24);

// §4.5.6.4 CONFLICT_06..10 defender-cease conflict shape. Tester
// emits an ARP packet (`opcode` = 1 Request / 2 Reply) with both
// sender_proto_ip and target_proto_ip set to the DUT's committed LL,
// claiming the address as its own. RFC 3927 §2.5 method 1
// (always-cease) requires the DUT to immediately abandon the LL on
// any such conflict; §4.5.6.4 verifies the resulting re-pick by
// observing a fresh DUT Probe whose target ≠ original LL. Spec body
// fixes sender_hw = <MAC-ADDR1> (kTesterInjectedMac); eth_dst is
// broadcast (RFC 826 Request convention; spec is silent on the
// Reply-opcode case so broadcast keeps the helper uniform).
inline int emitDefenderConflictArp(
    std::string_view iface,
    std::uint32_t    dut_committed_ll_be,
    std::uint16_t    opcode) {
    ::tc8::stimulus::ArpFrameSpec spec{};
    spec.eth_dst       = ::tc8::stimulus::kEthBroadcast;
    spec.opcode        = opcode;
    spec.sender_hw     = ::tc8::stimulus::kTesterInjectedMac;
    spec.sender_ip_be  = dut_committed_ll_be;
    spec.target_hw     = ::tc8::stimulus::kEthZero;
    spec.target_ip_be  = dut_committed_ll_be;
    const auto frame = ::tc8::stimulus::buildArpFrame(spec);
    return ::tc8::stimulus::sendRawEthernet(frame, iface);
}

// §4.5.6.2 _16 + §4.5.6.4 _11 claim-condition observer helper.
// Both cases drive the same post-claim Reply assertion: tester emits
// an ARP Request from `cfg.arp.tester_linklocal_ip` (AIFACE LL)
// targeting the DUT's committed LL, and the DUT MUST emit a broadcast
// ARP Reply (RFC 3927 §2.5). The observer registered on
// `target_state_id` (typically Listening_post_claim, entered after
// the first DUT Announce) does:
//   1. queries DUT's committed LL via OpQueryLLAddress,
//   2. snapshots the LL into `c.expected_responder_sender_ip_be` so
//      the SCXML's pass guard has the expected sender_proto_ip,
//   3. emits the AIFACE-LL ARP Request via emitArpRequestForDefender-
//      Test.
// _11 and _16 differ only in spec section + SCXML failure messaging;
// the wire stimulus is identical so both traits delegate here.
template <typename Captured>
inline void scheduleClaimConditionTesterRequest(
    IStimulusScheduler& scheduler,
    int                 target_state_id,
    const ::tc8::TestConfig& cfg,
    std::string_view    iface,
    Captured&           c) {
    const auto cfg_copy   = cfg;
    const auto iface_copy = std::string(iface);
    scheduler.scheduleAfterStateEntry(
        target_state_id,
        [cfg_copy, iface_copy, &c]() {
            const std::uint32_t committed_ll = queryLLAddressSync(cfg_copy);
            if (committed_ll == 0) return;
            c.expected_responder_sender_ip_be = committed_ll;
            emitArpRequestForDefenderTest(
                iface_copy, committed_ll,
                cfg_copy.arp.tester_linklocal_ip);
        });
}

// §4.5.6.5 LINKLOCAL_PACKETS_04 scheduled-stimulus helper. Registers
// a state-entry observer keyed on `target_state_id` (the SCXML's
// listening_post_claim, entered after the DUT's Announce 2 confirms
// the claim phase has completed). On entry the closure emits a single
// AIFACE-LL ARP Request whose target_proto_ip is `arbitrary_target_ll_be`
// (typically `kArbitraryReservedLinkLocalIpBe`), an address the DUT
// has by construction NOT claimed. RFC 3927 §2.7 MUST: the DUT must
// not answer; the SCXML's absence-of-Reply window is the verdict.
//
// Distinct from `scheduleClaimConditionTesterRequest`:
//   * No `OpQueryLLAddress` round-trip — the absence assertion does
//     not need the DUT's committed LL captured (Reply opcode is the
//     fail predicate, not its sender_ip), so the UT-query is wasted
//     work. Skipping it keeps the pre-emit gap as small as the
//     scheduler's wakeup latency.
//   * No `Captured&` parameter — the SCXML's no-Reply guard does not
//     reference any wire-derived snapshot, so the helper does not need
//     a write target. Sibling helpers carry `Captured&` because their
//     SCXMLs read `c.expected_responder_sender_ip_be`; passing it here
//     for "API symmetry" would be unused-arg noise.
//   * `tester_ll_be` is read from `cfg.arp.tester_linklocal_ip` (the
//     spec's <AIFACE-0-IP-LINKLOCAL-ADDR>).
inline void scheduleArbitraryTargetTesterRequest(
    IStimulusScheduler& scheduler,
    int                 target_state_id,
    const ::tc8::TestConfig& cfg,
    std::string_view    iface,
    std::uint32_t       arbitrary_target_ll_be) {
    const auto iface_copy   = std::string(iface);
    const auto tester_ll_be = cfg.arp.tester_linklocal_ip;
    scheduler.scheduleAfterStateEntry(
        target_state_id,
        [iface_copy, tester_ll_be, arbitrary_target_ll_be]() {
            emitArpRequestForDefenderTest(
                iface_copy, arbitrary_target_ll_be, tester_ll_be);
        });
}

// §4.5.6.4 CONFLICT_06..10 cluster A scheduled-stimulus helper.
// Registers a state-entry observer keyed on `target_state_id` (the
// SCXML's listening_post_claim, entered after the first DUT
// Announce confirms commit). On entry the closure
//   1. queries the DUT's committed LL via OpQueryLLAddress,
//   2. snapshots the LL into `c.expected_responder_sender_ip_be` so
//      the SCXML's "DUT picked a NEW LL" guard has a stable reference
//      against which to compare each subsequent Probe target,
//   3. emits the first conflict ARP (`opcode1`), and
//   4. when `opcode2 != 0`, sleeps `inter_conflict_delay` and emits a
//      second conflict (matching the spec procedure's "wait
//      DEFEND_INTERVAL/2 then send second conflict" shape — _06..09
//      pass two opcodes, _10 passes one).
//
// `inter_conflict_delay` defaults to 150 ms: the DUT responder polls
// every 50 ms, plus worker wakeup + stopArpResponder + Phase 1 entry,
// so 150 ms gives the cease branch room to register the first
// conflict before the second arrives. The second conflict is a
// no-op for an always-cease DUT (committed_address_be_ has cleared
// to 0 by then) — emitting it preserves spec-procedure fidelity for
// labs running a defend-then-cease implementation.
template <typename Captured>
inline void scheduleDefenderCeaseConflicts(
    IStimulusScheduler& scheduler,
    int                 target_state_id,
    std::string_view    iface,
    const ::tc8::TestConfig& cfg,
    Captured&           c,
    std::uint16_t       opcode1,
    std::uint16_t       opcode2 = 0,
    std::chrono::milliseconds inter_conflict_delay =
        kDefenderConflictGapMs) {
    const auto cfg_copy   = cfg;
    const auto iface_copy = std::string(iface);
    scheduler.scheduleAfterStateEntry(
        target_state_id,
        [cfg_copy, iface_copy, &c, opcode1, opcode2,
         inter_conflict_delay]() {
            const std::uint32_t committed_ll = queryLLAddressSync(cfg_copy);
            if (committed_ll == 0) return;
            c.expected_responder_sender_ip_be = committed_ll;
            emitDefenderConflictArp(iface_copy, committed_ll, opcode1);
            if (opcode2 != 0) {
                std::this_thread::sleep_for(inter_conflict_delay);
                emitDefenderConflictArp(iface_copy, committed_ll, opcode2);
            }
        });
}

}  // namespace tc8::sce::linklocal
