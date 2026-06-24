#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "tc8/captured_event.h"
#include "sce_integration/dhcpv4_captured.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_config.h"
#include "stimulus/upper_tester_client.h"

namespace tc8::sce::dhcpv4 {

// §4.7 lifecycle pilot initial wait — same 1500 ms floor as the §4.5
// LL pilot (`kLLPilotInitialWait`) so vsomeip bootstrap + UT bind
// have time to complete before the OpStartDhcpClient request lands.
inline constexpr auto kDhcpv4PilotInitialWait =
    std::chrono::milliseconds(1500);

// §4.7.6.8 RENEWING/REBINDING REQUEST cluster fast-envelope lease length.
// 6 s lease → T1 = 3 s, T2 = lease * 7/8 = 5 s integer-floor (RFC 2131
// §4.4.5). The DUT's BOUND/RENEWING/REBINDING phase machine reads
// Option 51 from the ACK and arms timers from this value. Cases that
// observe RENEWING / REBINDING REQUEST shape under the SCE 14 s
// case_timeout pass `params.lease_time_seconds = kFastEnvelopeLeaseSeconds`
// to the OFFER + ACK server emul; cases that don't exercise the phase
// machine keep `kDefaultLeaseTimeSeconds = 300U` (silent BOUND idle).
inline constexpr std::uint32_t kFastEnvelopeLeaseSeconds = 6U;

// §4.7.6.3 ALLOCATING_10 / §4.7.6.8 REACQUISITION_05/_06 retransmission
// cluster lease length. 12 s lease → T1 = 6 s, T2 = 10 s, lease_end =
// 12 s. Per RFC 2131 §4.4.5 the client retransmits the DHCPREQUEST in
// RENEWING / REBINDING after half the time remaining to T2 / lease_end:
//   * RENEWING retx interval = (T2 - now) / 2 = 2 s after the first
//     emit (REQUEST_pair_interval observed by REACQUISITION_05).
//   * REBINDING retx interval = (lease_end - now) / 2 = 1 s after
//     the first emit (REACQUISITION_06).
// Why 12 s not 6 s: kFastEnvelopeLeaseSeconds gives (T2-T1)/2 = 1 s
// and (lease-T2)/2 = 0.5 s — too tight against ParamToleranceTime
// (1 s default per spec §4.7.5). Spec uses HIGH-LEASE-TIME (350 s)
// and VERY-HIGH-LEASE-TIME (1000 s) to keep these intervals above
// the 60 s RFC 2131 retx floor; the harness elides the floor in
// firmware so 12 s emulates the spec's intent under the 14-18 s
// case_timeout budget.
inline constexpr std::uint32_t kRetransmissionLeaseSeconds = 12U;

// OpStartDhcpClient envelope. A config struct (not a 16-positional-param
// signature) so a call site sets only the fields it overrides — the common
// `emitStartDhcpClient(cfg, iface, mac)` keeps the fast-envelope defaults, and
// adding a knob never re-orders an existing call. Field names match the wire
// slots. (C++17: named-field assignment, not C++20 designated init.)
struct Dhcpv4StartConfig {
    std::uint8_t  retry_count                = 1;
    std::uint16_t retry_interval_ms          = 1000;
    // §4.7.6.9 INIT_ALLOC_01 NAK->DISCOVER desync window (RFC 2131 §4.4.1).
    std::uint16_t nak_to_discover_min_ms     = 0;
    std::uint16_t nak_to_discover_max_ms     = 0;
    // §4.7.6.9 INIT_ALLOC_08/_09/_10 post-BOUND ARP Probe listen window.
    std::uint16_t arp_probe_listen_ms        = 0;
    // §4.7.6.3 ALLOCATING_08 post-DECLINE restart window (RFC 2131 §3.1).
    std::uint16_t decline_to_discover_min_ms = 0;
    std::uint16_t decline_to_discover_max_ms = 0;
    // §4.7.6.7 CM_12/_13 exponential-backoff retransmission envelope.
    std::uint16_t retx_first_ms              = 0;
    std::uint16_t retx_cap_ms                = 0;
    std::uint16_t retx_jitter_ms             = 0;
    // §4.7.6.5 USAGE_01 Topology-2 secondary client.
    std::uint8_t  iface_index                = 0;
    // False when the 1.5 s pilot wait was already paid by an earlier call.
    bool          apply_initial_wait         = true;
    // §4.5.6.1 / §4.7 Phase F fault-injection flavor byte (kDhcpFlavor*).
    std::uint8_t  flavor                     = 0;
};

// Issue an OpStartDhcpClient RPC to the tc8-dut. Default fast envelope (2 s
// OFFER wait + 2 s ACK wait + retry_count=1). Override via the config struct,
// e.g. ALLOCATING_06's retransmission (retry_count=2 + retry_interval_ms=1000).
inline void emitStartDhcpClient(const ::tc8::TestConfig& cfg,
                                 std::string_view iface,
                                 const std::array<std::uint8_t, 6>& dut_mac,
                                 const Dhcpv4StartConfig& c = {}) {
    if (c.apply_initial_wait) {
        std::this_thread::sleep_for(kDhcpv4PilotInitialWait);
    }
    const auto req = ::tc8::stimulus::buildStartDhcpClientRequest(
        /*req_id=*/1,
        /*offer_wait_ms=*/2000,
        /*ack_wait_ms=*/2000,
        c.retry_count,
        c.retry_interval_ms,
        c.nak_to_discover_min_ms,
        c.nak_to_discover_max_ms,
        c.arp_probe_listen_ms,
        c.decline_to_discover_min_ms,
        c.decline_to_discover_max_ms,
        c.retx_first_ms,
        c.retx_cap_ms,
        c.retx_jitter_ms,
        c.iface_index,
        c.flavor);
    ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        /*tester_src_port=*/::tc8::ut::kTesterSrcPort, req);
}

// §4.5.6.1 / §4.7 Phase F fault-injection variant: issue OpStartDhcpClient
// carrying the trailing `flavor` byte so tc8-dut's DHCP client runs a
// deliberately non-conformant lifecycle path. Same fast envelope as
// emitStartDhcpClient (2 s OFFER / 2 s ACK / single attempt); only the
// flavor differs. Used by the §4.5.6.1 INTRO_01_NEG case so its
// fail_dut_emitted_ll_probe branch is reached by a real firmware mutant
// (the leak) rather than a harness-composed frame.
inline void emitStartDhcpClientBuggy(const ::tc8::TestConfig& cfg,
                                     std::string_view iface,
                                     const std::array<std::uint8_t, 6>& dut_mac,
                                     std::uint8_t flavor,
                                     bool apply_initial_wait = true,
                                     std::uint16_t arp_probe_listen_ms = 0) {
    if (apply_initial_wait) {
        std::this_thread::sleep_for(kDhcpv4PilotInitialWait);
    }
    const auto req = ::tc8::stimulus::buildStartDhcpClientBuggyRequest(
        /*req_id=*/1,
        /*offer_wait_ms=*/2000,
        /*ack_wait_ms=*/2000,
        /*retry_count=*/1,
        /*retry_interval_ms=*/1000,
        flavor,
        arp_probe_listen_ms);
    ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        /*tester_src_port=*/::tc8::ut::kTesterSrcPort, req);
}

// §4.7.6.8 RENEWING REQUEST cluster trait helper. Schedules:
//   * OFFER (msg_type=2) on Listening_for_first_request entry
//   * ACK   (msg_type=5) on Listening_for_renewing_request entry
// Both replies advertise lease=kFastEnvelopeLeaseSeconds via Option 51 so
// the DUT's BOUND/RENEWING/REBINDING phase machine arms T1/T2 within the
// SCE 14 s case_timeout. Caller passes the case's SM type so the helper
// can resolve the State enum at the right specialisation.
template <typename SM>
inline void scheduleRenewingFastEnvelopeReplies(
    IStimulusScheduler& scheduler,
    std::string_view    iface,
    typename SM::CapturedType& c) {
    using State = typename SM::PolicyType::State;
    ServerEmulParams params{};
    params.lease_time_seconds = kFastEnvelopeLeaseSeconds;
    scheduleDhcpReplyOnStateEntry(
        scheduler, static_cast<int>(State::Listening_for_first_request),
        iface, c, /*message_type=*/2, params);
    scheduleDhcpReplyOnStateEntry(
        scheduler, static_cast<int>(State::Listening_for_renewing_request),
        iface, c, /*message_type=*/5, params);
}

// §4.7.6.8 REBINDING REQUEST cluster trait helper. Same OFFER + ACK
// schedule as the RENEWING variant — the divergence is purely SCXML-side:
// the REBINDING template adds `Listening_for_rebinding_request` after
// `Listening_for_renewing_request` and the trait does NOT register a
// stimulus on the rebinding state, so the DUT's RENEWING REQUEST goes
// unanswered and T2 fires naturally.
template <typename SM>
inline void scheduleRebindingFastEnvelopeReplies(
    IStimulusScheduler& scheduler,
    std::string_view    iface,
    typename SM::CapturedType& c) {
    scheduleRenewingFastEnvelopeReplies<SM>(scheduler, iface, c);
}

// §4.7.6.3 ALLOCATING_09 cluster trait helper. Layered on top of the
// RENEWING fast envelope: OFFER + ACK on the first two listening
// states (DUT BOUND), then DHCPNAK (msg_type=6) on
// Listening_for_second_discover entry — fired when the DUT's RENEWING
// REQUEST arrives, so the NAK is the response that drives the DUT
// runBoundPhaseMachine back to INIT per RFC 2131 §3.1. NAK omits
// Option 51 (no lease) by leaving `lease_time_seconds` at its
// `ServerEmulParams` default (0); the builder skips the option when
// lease_time_seconds == 0 (RFC 2131 §4.3.2: NAK MUST NOT carry lease).
template <typename SM>
inline void scheduleRenewingNakSchedule(
    IStimulusScheduler& scheduler,
    std::string_view    iface,
    typename SM::CapturedType& c) {
    using State = typename SM::PolicyType::State;
    scheduleRenewingFastEnvelopeReplies<SM>(scheduler, iface, c);
    ServerEmulParams nak_params{};
    nak_params.lease_time_seconds = 0U;  // explicit: NAK does not carry Option 51
    scheduleDhcpReplyOnStateEntry(
        scheduler, static_cast<int>(State::Listening_for_second_discover),
        iface, c, /*message_type=*/6, nak_params);
}

// §4.7.6.3 ALLOCATING_10 / §4.7.6.8 REACQUISITION_05/_06 retx cluster
// trait helper. Same OFFER + ACK schedule as the RENEWING fast
// envelope but with `lease_time_seconds = kRetransmissionLeaseSeconds`
// (= 12 s). The DUT phase machine arms T1=6s/T2=10s/lease_end=12s and
// retransmits in-phase per RFC 2131 §4.4.5 (interval = half remaining
// time, no 60 s floor); harness templates observe two RENEWING /
// REBINDING REQUESTs without scheduling any reply on the second-
// listening states.
template <typename SM>
inline void scheduleRetxLeaseEnvelopeReplies(
    IStimulusScheduler& scheduler,
    std::string_view    iface,
    typename SM::CapturedType& c) {
    using State = typename SM::PolicyType::State;
    ServerEmulParams params{};
    params.lease_time_seconds = kRetransmissionLeaseSeconds;
    scheduleDhcpReplyOnStateEntry(
        scheduler, static_cast<int>(State::Listening_for_first_request),
        iface, c, /*message_type=*/2, params);
    scheduleDhcpReplyOnStateEntry(
        scheduler, static_cast<int>(State::Listening_for_renewing_request),
        iface, c, /*message_type=*/5, params);
}

// §4.7 DHCPv4 passive-observation pilot. Phase A scope (this session):
// every consumer (PROTOCOL_01/02, SUMMARY_04, future
// CONSTRUCTING_MESSAGES_01/03) reuses the §4.5
// `linklocal::emitStartLLAutoconfFast` stimulus — that path emits
// exactly one DHCPDISCOVER on `OpStartLLAutoconf` receipt, which is
// what the spec body's "DUT: Sends DHCPDISCOVER Message" precondition
// asks for. No new stimulus surface lives in this header until S2
// adds the tester-side OFFER/ACK server emulation for the
// success-path cluster.
//
// Dispatch helper: select the Dhcpv4Frame variant from a captured
// event, mirror its fields into `c`, and raise the shared
// `Dhcp_observed` external event on the SM. Cases that need to
// scope verdicts to DUT-emitted DISCOVER specifically gate on
// `captured.chaddr_matches_dut_mac(expected.dut_iface_mac)` plus
// `captured.is_dhcp_discover()` in their SCXML pass-guards;
// non-matching frames advance the SM but never satisfy the guard.
//
// Inter-frame timing surface (auto-managed `prev_observed_ts_us`):
// snapshots `c.observed_ts_us` into `c.prev_observed_ts_us` only
// when the SM's current state advances after `step()` — same
// contract as `udp_pilot_common.h::dispatchUdpFrame`. Future §4.7
// retransmission-timing cases (CONSTRUCTING_MESSAGES_12/_13) will
// read `c.frame_delta_us()` from SCXML guards.
template <typename SM>
inline void dispatchDhcpv4Frame(typename SM::CapturedType& c, SM& sm,
                                 const ::tc8::CapturedEvent& ev) {
    const auto* f = std::get_if<::tc8::Dhcpv4Frame>(&ev);
    if (f == nullptr) return;
    ::tc8::fillDhcpv4CapturedFromFrame(c, *f);
    // §4.7.6.8 REACQUISITION_03 / _04 timing surface: snapshot the
    // most-recent BOOTREPLY ACK arrival ts BEFORE raising the SM
    // transition so timing predicates fired on subsequent frames see
    // the ACK landmark. State-3 ACKs (in the dhcpv4_renewing_request_
    // field template) leave the SM intact (cond gates on
    // `is_dhcp_request`) and so wouldn't update prev_observed_ts_us
    // via the state-advance bookkeeping below — this snapshot covers
    // them.
    if (c.op == 2U && c.message_type == 5U) {
        c.last_ack_observed_ts_us = c.observed_ts_us;
    }
    // §4.7.6.9 INIT_ALLOC_01 timing surface: snapshot the most-recent
    // BOOTREPLY NAK (msg_type=6) arrival ts so the DISCOVER #2 guard
    // can assert the RFC 2131 §4.4.1 SHOULD random wait window via
    // `nak_to_discover_within_us`. Same pre-raise placement as the
    // ACK snapshot above (NAK handling in the BOUND phase machine
    // similarly consumes the frame without advancing the SM through
    // a wire-derived event).
    if (c.op == 2U && c.message_type == 6U) {
        c.last_nak_observed_ts_us = c.observed_ts_us;
    }
    // §4.7.6.3 ALLOCATING_08 timing surface: snapshot the most-recent
    // BOOTREQUEST DECLINE (msg_type=4) arrival ts. DECLINE is
    // op=BOOTREQUEST (the DUT is the originator) — distinct from the
    // ACK/NAK BOOTREPLY guards above. Pre-raise placement keeps the
    // landmark live for any post-DECLINE state's cond.
    if (c.op == 1U && c.message_type == 4U) {
        c.last_decline_observed_ts_us = c.observed_ts_us;
    }
    const auto state_before = sm.getCurrentState();
    sm.raiseExternal(SM::PolicyType::Event::Dhcp_observed);
    sm.step();
    const auto state_after = sm.getCurrentState();
    if (state_after != state_before) {
        c.prev_observed_ts_us = c.observed_ts_us;
    }
}

}  // namespace tc8::sce::dhcpv4
