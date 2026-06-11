#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <thread>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/ipv4_expected.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"

#include "tcp_checksum_04_sm.h"

namespace tc8::sce::cases {

using TcpChecksum04SM = ::SCE::Generated::tcp_checksum_04::tcp_checksum_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpChecksum04SM> {
    using SM       = cases::TcpChecksum04SM;
    using State    = typename SM::PolicyType::State;
    using Event    = typename SM::PolicyType::Event;
    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    static constexpr std::string_view kCaseId       = "TCP_CHECKSUM_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.2";
    static constexpr std::string_view kDescription  =
        "TCP MUST use clock-driven selection of initial sequence "
        "numbers (RFC 1122 §4.2.2.9 p87, RFC 793 §3.3 p27).";

    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Tcp;

    // Spec Test Procedure (v3.0 p301-p320.txt:216):
    //   1. TESTER: Cause DUT-side application to issue CONNECT — UT
    //      OpOpenTcpSocket(Active) cycle 1.
    //   2. DUT:    Send SYN.
    //   3. TESTER: Send RST,ACK to take DUT to CLOSED state — handled
    //      implicitly by the tester kernel: the DUT's SYN targets a
    //      destination port with no socket bound on the tester side, so
    //      `tcp_v4_send_reset` emits RST+ACK ack=ISN_d+1 that closes
    //      cycle 1's SYN-SENT TCB. No explicit raw inject required.
    //   4. TESTER: Cause DUT-side CONNECT again — UT OpOpenTcpSocket
    //      (Active) cycle 2 on the same 4-tuple.
    //   5. DUT:    Send SYN (with a fresh, clock-driven ISN).
    //   6. TESTER: Verify SYN2.seq != SYN1.seq.
    //
    // ## Verdict shape — stimulus-driven, dispatch=no-op
    //
    // The earlier wire-driven SCXML guard ("transition on tcp_observed
    // SYN with `prior_isn != 0 ∧ seq != prior_isn`") raced
    // deterministically against TestRunner's stimulus-first lifecycle:
    // `kickStimulus` blocks until stimulus completes, populating
    // `prior_isn = SYN1.seq` BEFORE `start()` arms SCXML deadlines.
    // The pcap source buffers SYN1 during stimulus; when SCXML begins
    // consuming events post-`start`, the buffered SYN1 dispatches with
    // `prior_isn` already populated, so `seq == prior_isn` triggers
    // `fail_isn_unchanged` on the cycle-1 SYN itself.
    //
    // Mirroring RETRANSMISSION_TO_03's pattern instead: stimulus uses
    // TWO TcpFrameSnippets (private libpcap handles, drained
    // synchronously) to capture cycle-1 and cycle-2 SYNs directly,
    // populates Captured fields, and `dispatch()` is a no-op so wire
    // frames never drive transitions. SCXML uses the evaluate-pattern
    // (an immediate `<send event="evaluate" delay="0ms"/>` from
    // `<onentry>`) to verdict purely off the captured fields.
    //
    // Same-4-tuple choice (rather than disjoint port quads per cycle)
    // is deliberate: with identical (saddr, daddr, sport, dport) the
    // secret-mixing term in Linux's `secure_tcp_seq` is constant
    // across the two ISN computations, so any seq difference comes
    // from the clock term — exactly the "clock-driven" axis the spec
    // asserts (RFC 1122 §4.2.2.9). Disjoint port quads would trivially
    // differ via the secret path and fail to validate the MUST.

    static constexpr auto kCycleSettle = std::chrono::milliseconds(250);
    static constexpr auto kSnippetCaptureTimeout =
        std::chrono::milliseconds(2000);

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = static_cast<std::uint16_t>(
            kBasicsActiveLocalPort  + kTcpChecksum04LocalOffset);
        const std::uint16_t remote_port = static_cast<std::uint16_t>(
            kBasicsActiveRemotePort + kTcpChecksum04LocalOffset);

        // ------- Cycle 1 -------
        // Open snippet BEFORE the UT request fires so libpcap's kernel
        // ring is armed by the time the DUT emits SYN1.
        auto snippet1 = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);
        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/1, local_port,
            cfg.ipv4.tester_ip, remote_port);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        if (auto syn1 = snippet1.tryCapture(kSnippetCaptureTimeout)) {
            c.cycle1_isn          = syn1->seq_num;
            c.cycle1_isn_captured = true;
        }

        // Settle: tester-kernel auto-RST round-trip (Linux
        // `tcp_v4_send_reset` against an unbound destination port —
        // this IS spec step 3, the explicit RST,ACK to close cycle 1).
        std::this_thread::sleep_for(kCycleSettle);
        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1);
        std::this_thread::sleep_for(kCycleSettle);

        // ------- Cycle 2 -------
        auto snippet2 = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);
        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/3, local_port,
            cfg.ipv4.tester_ip, remote_port);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        if (auto syn2 = snippet2.tryCapture(kSnippetCaptureTimeout)) {
            c.cycle2_isn          = syn2->seq_num;
            c.cycle2_isn_captured = true;
        }

        std::this_thread::sleep_for(kCycleSettle);
        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/4, /*socket_id=*/2);
    }

    static void dispatch(Captured& /*c*/, SM& /*sm*/, const ::tc8::CapturedEvent& /*ev*/) {
        // Verdict is computed from snippet-captured ISNs populated
        // synchronously in `stimulus()` — wire frames are not consulted,
        // so frame ingress is intentionally a no-op. The SM advances
        // purely on the `<send event="evaluate" delay="0ms"/>` raise in
        // `<onentry>` of the initial state, which the SCE scheduler
        // dispatches into the next macrostep.
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_cycle1_isn:         return "fail:cycle1_syn_capture_timeout";
            case State::Fail_no_cycle2_isn:         return "fail:cycle2_syn_capture_timeout";
            case State::Fail_isn_unchanged:         return "fail:dut_reused_prior_isn_across_active_opens";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpChecksum04SM, tcp_checksum_04)
