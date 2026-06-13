#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_01_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid01SM = ::SCE::Generated::tcp_flags_invalid_01::tcp_flags_invalid_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid01SM>
    : TcpAnyBase<cases::TcpFlagsInvalid01SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_01";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "TCP MUST ignore an incoming segment with RST flag in LISTEN "
        "state (RFC 793 §3.9 p65 Event Processing)";

    // Spec Test Procedure (v3.0 p321-p340.txt:202):
    //   1. TESTER: Cause DUT to LISTEN.
    //   2. TESTER: Send a segment with SYN and RST.
    //   3. DUT:    Send no response.
    //   4. TESTER: Verify DUT remains in LISTEN.
    //
    // Three raw-injects bracketed by a UT passive open / close. The
    // third inject (LISTEN-survival probe) and the close fire from
    // `tick()` the moment SCXML lands on `listening_phase3_synack`,
    // so they hit the wire only AFTER the absence window has elapsed:
    //   Phase 1 — bare SYN on (kBasicsTesterPort, kBasicsListenPort)
    //             drives DUT into SYN-RCVD; observed DUT SYN+ACK
    //             proves the LISTEN-baseline before the spec-tested
    //             step.
    //   Phase 2 — SYN+RST on (kBasicsTesterPort+1, kBasicsListenPort)
    //             targets the LISTEN socket with the spec-asserted
    //             invalid segment. Distinct tester source port keeps
    //             phase-1's SYN-RCVD SYN+ACK retransmits (which
    //             carry dst_port=kBasicsTesterPort) out of the
    //             phase-2 absence-fail guard's match window.
    //   Phase 3 — bare SYN on (kBasicsTesterPort+2, kBasicsListenPort),
    //             registered as a state-entry observer on
    //             `listening_phase3_synack`. DUT MUST reply SYN+ACK
    //             on the new tester quad — directly proving "remains
    //             in LISTEN" (spec step 4) on the wire.
    //
    // The state-entry phasing is required because pcap events
    // captured during synchronous `kickStimulus` are buffered until
    // TestRunner::start() arms the SCXML; if phase 3 ran inside
    // `kickStimulus`, its DUT SYN+ACK would be drained while SCXML
    // was still in `listening_absence` (whose guard does NOT match
    // dst_port=kBasicsTesterPort+2), silently consumed, and never
    // observed by `listening_phase3_synack`. Same shape as
    // §4.4.4.6 FRAGMENTS_02 — see that case's preamble for the
    // synchronous-stimulus-vs-buffered-pcap rationale in detail.
    //
    // The phase-3 fresh-handshake probe replaces the prior version's
    // implicit-trust on Linux's `goto discard` (a structural
    // argument, not a wire-level observation) with a direct
    // demonstration that the LISTEN socket still accepts new SYNs
    // after the SYN+RST drop.
    //
    // State-entry scheduling decouples phase 3's emit moment from
    // `listening_absence`'s `<send delay="3s"/>` value: the runner
    // observes the SCXML transition into `listening_phase3_synack`
    // (driven by SCXML's own `deadline_absence` timer firing inside
    // `sm_.tick()`) and fires the queued action on the same tick.
    // No magic-milliseconds wall-time constant for the trait to keep
    // in sync with the SCXML.

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // LISTEN via driveSeamListen (ITcpControl::listenTcp, listen-only) so
        // the case runs on whichever backend `--dut-control` selected; the
        // three raw injects and the deferred close stay tester/seam-side.
        const auto listen = driveSeamListen(dut, kBasicsListenPort);
        if (!listen) return;

        // Phase 1 — drive DUT from LISTEN into SYN-RCVD; the
        // SYN+ACK reply is the SCXML's first-state observation.
        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = kBasicsTesterPort;
        syn.dst_port = kBasicsListenPort;
        syn.seq_num  = kTesterInitialSeq;
        syn.ack_num  = 0U;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // Phase 2 — spec-asserted invalid segment. Distinct tester
        // source port (kBasicsTesterPort + 1) so the absence guard
        // does not see phase-1's SYN+ACK retransmits.
        ::tc8::stimulus::TcpSegmentSpec syn_rst{};
        syn_rst.src_port = kBasicsTesterPort + 1U;
        syn_rst.dst_port = kBasicsListenPort;
        syn_rst.seq_num  = kTesterInitialSeq;
        syn_rst.ack_num  = 0U;
        syn_rst.flags    = ::tc8::stimulus::kTcpFlagSyn
                         | ::tc8::stimulus::kTcpFlagRst;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn_rst,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // Phase 3 + UT close — registered on `listening_phase3_synack`
        // entry. Captures arguments by value so kickStimulus returns
        // immediately. When the action fires from tick() (the same
        // tick that processed `deadline_absence` and transitioned the
        // SM), it sends a fresh SYN on (kBasicsTesterPort + 2) and
        // then closes the LISTEN socket. If the test reaches a
        // verdict before the absence deadline (e.g. phase 1 or phase
        // 2 already failed), the SCXML never lands on
        // `listening_phase3_synack`, the observer never fires, and
        // the poll loop exits cleanly — no thread to leak, no
        // SIGKILL race, no partial-emit risk.
        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy   = cfg;
        std::array<std::uint8_t, 6> dut_mac_copy = cfg.dut.mac;
        // dut outlives the poll loop (CLI-owned), so capturing &dut for the
        // deferred close is lifetime-safe (FLAGS_PROCESSING_09 idiom).
        ::tc8::sce::IDutControl*    dut_ptr = &dut;
        const ::tc8::sce::DutSocket listen_handle = *listen;
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase3_synack),
            [iface_copy, cfg_copy, dut_mac_copy, dut_ptr, listen_handle]() {
                ::tc8::stimulus::TcpSegmentSpec syn3{};
                syn3.src_port = kBasicsTesterPort + 2U;
                syn3.dst_port = kBasicsListenPort;
                syn3.seq_num  = kTesterInitialSeq;
                syn3.ack_num  = 0U;
                syn3.flags    = ::tc8::stimulus::kTcpFlagSyn;
                emitTcpFrame(cfg_copy, iface_copy, dut_mac_copy, syn3,
                             /*initial_wait=*/std::chrono::milliseconds(0));
                dut_ptr->tcpControl()->closeTcp(listen_handle);
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                  return "pass";
            case State::Fail_timeout_first_synack:             return "fail:no_dut_synack_to_first_tester_syn";
            case State::Fail_unexpected_response_to_syn_rst:   return "fail:dut_emitted_response_after_syn_rst_in_listen";
            case State::Fail_p3_no_synack:                     return "fail:listen_socket_did_not_survive_syn_rst";
            default:                                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid01SM, tcp_flags_invalid_01)
