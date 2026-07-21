#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_02_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid02SM = ::SCE::Generated::tcp_flags_invalid_02::tcp_flags_invalid_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid02SM>
    : TcpAnyBase<cases::TcpFlagsInvalid02SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_02";
    static constexpr std::string_view kDescription  =
        "TCP in LISTEN state MUST send RST in response to incoming "
        "ACK and remain in LISTEN; RST.SEQ taken from SEG.ACK "
        "(RFC 793 §3.9 p65 Event Processing)";

    // Spec Test Procedure (v3.0 p321-p340.txt:234):
    //   1. TESTER: Cause DUT to LISTEN.
    //   2. TESTER: Send a segment with SYN and ACK.
    //   3. DUT:    Send RST with SEQ == incoming SEG.ACK.
    //   4. TESTER: Verify DUT remains in LISTEN.
    //
    // Two synchronous raw-injects bracketed by a seam passive open /
    // close (driveSeamListen, listen-only, backend-agnostic):
    //   Phase 1 — SYN+ACK on (kBasicsTesterPort, kBasicsListenPort)
    //             with ack_num=kFlagsInvalid02ProbeAck. DUT MUST
    //             reply RST with seq=kFlagsInvalid02ProbeAck.
    //   Phase 2 — bare SYN on (kBasicsTesterPort+1, kBasicsListenPort).
    //             DUT MUST reply SYN+ACK on the new tester quad,
    //             directly proving "remains in LISTEN" (spec step 4).
    //
    // Both DUT replies are captured during the synchronous stimulus
    // and queued in the pcap buffer before TestRunner::start(); the
    // poll loop then drains them in arrival order. Phase 1's RST
    // matches listening_for_rst's pass guard and transitions to
    // listening_phase2_synack, where phase 2's SYN+ACK matches and
    // transitions to pass. Distinct tester source ports per phase
    // disambiguate the two pass observations.
    //
    // The phase-2 fresh-handshake probe replaces the prior version's
    // implicit-trust on Linux's tcp_v4_send_reset (which is a
    // structural argument, not a wire-level observation) with a
    // direct demonstration that the LISTEN socket still accepts new
    // SYNs after the RST emission.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const auto listen = driveSeamListen(dut, kBasicsListenPort);
        if (!listen) return;

        // Phase 1 — spec-asserted invalid segment. ack_num planted
        // with kFlagsInvalid02ProbeAck so the SCXML can verify
        // RFC 793's "RST SEQ <- ACK" rule by equality.
        ::tc8::stimulus::TcpSegmentSpec syn_ack{};
        syn_ack.src_port = kBasicsTesterPort;
        syn_ack.dst_port = kBasicsListenPort;
        syn_ack.seq_num  = kTesterInitialSeq;
        syn_ack.ack_num  = kFlagsInvalid02ProbeAck;
        syn_ack.flags    = ::tc8::stimulus::kTcpFlagSyn
                         | ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn_ack);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // Phase 2 — LISTEN-survival post-probe. Fresh tester source
        // port so the SYN+ACK landing on (kBasicsListenPort,
        // kBasicsTesterPort+1) is unambiguously a reply to this SYN
        // and not a phase-1 retransmit (Linux's tcp_v4_send_reset
        // path does not spawn a SYN-RCVD child, so no retransmits
        // are expected on phase 1's quad either, but the port split
        // hardens the discrimination).
        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = kBasicsTesterPort + 1U;
        syn.dst_port = kBasicsListenPort;
        syn.seq_num  = kTesterInitialSeq;
        syn.ack_num  = 0U;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        dut.tcpControl()->closeTcp(*listen);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid02SM, tcp_flags_invalid_02)
