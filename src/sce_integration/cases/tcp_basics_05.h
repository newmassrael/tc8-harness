#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_basics_05_sm.h"

namespace tc8::sce::cases {

using TcpBasics05SM = ::SCE::Generated::tcp_basics_05::tcp_basics_05;

// Tester-chosen ACK literals sent in the BASICS_05 stimulus iterations.
// The DUT's RFC 793 §3.9 RST response carries SEQ ← incoming.ACK, so
// each phase's SCXML pass guard pins to the corresponding literal.
// Bytes chosen to be unambiguously distinct from 0 (BASICS_04's pass
// criterion) and from the tester's own SEQ
// (`tcp_pilot_common::kTesterInitialSeq`); the two phase literals also
// differ from each other so a stuck-at DUT bug that emits a single
// RST whose SEQ matches one phase but not the other is caught (rather
// than silently masquerading as pass on both phases under a shared
// literal).
inline constexpr std::uint32_t kTesterPilotAckPhaseSynAck = 0xC0FFEE00U;
inline constexpr std::uint32_t kTesterPilotAckPhaseAck    = 0xDEADBEEFU;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics05SM>
    : TcpAnyBase<cases::TcpBasics05SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_05";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSED state MUST send a RST whose SEQ is the incoming "
        "segment's ACK in response to an ACK-bearing non-RST segment "
        "(RFC 793 §3.9 p65 Event Processing)";

    // Spec Test Procedure (v3.0 p281-p300.txt:535), two iterations:
    //   1. TESTER: Send a TCP segment with `flag=SYN,ACK` (ACK=phase1
    //      literal) to a closed port.
    //   2. TESTER: Send a TCP segment with `flag=ACK`     (ACK=phase2
    //      literal) to the same port.
    // After each: DUT MUST reply RST with SEQ = incoming.ACK (RFC 793
    // RFC 793 §3.9 p65; `tcp_v4_send_reset` ACK-bearing branch picks
    // `rep.th.seq = th->ack_seq`).
    //
    // Stimulus walks the two iterations sequentially with a
    // `kTcpPilotPhaseGap` (200 ms) gap between segments. Distinct ACK
    // literals across phases (kTesterPilotAckPhaseSynAck vs
    // kTesterPilotAckPhaseAck) ensure each phase's pass guard pins to
    // a unique value so no shared-literal pass-through can mask a bug.
    //
    // Per-phase tester-side SEQ literals (kTesterInitialSeq + offsets)
    // are irrelevant to the spec criterion (only ACK matters) but kept
    // distinct so a buggy DUT that mirrors SEQ instead of ACK fails
    // loudly on the SEQ-num conjunct.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        // iter 1 — SYN+ACK
        emitTcpStimulus(
            cfg, iface, cfg.dut.mac,
            /*dst_port=*/kBasicsClosedPort,
            /*flags=*/static_cast<std::uint8_t>(
                ::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagAck),
            /*seq_num=*/kTesterInitialSeq,
            /*ack_num=*/cases::kTesterPilotAckPhaseSynAck);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // iter 2 — bare ACK
        emitTcpStimulus(
            cfg, iface, cfg.dut.mac,
            /*dst_port=*/kBasicsClosedPort,
            /*flags=*/::tc8::stimulus::kTcpFlagAck,
            /*seq_num=*/kTesterInitialSeq + 0x100U,
            /*ack_num=*/cases::kTesterPilotAckPhaseAck,
            /*payload=*/{},
            /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_wrong_seq_synack:      return "fail:dut_rst_seq_not_synack_ack_literal";
            case State::Fail_wrong_seq_ack:         return "fail:dut_rst_seq_not_ack_phase_ack_literal";
            case State::Fail_timeout_synack:        return "fail:no_dut_rst_after_synack";
            case State::Fail_timeout_ack:           return "fail:no_dut_rst_after_ack";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics05SM, tcp_basics_05)
