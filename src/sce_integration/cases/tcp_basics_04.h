#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_basics_04_sm.h"

namespace tc8::sce::cases {

using TcpBasics04SM = ::SCE::Generated::tcp_basics_04::tcp_basics_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics04SM>
    : TcpAnyBase<cases::TcpBasics04SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSED state MUST send a RST segment with zero SEQ "
        "number in response to an incoming segment not containing RST "
        "and ACK flags (RFC 793 §3.9 p65 Event Processing)";

    // Spec Test Procedure (v3.0 p281-p300.txt:501), three iterations:
    //   1. TESTER: Send a TCP segment with `flag=SYN`            to a closed port.
    //   2. TESTER: Send a TCP segment with `flag=FIN`            to the same port.
    //   3. TESTER: Send a TCP `Data segment` (no ACK, no RST) to the same port.
    // After each: DUT MUST reply RST with SEQ=0 (RFC 793 §3.9 p65,
    // CLOSED-state event processing for non-RST non-ACK arrivals).
    //
    // Stimulus walks the three iterations sequentially with a
    // `kTcpPilotPhaseGap` (200 ms) gap between segments. All three are
    // hand-built via `emitTcpStimulus` (raw-inject) — no Upper Tester
    // setup required since the CLOSED state is the default for an
    // un-bound port. Per-phase tester-side SEQ literals
    // (kTesterInitialSeq + offsets) keep each segment distinguishable
    // in pcap traces and pin the spec's "no ACK" by leaving ack_num=0
    // (a segment whose ACK control bit is clear has no ACK semantics
    // regardless of the ack_num field, but a non-zero literal would be
    // misleading on inspection).
    //
    // Iteration 3's payload is a small fixed buffer
    // (`kIter3DataPayload`) — the spec text "Data segment" is a TCP
    // segment carrying data with no ACK and no RST. Linux's
    // `tcp_v4_rcv` reaches the same `tcp_v4_send_reset` regardless of
    // payload presence, but a non-empty body asserts the spec literal
    // at the wire level rather than re-running iter 1's bare-flag
    // exercise under a different name.
    static constexpr std::array<std::uint8_t, 4> kIter3DataPayload = {
        0xAAU, 0xBBU, 0xCCU, 0xDDU};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        // iter 1 — SYN
        emitTcpStimulus(cfg, iface, cfg.arp.dut_real_mac,
                        /*dst_port=*/kBasicsClosedPort,
                        /*flags=*/::tc8::stimulus::kTcpFlagSyn,
                        /*seq_num=*/kTesterInitialSeq,
                        /*ack_num=*/0U);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // iter 2 — FIN (no ACK, no RST)
        emitTcpStimulus(cfg, iface, cfg.arp.dut_real_mac,
                        /*dst_port=*/kBasicsClosedPort,
                        /*flags=*/::tc8::stimulus::kTcpFlagFin,
                        /*seq_num=*/kTesterInitialSeq + 0x100U,
                        /*ack_num=*/0U,
                        /*payload=*/{},
                        /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // iter 3 — Data segment (flags=0; no ACK, no RST; non-empty payload)
        emitTcpStimulus(
            cfg, iface, cfg.arp.dut_real_mac,
            /*dst_port=*/kBasicsClosedPort,
            /*flags=*/0U,
            /*seq_num=*/kTesterInitialSeq + 0x200U,
            /*ack_num=*/0U,
            /*payload=*/std::vector<std::uint8_t>(
                kIter3DataPayload.begin(), kIter3DataPayload.end()),
            /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_wrong_seq_syn:         return "fail:dut_rst_seq_not_zero_after_syn";
            case State::Fail_wrong_seq_fin:         return "fail:dut_rst_seq_not_zero_after_fin";
            case State::Fail_wrong_seq_data:        return "fail:dut_rst_seq_not_zero_after_data";
            case State::Fail_timeout_syn:           return "fail:no_dut_rst_after_syn";
            case State::Fail_timeout_fin:           return "fail:no_dut_rst_after_fin";
            case State::Fail_timeout_data:          return "fail:no_dut_rst_after_data";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics04SM, tcp_basics_04)
