#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_05_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable05SM = ::SCE::Generated::tcp_unacceptable_05::tcp_unacceptable_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable05SM>
    : TcpAnyBase<cases::TcpUnacceptable05SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_05";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in LISTEN state MUST send a RST after receiving a segment "
        "carrying an unacceptable ACK (RFC 793 §3.4 p36 Establishing a "
        "Connection)";

    static constexpr std::uint16_t kPhase1ListenPort    = 12345U;
    static constexpr std::uint16_t kPhase2ListenPort    = 12346U;

    // Spec Test Procedure (v3.0 p301-p320.txt:401), two iterations:
    //   * Phase 1 — flag set = SYN,ACK with arbitrary ACK number.
    //   * Phase 2 — flag set = ACK only with arbitrary ACK number.
    //
    // Each phase walks UT passive open → tester raw-inject → DUT RST
    // → UT close. Distinct DUT listener ports (12345 / 12346) ensure
    // phase 1 RST cannot contaminate phase 2 listen window. socket_id
    // 1 (phase 1) is closed by phase 1's UT close; phase 2 opens
    // socket_id 2 fresh.
    //
    // The "unacceptable ACK number" in LISTEN is any non-zero ACK —
    // LISTEN has sent no bytes, so any positive ACK is acknowledging
    // something never sent. kTesterInitialSeq + 1 is an arbitrary
    // non-zero literal.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // -------- Phase 1: SYN+ACK to LISTEN --------
        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/1, /*local_port=*/kPhase1ListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        ::tc8::stimulus::TcpSegmentSpec synack{};
        synack.src_port = kBasicsTesterPort;
        synack.dst_port = kPhase1ListenPort;
        synack.seq_num  = kTesterInitialSeq;
        synack.ack_num  = kTesterInitialSeq + 1U;
        synack.flags    = ::tc8::stimulus::kTcpFlagSyn
                        | ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.dut.mac, synack);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // -------- Phase 2: bare ACK to LISTEN --------
        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/3, /*local_port=*/kPhase2ListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        ::tc8::stimulus::TcpSegmentSpec ack{};
        ack.src_port = kBasicsTesterPort;
        ack.dst_port = kPhase2ListenPort;
        ack.seq_num  = kTesterInitialSeq + 0x100U;
        ack.ack_num  = kTesterInitialSeq + 1U;
        ack.flags    = ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.dut.mac, ack,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/4, /*socket_id=*/2);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                  return "pass";
            case State::Fail_timeout_phase1:   return "fail:no_dut_rst_to_listen_synack";
            case State::Fail_timeout_phase2:   return "fail:no_dut_rst_to_listen_naked_ack";
            default:                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable05SM, tcp_unacceptable_05)
