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

#include "tcp_unacceptable_05_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable05SM = ::SCE::Generated::tcp_unacceptable_05::tcp_unacceptable_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable05SM>
    : TcpAnyBase<cases::TcpUnacceptable05SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_05";
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
    // Each phase walks a seam passive open → tester raw-inject → DUT
    // RST → seam close. Distinct DUT listener ports (12345 / 12346)
    // ensure phase 1 RST cannot contaminate phase 2 listen window; the
    // two LISTENs use independent seam handles (no socket-id literals).
    // The LISTEN is established via driveSeamListen
    // (ITcpControl::listenTcp, listen-only) so the case runs on
    // whichever backend `--dut-control` selected.
    //
    // The "unacceptable ACK number" in LISTEN is any non-zero ACK —
    // LISTEN has sent no bytes, so any positive ACK is acknowledging
    // something never sent. kTesterInitialSeq + 1 is an arbitrary
    // non-zero literal.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // -------- Phase 1: SYN+ACK to LISTEN --------
        const auto listen1 = driveSeamListen(dut, kPhase1ListenPort);
        if (!listen1) return;

        ::tc8::stimulus::TcpSegmentSpec synack{};
        synack.src_port = kBasicsTesterPort;
        synack.dst_port = kPhase1ListenPort;
        synack.seq_num  = kTesterInitialSeq;
        synack.ack_num  = kTesterInitialSeq + 1U;
        synack.flags    = ::tc8::stimulus::kTcpFlagSyn
                        | ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.dut.mac, synack);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        dut.tcpControl()->closeTcp(*listen1);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // -------- Phase 2: bare ACK to LISTEN --------
        const auto listen2 = driveSeamListen(dut, kPhase2ListenPort);
        if (!listen2) return;

        ::tc8::stimulus::TcpSegmentSpec ack{};
        ack.src_port = kBasicsTesterPort;
        ack.dst_port = kPhase2ListenPort;
        ack.seq_num  = kTesterInitialSeq + 0x100U;
        ack.ack_num  = kTesterInitialSeq + 1U;
        ack.flags    = ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.dut.mac, ack,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        dut.tcpControl()->closeTcp(*listen2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable05SM, tcp_unacceptable_05)
