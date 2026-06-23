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

#include "tcp_unacceptable_02_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable02SM = ::SCE::Generated::tcp_unacceptable_02::tcp_unacceptable_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable02SM>
    : TcpAnyBase<cases::TcpUnacceptable02SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_02";
    static constexpr std::string_view kDescription  =
        "TCP MUST NOT change state on receiving an unacceptable RST in "
        "SYN-RCVD state (RFC 793 §3.4 p33 Establishing a connection)";

    // Out-of-window RST SEQ. The DUT's receive window after sending
    // its SYN+ACK starts at ISN_t+1 and extends one window-size
    // (Linux default ~64 KB on a fresh socket, scaled by wscale).
    // ISN_t + 1 + 1 MB lands far outside any plausible window scale,
    // so Linux's `tcp_check_req` discards the RST as unacceptable.
    static constexpr std::uint32_t kOutOfWindowRstSeq =
        ::tc8::sce::tcp::kTesterInitialSeq + 1U + 0x100000U;

    // Spec Test Procedure (v3.0 p301-p320.txt:294):
    //   1. TESTER: Cause DUT to move to SYN-RCVD via passive open +
    //              tester SYN.
    //   2. TESTER: Send a RST with a SEQ outside the receive window.
    //   3. DUT:    Ignore the unacceptable RST.
    //   4. TESTER: Verify DUT remains in SYN-RCVD state.
    //
    // Two raw-injects bracketed by a seam passive open / close. The
    // SCXML's listening_absence state proves the spec assertion via
    // absence of a DUT-emitted RST during a 3 s window — Linux's
    // syn-recv SYN+ACK retransmits during the same window are
    // expected behavior (DUT actively trying to complete the
    // handshake) and are filtered out of the absence-fail guard by
    // the RST-flag conjunct. The LISTEN is established via
    // driveSeamListen (ITcpControl::listenTcp, listen-only) so the
    // case runs on whichever backend `--dut-control` selected.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // Suppress tester-kernel auto-RST so DUT's syn-recv state
        // remains live for the OTW-RST inject. Without this the
        // tester kernel emits its own RST in response to the DUT's
        // SYN+ACK, killing syn-recv before our spec-tested
        // unacceptable RST arrives — the absence-pass would still
        // observe no DUT RST, but the connection wouldn't actually
        // be in syn-recv to ignore the bad RST. Suppression makes
        // the absence-pass faithful to the spec.
        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        const auto listen = driveSeamListen(dut, kBasicsListenPort);
        if (!listen) return;

        // Probe — drive DUT from LISTEN into SYN-RCVD.
        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = ::tc8::sce::tcp::kBasicsTesterPort;
        syn.dst_port = kBasicsListenPort;
        syn.seq_num  = kTesterInitialSeq;
        syn.ack_num  = 0U;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // Out-of-window RST — DUT's tcp_check_req rejects on
        // unacceptable SEQ. No DUT response expected; absence proves
        // ignore + state preserved.
        ::tc8::stimulus::TcpSegmentSpec rst{};
        rst.src_port = ::tc8::sce::tcp::kBasicsTesterPort;
        rst.dst_port = kBasicsListenPort;
        rst.seq_num  = kOutOfWindowRstSeq;
        rst.ack_num  = 0U;
        rst.flags    = ::tc8::stimulus::kTcpFlagRst;
        emitTcpFrame(cfg, iface, cfg.dut.mac, rst,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        dut.tcpControl()->closeTcp(*listen);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable02SM, tcp_unacceptable_02)
