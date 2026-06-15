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

#include "tcp_unacceptable_01_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable01SM = ::SCE::Generated::tcp_unacceptable_01::tcp_unacceptable_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable01SM>
    : TcpAnyBase<cases::TcpUnacceptable01SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_01";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP MUST return to LISTEN state on receiving an acceptable RST "
        "in SYN-RCVD state (RFC 793 §3.4 p33 Establishing a connection)";

    // Tester source ports for the two probe phases. Both target the
    // same DUT listener port (kBasicsListenPort=12345), but use
    // distinct source ports so the SCXML's two listening states
    // discriminate "DUT-SYN+ACK to first probe" from "DUT-SYN+ACK to
    // second probe (post-RST)" without depending on timing alone. The
    // DUT's reply dst_port mirrors the tester's source port, so the
    // 49152 / 49153 split surfaces directly in the pass guard.
    static constexpr std::uint16_t kProbe1SrcPort =
        ::tc8::sce::tcp::kBasicsTesterPort;
    static constexpr std::uint16_t kProbe2SrcPort =
        ::tc8::sce::tcp::kBasicsTesterPort + 1U;

    // Acceptable RST: SEQ = ISN_t + 1. After the tester's first SYN
    // (SEQ = ISN_t = kTesterInitialSeq), DUT's syn-recv expects the
    // next inbound byte at ISN_t + 1. RFC 793 §3.4 p36 makes a RST
    // acceptable when its SEQ falls inside the receive window; in a
    // freshly-formed embryonic socket the window starts exactly at
    // ISN_t + 1, so the +1 offset is the textbook in-window value.
    static constexpr std::uint32_t kAcceptableRstSeq =
        ::tc8::sce::tcp::kTesterInitialSeq + 1U;

    // Spec Test Procedure (v3.0 p301-p320.txt:261):
    //   1. TESTER: Cause DUT to move to SYN-RCVD via passive open +
    //              tester SYN.
    //   2. TESTER: Send acceptable RST.
    //   3. DUT:    Do not send response (move to LISTEN).
    //   4. TESTER: Verify DUT is in LISTEN — send fresh SYN, expect
    //              new DUT SYN+ACK.
    //
    // Three raw-injects bracketed by a seam passive open / close drive
    // the DUT through SYN-RCVD → LISTEN → SYN-RCVD'. The first SYN+ACK
    // and the post-RST second SYN+ACK are the two observable edges
    // that distinguish a conformant LISTEN return from a stuck
    // syn-recv state. The LISTEN is established via driveSeamListen
    // (ITcpControl::listenTcp, listen-only — the handshake never
    // completes) so the case runs on whichever backend `--dut-control`
    // selected; the raw injects stay tester-side.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // Without RST suppression the tester kernel emits an auto-
        // RST microseconds after the DUT's SYN+ACK lands on
        // (tester_ip, 49152) — short-circuiting the spec's
        // syn-recv → LISTEN transition before our acceptable RST
        // arrives. The SCXML's two-SYN+ACK observation pattern
        // would still pass via the wire-level edges, but the spec
        // criterion (acceptable-RST-driven move-to-LISTEN) would
        // not be the actual cause. Suppression makes the test
        // faithful to the spec.
        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        const auto listen = driveSeamListen(dut, kBasicsListenPort);
        if (!listen) return;

        // Probe 1 — drive DUT from LISTEN into SYN-RCVD.
        ::tc8::stimulus::TcpSegmentSpec syn1{};
        syn1.src_port = kProbe1SrcPort;
        syn1.dst_port = kBasicsListenPort;
        syn1.seq_num  = kTesterInitialSeq;
        syn1.ack_num  = 0U;
        syn1.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn1);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // Acceptable RST — tears down the embryonic SYN-RCVD socket
        // and returns the listener to LISTEN. No ACK flag, just RST,
        // SEQ in-window. initial_wait=0 because the SOCK_RAW socket
        // warm-up has already elapsed on probe 1.
        ::tc8::stimulus::TcpSegmentSpec rst{};
        rst.src_port = kProbe1SrcPort;
        rst.dst_port = kBasicsListenPort;
        rst.seq_num  = kAcceptableRstSeq;
        rst.ack_num  = 0U;
        rst.flags    = ::tc8::stimulus::kTcpFlagRst;
        emitTcpFrame(cfg, iface, cfg.dut.mac, rst,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        // Probe 2 — fresh SYN on a different source port. Reaches
        // LISTEN if (and only if) the listener returned to LISTEN
        // after the RST. DUT's SYN+ACK is the spec-asserted edge.
        ::tc8::stimulus::TcpSegmentSpec syn2{};
        syn2.src_port = kProbe2SrcPort;
        syn2.dst_port = kBasicsListenPort;
        syn2.seq_num  = kTesterInitialSeq;
        syn2.ack_num  = 0U;
        syn2.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn2,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        dut.tcpControl()->closeTcp(*listen);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable01SM, tcp_unacceptable_01)
