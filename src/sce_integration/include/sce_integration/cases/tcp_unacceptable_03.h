#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_03_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable03SM = ::SCE::Generated::tcp_unacceptable_03::tcp_unacceptable_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable03SM>
    : TcpAnyBase<cases::TcpUnacceptable03SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamListen /
    // closeTcp), so it is not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_03";
    static constexpr std::string_view kDescription  =
        "TCP MUST send a RST after receiving an unacceptable ACK in "
        "SYN-RCVD state (RFC 793 §3.4 p35 Establishing a Connection)";

    // Case shape:
    //   a passive open plus a tester SYN parks the DUT in SYN-RCVD, the
    //   tester then injects a segment whose ACK number cannot be
    //   accepted, and the DUT's RST is the observable.
    //
    // The "unacceptable ACK" requires the tester to know ISN_d (the
    // DUT's chosen initial sequence number, randomised per
    // connection by Linux's secure ISN generator). The stimulus awaits
    // the DUT-emitted SYN+ACK on the case's own capture to extract
    // ISN_d, then the tester injects an ACK with
    // ack_num = ISN_d + LARGE_OFFSET — which acknowledges a byte
    // the DUT has not sent — and DUT responds RST per RFC 793
    // RFC 793 §3.4 p35.
    //
    // The capture is marked BEFORE the upstream SYN inject, so a
    // SYN+ACK that arrives while the inject is still being emitted
    // counts.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // Suppress tester-kernel auto-RST: when our raw-injected SYN
        // elicits the DUT's SYN+ACK, the tester kernel sees a SYN+ACK
        // landing on (tester_ip, 49152) where no socket is bound and
        // would otherwise emit RST microseconds after, killing DUT's
        // syn-recv state before the bad-ACK inject can fire. The
        // iptables OUTPUT drop takes the auto-RST off the wire.
        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        // LISTEN via driveSeamListen (ITcpControl::listenTcp, listen-only) so
        // the case runs on whichever backend `--dut-control` selected; the
        // SYN-RCVD drive and bad-ACK inject stay tester-side.
        const auto listen = driveSeamListen(ctx.dut, kBasicsListenPort);
        if (!listen) return;

        // The wait below matches the DUT-emitted SYN+ACK on the tester's
        // raw-inject source port — the spec-asserted SYN+ACK whose seq_num
        // is the freshly-randomised ISN_d.
        const ::tc8::sce::ObservationCursor armed = ctx.observer.mark();

        // Probe — drive DUT from LISTEN into SYN-RCVD.
        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = kBasicsTesterPort;
        syn.dst_port = kBasicsListenPort;
        syn.seq_num  = kTesterInitialSeq;
        syn.ack_num  = 0U;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, ctx.iface, cfg.dut.mac, syn);

        // Capture SYN+ACK to learn ISN_d. 500 ms covers the worst-
        // case kernel scheduling jitter; a same-host netns
        // typically responds in single-digit milliseconds.
        const auto synack = ctx.observer.awaitObservation(
            "dut_syn_ack", armed, dutSynAckTo(cfg.dut.ip, kBasicsTesterPort),
            std::chrono::milliseconds(500));
        if (synack.has_value()) {
            // Unacceptable ACK = DUT's ISN_d + LARGE_OFFSET. ISN_d
            // is the SEQ field of the DUT's SYN+ACK; the next byte
            // DUT will ever send is ISN_d + 1 (the SYN consumed
            // one), so any ack_num far above ISN_d + 1 acknowledges
            // bytes never sent.
            ::tc8::stimulus::TcpSegmentSpec bad_ack{};
            bad_ack.src_port = kBasicsTesterPort;
            bad_ack.dst_port = kBasicsListenPort;
            bad_ack.seq_num  = kTesterInitialSeq + 1U;
            bad_ack.ack_num  = segmentOf(synack->view()).seq_num + kUnacceptableAckOffset;
            bad_ack.flags    = ::tc8::stimulus::kTcpFlagAck;
            emitTcpFrame(cfg, ctx.iface, cfg.dut.mac, bad_ack,
                         /*initial_wait=*/std::chrono::milliseconds(0));
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }

        ctx.dut.tcpControl()->closeTcp(*listen);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable03SM, tcp_unacceptable_03)
