#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
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
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP MUST send a RST after receiving an unacceptable ACK in "
        "SYN-RCVD state (RFC 793 §3.4 p35 Establishing a Connection)";

    // Spec Test Procedure (v3.0 p301-p320.txt:328):
    //   1. TESTER: Cause DUT to move to SYN-RCVD via passive open +
    //              tester SYN.
    //   2. TESTER: Send a segment with an unacceptable ACK number.
    //   3. DUT:    Send a RST.
    //
    // The "unacceptable ACK" requires the tester to know ISN_d (the
    // DUT's chosen initial sequence number, randomised per
    // connection by Linux's secure ISN generator). TcpFrameSnippet
    // captures the DUT-emitted SYN+ACK via libpcap to extract
    // ISN_d, then the tester injects an ACK with
    // ack_num = ISN_d + LARGE_OFFSET — which acknowledges a byte
    // the DUT has not sent — and DUT responds RST per RFC 793
    // RFC 793 §3.4 p35.
    //
    // The pcap snippet is opened BEFORE the upstream SYN inject so
    // the kernel pcap ring has already armed when the SYN+ACK
    // arrives; otherwise scheduler jitter could let the SYN+ACK
    // land before the pcap handle accepts it.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
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

        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/1, /*local_port=*/kBasicsListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        // Snippet matches DUT-emitted SYN+ACK on the tester's
        // raw-inject source port — picks up the spec-asserted
        // SYN+ACK whose seq_num is the freshly-randomised ISN_d.
        auto snippet = TcpFrameSnippet::forDutSynAck(
            cfg, iface, kBasicsTesterPort);

        // Probe — drive DUT from LISTEN into SYN-RCVD.
        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = kBasicsTesterPort;
        syn.dst_port = kBasicsListenPort;
        syn.seq_num  = kTesterInitialSeq;
        syn.ack_num  = 0U;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn);

        // Capture SYN+ACK to learn ISN_d. 500 ms covers the worst-
        // case kernel scheduling jitter; a same-host netns
        // typically responds in single-digit milliseconds.
        const auto synack = snippet.tryCapture(
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
            bad_ack.ack_num  = synack->seq_num + kUnacceptableAckOffset;
            bad_ack.flags    = ::tc8::stimulus::kTcpFlagAck;
            emitTcpFrame(cfg, iface, cfg.dut.mac, bad_ack,
                         /*initial_wait=*/std::chrono::milliseconds(0));
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:           return "pass";
            case State::Fail_timeout:   return "fail:no_dut_rst_to_unacceptable_ack_in_syn_recv";
            default:                    return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable03SM, tcp_unacceptable_03)
