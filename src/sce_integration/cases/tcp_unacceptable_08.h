#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_08_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable08SM = ::SCE::Generated::tcp_unacceptable_08::tcp_unacceptable_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable08SM>
    : TcpAnyBase<cases::TcpUnacceptable08SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_08";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-SENT state MUST send a RST control message after "
        "receiving a segment with an unacceptable ACK number "
        "(RFC 793 §3.4 p36 Establishing a Connection)";

    // Spec Test Procedure (v3.0 p301-p320.txt:506) lists two
    // iterations (CASE 1 = SYN+ACK, CASE 2 = ACK). Linux scope —
    // only CASE 1 is exercised; CASE 2's compound shape races
    // tc8-dut's close-path connector-thread join + lingering
    // syn-sent retransmits on the same kernel socket. See SCXML
    // preamble for the deviation rationale.
    //
    // Mechanism:
    //   1. TesterAutoRstDrop suppresses tester-kernel auto-RST so
    //      DUT's syn-sent is not killed by the kernel's response
    //      to its own outbound SYN.
    //   2. UT Active OPEN — DUT enters syn-sent.
    //   3. TcpFrameSnippet captures DUT SYN to learn ISN_d.
    //   4. Raw-inject SYN+ACK with ack = ISN_d + LARGE_OFFSET.
    //   5. SCXML observes DUT-emitted RST.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        // Snippet matches DUT-emitted SYN on the active-OPEN
        // local port (49500) — picks up the freshly-randomised
        // ISN_d before the bad-ACK inject.
        auto snippet = TcpFrameSnippet::forDutSyn(
            cfg, iface, kBasicsActiveLocalPort);

        // Active OPEN — DUT issues SYN to (tester_ip, remote_port).
        // No tester listener; DUT's SYN reaches no socket and would
        // normally elicit tester-kernel RST, but TesterAutoRstDrop
        // suppresses that path.
        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, kBasicsActiveLocalPort,
            cfg.ipv4.tester_ip, kBasicsActiveRemotePort);

        // Capture DUT's SYN to learn ISN_d. Linux's syn-sent
        // retransmits SYN at ~1 s intervals; the snippet picks up
        // the first emission within 500 ms on a same-host netns.
        const auto syn = snippet.tryCapture(
            std::chrono::milliseconds(500));
        if (syn.has_value()) {
            ::tc8::stimulus::TcpSegmentSpec bad{};
            bad.src_port = kBasicsActiveRemotePort;
            bad.dst_port = kBasicsActiveLocalPort;
            bad.seq_num  = kTesterInitialSeq;
            // Unacceptable ACK = ISN_d + LARGE_OFFSET.
            bad.ack_num  = syn->seq_num + kUnacceptableAckOffset;
            bad.flags    = ::tc8::stimulus::kTcpFlagSyn
                         | ::tc8::stimulus::kTcpFlagAck;
            emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, bad,
                         /*initial_wait=*/std::chrono::milliseconds(0));
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:           return "pass";
            case State::Fail_timeout:   return "fail:no_dut_rst_to_synack_with_unacceptable_ack";
            default:                    return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable08SM, tcp_unacceptable_08)
