#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_03_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid03SM = ::SCE::Generated::tcp_flags_invalid_03::tcp_flags_invalid_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid03SM>
    : TcpAnyBase<cases::TcpFlagsInvalid03SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-SENT state MUST ignore a segment carrying both ACK "
        "and RST flags with an unacceptable ACK number "
        "(RFC 793 §3.9 p66 Event Processing)";

    // Mechanism (single iteration):
    //   1. TesterAutoRstDrop suppresses tester-kernel auto-RST so the
    //      DUT-emitted SYN to the unbound tester port does not provoke
    //      a kernel RST that would race-kill DUT's SYN-SENT before the
    //      ACK+RST inject lands.
    //   2. UT Active-OPEN drives DUT to SYN-SENT.
    //   3. TcpFrameSnippet captures the DUT-emitted pure SYN to learn
    //      ISN_d.
    //   4. Raw-inject ACK+RST with seq=kTesterInitialSeq and
    //      ack=ISN_d + kUnacceptableAckOffset (NOT in {ISN_d + 1}).
    //   5. SCXML observes DUT SYN (positive trigger) then 3 s absence
    //      window asserts no DUT-emitted RST or pure ACK on the
    //      4-tuple.
    //
    // RstDrop scope = stimulus body only. After dtor fires, DUT's
    // continuing SYN retransmits draw tester-kernel RST+ACK with
    // ack=ISN_d+1 (acceptable), which Linux processes per RFC 793
    // RFC 793 §3.9 → CLOSED silently. Absence guard remains satisfied because
    // DUT does not emit any segment in that path.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 20U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 20U;

        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/1, local_port,
            cfg.ipv4.tester_ip, remote_port);

        const auto syn = snippet.tryCapture(
            std::chrono::milliseconds(500));
        if (syn.has_value()) {
            ::tc8::stimulus::TcpSegmentSpec bad{};
            bad.src_port = remote_port;
            bad.dst_port = local_port;
            bad.seq_num  = kTesterInitialSeq;
            bad.ack_num  = syn->seq_num + kUnacceptableAckOffset;
            bad.flags    = ::tc8::stimulus::kTcpFlagAck
                         | ::tc8::stimulus::kTcpFlagRst;
            emitTcpFrame(cfg, iface, cfg.dut.mac, bad,
                         /*initial_wait=*/std::chrono::milliseconds(0));
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_dut_syn:            return "fail:no_dut_syn_to_active_open";
            case State::Fail_unexpected_response:   return "fail:dut_emitted_response_to_ack_rst_with_unacceptable_ack";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid03SM, tcp_flags_invalid_03)
