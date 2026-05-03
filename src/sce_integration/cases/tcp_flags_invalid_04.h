#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_04_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid04SM = ::SCE::Generated::tcp_flags_invalid_04::tcp_flags_invalid_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid04SM>
    : TcpAnyBase<cases::TcpFlagsInvalid04SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.6";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-SENT state MUST ignore a RST control message "
        "(RFC 793 §3.9 p67 Event Processing)";

    // Mechanism (single iteration). Same prelude shape as
    // FLAGS_INVALID_03; the only difference is the injected segment
    // carries RST without ACK (bare RST). Linux's
    // `tcp_rcv_synsent_state_process` requires the ACK bit to reach
    // the connection-reset branch; a bare RST is dropped before any
    // response decision, so DUT silently remains in SYN-SENT.
    //
    // seq=ISN_d+1 (in-window relative to DUT's expected receive
    // sequence) keeps the segment plausible at the IP layer; bare-RST
    // with random seq would still be dropped by Linux but for a
    // different reason (RFC 5961 strict-RST sequence check), which
    // would not exercise the spec-asserted "drop because no ACK"
    // branch.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 21U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 21U;

        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        sendOpenTcpSocketActiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, local_port,
            cfg.ipv4.tester_ip, remote_port);

        const auto syn = snippet.tryCapture(
            std::chrono::milliseconds(500));
        if (syn.has_value()) {
            ::tc8::stimulus::TcpSegmentSpec bad{};
            bad.src_port = remote_port;
            bad.dst_port = local_port;
            bad.seq_num  = syn->seq_num + 1U;
            bad.ack_num  = 0U;
            bad.flags    = ::tc8::stimulus::kTcpFlagRst;
            emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, bad,
                         /*initial_wait=*/std::chrono::milliseconds(0));
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_dut_syn:            return "fail:no_dut_syn_to_active_open";
            case State::Fail_unexpected_response:   return "fail:dut_emitted_response_to_bare_rst_in_syn_sent";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid04SM, tcp_flags_invalid_04)
