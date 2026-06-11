#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_sequence_04_sm.h"

namespace tc8::sce::cases {

using TcpSequence04SM =
    ::SCE::Generated::tcp_sequence_04::tcp_sequence_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpSequence04SM>
    : TcpAnyBase<cases::TcpSequence04SM> {
    static constexpr std::string_view kCaseId       = "TCP_SEQUENCE_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.17";
    static constexpr std::string_view kDescription  =
        "DUT accepts SYN with Sequence Number = SeqMaxVal (0xFFFFFFFF) "
        "and emits SYN,ACK with ack_num wrapping to 0 (RFC 793 §3.1 "
        "modulo-32 arithmetic).";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        driveRawPassiveHandshake(
            cfg, iface, cfg.dut.mac,
            kTcpSequence04ListenPort,
            std::vector<std::uint8_t>{},
            kTcpSequence04TesterSrcPort,
            /*open_req_id=*/1,
            /*query_req_id=*/0,
            /*socket_id=*/1,
            /*capture_timeout=*/std::chrono::milliseconds(2000),
            /*tester_isn=*/0xFFFFFFFFU);

        sendCloseTcpSocketRequest(cfg, iface, cfg.dut.mac,
                                   /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:               return "pass";
            case State::Fail_wrong_ack_num: return "fail:dut_synack_ack_num_not_zero_for_max_isn";
            case State::Fail_timeout:       return "fail:no_dut_syn_ack_within_listen_window";
            default:                        return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpSequence04SM, tcp_sequence_04)
