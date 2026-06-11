#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_mss_options_03_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions03SM = ::SCE::Generated::tcp_mss_options_03::tcp_mss_options_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions03SM>
    : TcpAnyBase<cases::TcpMssOptions03SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.9";
    static constexpr std::string_view kDescription  =
        "DUT MUST ignore an unimplemented TCP option in a SYN segment "
        "and complete the handshake (RFC 1122 §4.2.2.5 p85)";

    // Spec Test Procedure (v3.0 p357):
    //   1. UT OpOpenTcpSocket(passive) → DUT LISTEN.
    //   2. Tester raw-injects SYN with kind=253 option (RFC 4727 §7.1
    //      reserved for experimentation — no production stack
    //      implements it, so it satisfies "unimplemented" without
    //      ambiguity). Encoding: [0xFD 0x04 0xAA 0xBB] — kind, length=4
    //      (kind+length+2 data bytes), arbitrary 2 data bytes.
    //   3. DUT replies SYN+ACK.
    //   4. Tester raw-injects ACK closing the handshake.
    //   5. Tester verifies DUT EST via UT OpQueryTcpEstablished.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // RFC 4727 kind 253 with 2-byte payload, length=4, padded to 4.
        const std::vector<std::uint8_t> syn_options{0xFDU, 0x04U, 0xAAU, 0xBBU};

        const auto info = driveRawPassiveHandshake(
            cfg, iface, cfg.dut.mac,
            kTcpMssOptionsListenPort03,
            syn_options,
            kTcpMssOptionsTesterSrcPort03,
            /*open_req_id=*/1,
            /*query_req_id=*/3,
            /*socket_id=*/1);
        c.ut_established = info.ut_established;

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                   return "pass";
            case State::Fail_not_established:   return "fail:dut_did_not_reach_established";
            case State::Fail_timeout:           return "fail:no_dut_syn_ack_within_listen_window";
            default:                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions03SM, tcp_mss_options_03)
