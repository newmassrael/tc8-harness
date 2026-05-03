#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_mss_options_02_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions02SM = ::SCE::Generated::tcp_mss_options_02::tcp_mss_options_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions02SM>
    : TcpAnyBase<cases::TcpMssOptions02SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.9";
    static constexpr std::string_view kDescription  =
        "DUT MUST accept No Operation and End of Options List options "
        "in a SYN segment and complete the handshake (RFC 1122 "
        "§4.2.2.5 p85)";

    // Spec Test Procedure (v3.0 p356):
    //   1. UT OpOpenTcpSocket(passive) → DUT LISTEN.
    //   2. Tester raw-injects SYN with options bytes [01 01 01 00]
    //      (three NOPs followed by EOL — RFC 793 §3.1 kinds 1 and 0).
    //   3. DUT replies SYN+ACK.
    //   4. Tester raw-injects ACK closing the handshake.
    //   5. Tester verifies DUT EST via UT OpQueryTcpEstablished.
    //
    // The handshake runs entirely inside `driveRawPassiveHandshake`
    // and the EST query result is written into c.ut_established
    // before TestRunner::start() arms the listen window — same
    // synchronous pattern BASICS_02 uses with connectToDutTcp.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // RFC 793 §3.1 kind 1 (NOP) ×3 + kind 0 (EOL). 4 bytes total —
        // already 4-byte aligned so buildTcpSegment adds no padding;
        // Data Offset = (20 + 4) / 4 = 6.
        const std::vector<std::uint8_t> syn_options{0x01U, 0x01U, 0x01U, 0x00U};

        const auto info = driveRawPassiveHandshake(
            cfg, iface, cfg.arp.dut_real_mac,
            kTcpMssOptionsListenPort02,
            syn_options,
            kTcpMssOptionsTesterSrcPort02,
            /*open_req_id=*/1,
            /*query_req_id=*/3,
            /*socket_id=*/1);
        c.ut_established = info.ut_established;

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.arp.dut_real_mac,
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

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions02SM, tcp_mss_options_02)
