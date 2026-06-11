#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_mss_options_10_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions10SM = ::SCE::Generated::tcp_mss_options_10::tcp_mss_options_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions10SM>
    : TcpAnyBase<cases::TcpMssOptions10SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_10";
    static constexpr std::string_view kSpecSection  = "4.8.6.9";
    static constexpr std::string_view kDescription  =
        "If an MSS option is not received at connection setup, DUT "
        "MUST default send MSS to 536 bytes (RFC 1122 §4.2.2.6 p85).";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // Outer RstDrop scope — keeps tester-kernel RSTs against the
        // orphaned 4-tuple suppressed across the post-handshake data
        // window. driveRawPassiveHandshake also installs the rule
        // internally; iptables -A is additive, dtor symmetry preserves
        // the outer rule until our scope ends.
        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        // Empty SYN options: Linux defaults `tp->rx_opt.mss_clamp` to
        // 536 when no kind=2 MSS arrived at handshake (RFC 1122
        // §4.2.2.6). Subsequent ::send() segments cap at 536 B.
        const auto info = driveRawPassiveHandshake(
            cfg, iface, cfg.dut.mac,
            kTcpMssOptionsListenPort10,
            std::vector<std::uint8_t>{},  // no MSS option
            kTcpMssOptionsTesterSrcPort10,
            /*open_req_id=*/1,
            /*query_req_id=*/0,  // skip EST query — pass guard is
                                  // segment-size, not state
            /*socket_id=*/1);
        (void)info;

        // 1024 B > 536 B ensures Linux segments the write into at
        // least 2 chunks. First chunk size = mss_clamp = 536 if the
        // DUT applied the RFC 1122 default correctly.
        sendSendTcpDataPatternRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1,
            /*pattern=*/0xAAU, /*total_len=*/1024U);
        // 200 ms grace for the kernel to flush the first segment to
        // the wire — pcap captures it before the SCXML deadline fires
        // and before any subsequent UT close torpedoes the connection.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/3, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_wrong_segment_size:    return "fail:dut_data_segment_size_not_default_536";
            case State::Fail_timeout:               return "fail:no_dut_data_segment_within_listen_window";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions10SM, tcp_mss_options_10)
