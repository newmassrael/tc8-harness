#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_mss_options_11_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions11SM = ::SCE::Generated::tcp_mss_options_11::tcp_mss_options_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions11SM>
    : TcpAnyBase<cases::TcpMssOptions11SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_11";
    static constexpr std::string_view kSpecSection  = "4.8.6.9";
    static constexpr std::string_view kDescription  =
        "DUT MUST implement sending the MSS option in its active-OPEN "
        "SYN (RFC 1122 §4.2.2.6 p85)";

    // Spec Test Procedure (v3.0 p362):
    //   1. Tester triggers DUT active OPEN — UT OpOpenTcpSocket(Active).
    //   2. DUT emits a SYN; SCXML asserts the segment carries an MSS
    //      option (captured.mss > 0).
    //
    // Same scaffold as BASICS_06 with one extra pass-guard conjunct.
    // The auxiliary tester listener exists only so the DUT's outbound
    // SYN reaches a real receiver instead of triggering tester-kernel
    // RST-on-closed-port — the spec assertion is on the DUT's emitted
    // SYN, observed before the handshake completes.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 40U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 40U;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1, local_port, remote_port);
        (void)listener;

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:          return "pass";
            case State::Fail_timeout:  return "fail:no_dut_syn_with_mss_option";
            default:                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions11SM, tcp_mss_options_11)
