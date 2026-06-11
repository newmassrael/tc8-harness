#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_mss_options_12_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions12SM = ::SCE::Generated::tcp_mss_options_12::tcp_mss_options_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions12SM>
    : TcpAnyBase<cases::TcpMssOptions12SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_12";
    static constexpr std::string_view kSpecSection  = "4.8.6.9";
    static constexpr std::string_view kDescription  =
        "DUT SHOULD advertise an MSS != 536 in active-OPEN SYN when its "
        "receive MSS differs from the RFC 1122 §4.2.2.6 default";

    // Spec Test Procedure (v3.0 p363):
    //   Prerequisite: DUT receive MSS != 536 (Ethernet MTU 1500 → 1460
    //   on the veth pair satisfies this without setup-netns mods).
    //   1. Tester triggers DUT active OPEN — UT OpOpenTcpSocket(Active).
    //   2. DUT emits a SYN with MSS != 536; SCXML asserts.
    //
    // Same scaffold as MSS_OPTIONS_11 with a stricter pass guard
    // (captured.mss != 536). Port quad chosen one slot above _11 to
    // avoid TIME-WAIT residue collision when the cluster smoke runs
    // both cases on the same worker netns.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 41U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 41U;

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
            case State::Fail_timeout:  return "fail:no_dut_syn_with_non_default_mss";
            default:                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions12SM, tcp_mss_options_12)
