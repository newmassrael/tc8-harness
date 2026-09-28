#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_mss_options_11_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions11SM = ::SCE::Generated::tcp_mss_options_11::tcp_mss_options_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions11SM>
    : TcpDutDrivenBase<cases::TcpMssOptions11SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_11";
    static constexpr std::string_view kDescription  =
        "DUT MUST implement sending the MSS option in its active-OPEN "
        "SYN (RFC 1122 §4.2.2.6 p85)";

    // Case shape:
    //   1. Tester triggers the DUT active OPEN through the Tier-2 seam.
    //   2. DUT emits a SYN; SCXML asserts the segment carries an MSS
    //      option (captured.mss > 0).
    //
    // Same scaffold as BASICS_06 with one extra pass-guard conjunct.
    // Open routes through the ITcpControl seam so the case runs unchanged
    // on whichever backend `--dut-control` selected. The auxiliary tester
    // listener (held by the returned SeamActiveOpen) exists only so the
    // DUT's outbound SYN reaches a real receiver instead of triggering
    // tester-kernel RST-on-closed-port — the spec assertion is on the
    // DUT's emitted SYN, observed before the handshake completes.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpMssOptions11LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpMssOptions11LocalOffset;

        auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
        if (!open.conn) return;

        ctx.dut.tcpControl()->closeTcp(open.conn->socket);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions11SM, tcp_mss_options_11)
