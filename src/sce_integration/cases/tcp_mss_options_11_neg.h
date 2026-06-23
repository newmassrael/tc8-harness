#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_mss_options_11_neg_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions11NegSM =
    ::SCE::Generated::tcp_mss_options_11_neg::tcp_mss_options_11_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions11NegSM>
    : TcpEgressFaultNegBase<cases::TcpMssOptions11NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_11_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_MSS_OPTIONS_11: the lwIP kTcpFaultSynMssZero egress "
        "flavor zeroes the active-OPEN SYN's MSS option; a conformant DUT advertises one";

    // Arm the MSS-zero fault, then drive the same active OPEN the positive uses. The
    // flavor zeroes the DUT SYN's MSS option value (flags stay pure SYN), so the
    // dissector reports mss == 0 — the missing-MSS violation the positive forbids —
    // observed on the SYN before the handshake completes.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultSynMssZero);

        auto open = driveSeamActiveOpen(
            dut, cfg,
            kBasicsActiveLocalPort  + kTcpMssOptions11LocalOffset,
            kBasicsActiveRemotePort + kTcpMssOptions11LocalOffset);
        if (!open.conn) return;

        dut.tcpControl()->closeTcp(open.conn->socket);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions11NegSM, tcp_mss_options_11_neg)
