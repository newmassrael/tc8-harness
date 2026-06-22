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

#include "tcp_mss_options_12_neg_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions12NegSM =
    ::SCE::Generated::tcp_mss_options_12_neg::tcp_mss_options_12_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions12NegSM>
    : TcpEgressFaultNegBase<cases::TcpMssOptions12NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_12_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.9";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_MSS_OPTIONS_12: the lwIP kTcpFaultSynMssDefault egress "
        "flavor forces the SYN's MSS to the 536 default; a conformant DUT advertises a "
        "non-default MSS";

    // Arm the MSS-default fault, then drive the same active OPEN the positive uses. The
    // flavor rewrites the DUT SYN's MSS option value to the RFC 1122 default 536 (flags
    // stay pure SYN), so the dissector reports mss == 536 — the equals-default violation
    // the positive forbids — observed on the SYN before the handshake completes.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultSynMssDefault);

        auto open = driveSeamActiveOpen(
            dut, cfg,
            kBasicsActiveLocalPort  + 41U,
            kBasicsActiveRemotePort + 41U);
        if (!open.conn) return;

        dut.tcpControl()->closeTcp(open.conn->socket);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions12NegSM, tcp_mss_options_12_neg)
