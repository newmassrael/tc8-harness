#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/udp_user_interface_03.h"  // SSOT for kUserInterface03SrcPort
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_03_neg_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface03NegSM =
    ::SCE::Generated::udp_user_interface_03_neg::udp_user_interface_03_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of UDP_USER_INTERFACE_03: the §4.6.5.5 source-port report is a receive-
// operation property — the stack delivers the correct src port and the application surfaces
// it in the GetReceivedUdp Confirmation. The kAppFaultReportWrongSrcPort app fault corrupts
// that report (the only faithful site — an ingress rewrite would make the DUT faithfully
// report the rewritten value), so a buggy DUT surfaces a wrong port. lwIP-only (kCapAppFault
// via UdpAppFaultNegBase).
template <>
struct TestCaseTraits<cases::UdpUserInterface03NegSM>
    : UdpAppFaultNegBase<cases::UdpUserInterface03NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_03_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_USER_INTERFACE_03: the lwIP kAppFaultReportWrongSrcPort app "
        "fault makes the Confirmation report a wrong source port; a conformant DUT reports "
        "the port the datagram carried";

    // Arm the source-port report fault, then drive the same probe + UT GetReceivedUdp query
    // the positive uses (the wire-level src port is unchanged; the flavor corrupts only the
    // reported value), so the Confirmation surfaces a src port != 20019.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitAppFlavorArm(cfg, iface, ::tc8::ut::kAppFaultReportWrongSrcPort);
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            cases::kUserInterface03SrcPort);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface03NegSM, udp_user_interface_03_neg)
