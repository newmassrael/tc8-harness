#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_04_neg_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface04NegSM =
    ::SCE::Generated::udp_user_interface_04_neg::udp_user_interface_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of UDP_USER_INTERFACE_04: the §4.6.5.5 source-IP report is a receive-
// operation property — the stack delivers the correct src IP and the application surfaces it
// in the GetReceivedUdp Confirmation. The kAppFaultReportWrongSrcIp app fault corrupts that
// report (the only faithful site), so a buggy DUT surfaces a wrong IP. lwIP-only
// (kCapAppFault via UdpAppFaultNegBase).
template <>
struct TestCaseTraits<cases::UdpUserInterface04NegSM>
    : UdpAppFaultNegBase<cases::UdpUserInterface04NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_04_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_USER_INTERFACE_04: the lwIP kAppFaultReportWrongSrcIp app "
        "fault makes the Confirmation report a wrong source IP; a conformant DUT reports the "
        "IP the datagram carried";

    // Arm the source-IP report fault, then drive the same probe + UT GetReceivedUdp query
    // the positive uses (the wire-level src IP is unchanged; the flavor corrupts only the
    // reported value), so the Confirmation surfaces a src IP != tester_ip.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitAppFlavorArm(cfg, iface, ::tc8::ut::kAppFaultReportWrongSrcIp);
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size());
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface04NegSM, udp_user_interface_04_neg)
