#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_01_neg_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface01NegSM =
    ::SCE::Generated::udp_user_interface_01_neg::udp_user_interface_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of UDP_USER_INTERFACE_01: the §4.6.5.5 receive-port count is a receive-
// interface property — the application binds the ports and reports the count in the
// CreateUdpReceivePorts Confirmation. The kAppFaultMiscountPorts app fault makes it
// over-report by one, so a buggy DUT surfaces a wrong count. lwIP-only (kCapAppFault via
// UdpAppFaultNegBase).
template <>
struct TestCaseTraits<cases::UdpUserInterface01NegSM>
    : UdpAppFaultNegBase<cases::UdpUserInterface01NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_01_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_USER_INTERFACE_01: the lwIP kAppFaultMiscountPorts app fault "
        "makes the Confirmation over-report the receive-port count; a conformant DUT reports "
        "the count it bound";

    // Arm the miscount fault, then drive the same CreateUdpReceivePorts request the positive
    // uses (10 ports), so the Confirmation surfaces ut_create_actual_count != 10.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitAppFlavorArm(cfg, iface, ::tc8::ut::kAppFaultMiscountPorts);
        ::tc8::sce::udp::emitCreateUdpReceivePorts(
            cfg, iface,
            /*req_id=*/1,
            /*count=*/10,
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface01NegSM, udp_user_interface_01_neg)
