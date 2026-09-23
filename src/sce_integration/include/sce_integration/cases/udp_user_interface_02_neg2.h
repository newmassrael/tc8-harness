#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_02_neg2_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface02Neg2SM =
    ::SCE::Generated::udp_user_interface_02_neg2::udp_user_interface_02_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of UDP_USER_INTERFACE_02's receipt guard: the positive injects a datagram
// the DUT must receive, so a Confirmation reporting received=0 is an observed violation. The
// kAppFaultReportNoReceipt app fault makes the shared data listener lose the datagram the
// stack delivered (the only faithful site), so a buggy DUT reports no receipt. lwIP-only
// (kCapAppFault via UdpAppFaultNegBase).
template <>
struct TestCaseTraits<cases::UdpUserInterface02Neg2SM>
    : UdpAppFaultNegBase<cases::UdpUserInterface02Neg2SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_02_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_USER_INTERFACE_02: the lwIP kAppFaultReportNoReceipt app "
        "fault makes the Confirmation report no receipt; a conformant DUT reports the "
        "datagram it received";

    // Arm the receipt-loss fault, then drive the same probe + UT GetReceivedUdp query the
    // positive uses, so the Confirmation surfaces ut_received == 0.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        emitAppFlavorArm(cfg, iface, ::tc8::ut::kAppFaultReportNoReceipt);
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, dut,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size());
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface02Neg2SM, udp_user_interface_02_neg2)
