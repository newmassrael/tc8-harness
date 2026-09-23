#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/udp_fields_12.h"  // SSOT for the positive's stimulus
#include "sce_integration/test_runner.h"

#include "udp_fields_12_neg2_sm.h"

namespace tc8::sce::cases {

using UdpFields12Neg2SM = ::SCE::Generated::udp_fields_12_neg2::udp_fields_12_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.6.5.4 UDP_FIELDS_12's receipt guard: the positive injects a maximum-
// length datagram the DUT must receive, so a Confirmation reporting received=0 is an observed
// violation. The kAppFaultReportNoReceipt app fault makes the shared data listener lose the
// datagram the stack reassembled and delivered (the only faithful site), so a buggy DUT
// reports no receipt. lwIP-only (kCapAppFault via UdpAppFaultNegBase).
template <>
struct TestCaseTraits<cases::UdpFields12Neg2SM>
    : UdpAppFaultNegBase<cases::UdpFields12Neg2SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_12_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_FIELDS_12: the lwIP kAppFaultReportNoReceipt app fault makes "
        "the Confirmation report no receipt; a conformant DUT reports the maximum-length "
        "datagram it reassembled";

    // Arm the receipt-loss fault, then drive the same 65 507 B fragmented stimulus + UT
    // GetReceivedUdp query the positive uses, so the Confirmation surfaces ut_received == 0.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        emitAppFlavorArm(cfg, iface, ::tc8::ut::kAppFaultReportNoReceipt);
        cases::emitMaxLengthDatagramAndQuery(cfg, iface, dut);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields12Neg2SM, udp_fields_12_neg2)
