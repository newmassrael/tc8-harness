#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_02_neg_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface02NegSM =
    ::SCE::Generated::udp_user_interface_02_neg::udp_user_interface_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of UDP_USER_INTERFACE_02: the §4.6.5.5 received-data-octets report is a
// receive-operation property — the stack delivers the correct payload and the application
// surfaces it in the GetReceivedUdp Confirmation. The kAppFaultReportWrongPayload app fault
// corrupts the first reported octet (the only faithful site), so a buggy DUT surfaces wrong
// data. lwIP-only (kCapAppFault via UdpAppFaultNegBase).
template <>
struct TestCaseTraits<cases::UdpUserInterface02NegSM>
    : UdpAppFaultNegBase<cases::UdpUserInterface02NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_02_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_USER_INTERFACE_02: the lwIP kAppFaultReportWrongPayload app "
        "fault makes the Confirmation report a corrupted payload byte; a conformant DUT "
        "reports the data the datagram carried";

    // Arm the payload report fault, then drive the same probe + UT GetReceivedUdp query the
    // positive uses (the wire-level payload is unchanged; the flavor corrupts only the first
    // reported octet), so the Confirmation surfaces ut_recv_payload_first16[0] != 0x10.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitAppFlavorArm(cfg, iface, ::tc8::ut::kAppFaultReportWrongPayload);
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size());
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface02NegSM, udp_user_interface_02_neg)
