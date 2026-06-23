#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_messageformat_02_neg_sm.h"

namespace tc8::sce::cases {

using UdpMessageFormat02NegSM =
    ::SCE::Generated::udp_messageformat_02_neg::udp_messageformat_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.6.5.1 UDP_MessageFormat_02: the lwIP kUdpFaultRejectValid ingress flavor
// makes the input hook swallow the inbound well-formed datagram (never forwards it to
// lwIP), so the receive-counting app never sees one the DUT must accept; a conformant
// DUT still accepts it (ut_received == 1, the fault-inert branch). lwIP-only
// (kCapIngressFault via UdpIngressFaultNegBase). Drives the same well-formed ingress
// probe + UT GetReceivedUdp query the positive uses.
template <>
struct TestCaseTraits<cases::UdpMessageFormat02NegSM>
    : UdpIngressFaultNegBase<cases::UdpMessageFormat02NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_MessageFormat_02_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_MessageFormat_02: the lwIP kUdpFaultRejectValid ingress "
        "flavor makes the DUT drop a well-formed datagram; a conformant DUT accepts it";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kUdpFaultRejectValid);
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size());
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpMessageFormat02NegSM, udp_messageformat_02_neg)
