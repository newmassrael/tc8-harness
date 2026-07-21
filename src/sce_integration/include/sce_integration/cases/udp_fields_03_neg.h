#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_03_neg_sm.h"

namespace tc8::sce::cases {

using UdpFields03NegSM = ::SCE::Generated::udp_fields_03_neg::udp_fields_03_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields03NegSM>
    : UdpIngressFaultNegBase<cases::UdpFields03NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_03_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_FIELDS_03: the lwIP kUdpFaultRejectValid ingress flavor "
        "makes the DUT drop a valid source-port-0 datagram; a conformant DUT accepts it";
    // Arm the ingress rejection fault, then drive the same valid src_port=0 ingress
    // probe + UT GetReceivedUdp query the positive uses. With the flavor armed the
    // input hook swallows the datagram so lwIP never delivers it (ut_received == 0).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kUdpFaultRejectValid);
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            /*src_port=*/0);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields03NegSM, udp_fields_03_neg)
