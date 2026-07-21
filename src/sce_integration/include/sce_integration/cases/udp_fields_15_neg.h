#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_15_neg_sm.h"

namespace tc8::sce::cases {

using UdpFields15NegSM = ::SCE::Generated::udp_fields_15_neg::udp_fields_15_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields15NegSM>
    : UdpIngressFaultNegBase<cases::UdpFields15NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_15_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_FIELDS_15: the lwIP kUdpFaultAcceptBadChecksum ingress "
        "flavor makes the DUT accept a non-zero invalid-checksum datagram; a conformant "
        "DUT drops it";
    // Arm the ingress acceptance fault, then drive the same bad-checksum ingress probe +
    // UT GetReceivedUdp query the positive uses. With the flavor armed the input hook
    // zeroes the checksum so lwIP's validation gate skips and delivers it
    // (ut_received == 1).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kUdpFaultAcceptBadChecksum);
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        ov.udp.checksum_field = std::uint16_t{0xDEAD};
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            ::tc8::sce::udp::kDataPeerPort, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields15NegSM, udp_fields_15_neg)
