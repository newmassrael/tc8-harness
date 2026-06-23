#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_10_neg_sm.h"

namespace tc8::sce::cases {

using UdpFields10NegSM = ::SCE::Generated::udp_fields_10_neg::udp_fields_10_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields10NegSM>
    : UdpIngressFaultNegBase<cases::UdpFields10NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_10_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_FIELDS_10: the lwIP kUdpFaultAcceptBadChecksum ingress "
        "flavor makes the DUT accept a datagram whose Length exceeds the payload; a "
        "conformant DUT drops it";
    // Arm the ingress acceptance fault, then drive the same overstated-Length ingress
    // probe + UT GetReceivedUdp query the positive uses. With the flavor armed the
    // input hook zeroes the checksum so lwIP delivers the datagram (ut_received == 1).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kUdpFaultAcceptBadChecksum);
        // (8 + payload + 1) overstates the actual length by one byte.
        constexpr std::uint16_t kPayload = static_cast<std::uint16_t>(
            ::tc8::sce::udp::kUdpDefaultData.size());
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        ov.udp.length_field = static_cast<std::uint16_t>(8U + kPayload + 1U);
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            ::tc8::sce::udp::kDataPeerPort, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields10NegSM, udp_fields_10_neg)
