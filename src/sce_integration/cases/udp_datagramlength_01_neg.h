#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_datagramlength_01_neg_sm.h"

namespace tc8::sce::cases {

using UdpDatagramLength01NegSM =
    ::SCE::Generated::udp_datagramlength_01_neg::udp_datagramlength_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpDatagramLength01NegSM>
    : UdpIngressFaultNegBase<cases::UdpDatagramLength01NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_DatagramLength_01_NEG";
    static constexpr std::string_view kSpecSection = "4.6.5.4";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_DatagramLength_01: the lwIP kUdpFaultAcceptBadChecksum "
        "ingress flavor makes the DUT accept a datagram whose Length is smaller than the "
        "payload; a conformant DUT drops it";
    // Arm the ingress acceptance fault, then drive the same understated-Length ingress
    // probe + UT GetReceivedUdp query the positive uses. With the flavor armed the
    // input hook zeroes the checksum so lwIP delivers the datagram (ut_received == 1).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kUdpFaultAcceptBadChecksum);
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        ov.udp.length_field = std::uint16_t{8U};
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            ::tc8::sce::udp::kDataPeerPort, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpDatagramLength01NegSM, udp_datagramlength_01_neg)
