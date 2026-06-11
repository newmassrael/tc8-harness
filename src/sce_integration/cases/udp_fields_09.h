#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_09_sm.h"

namespace tc8::sce::cases {

using UdpFields09SM = ::SCE::Generated::udp_fields_09::udp_fields_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields09SM>
    : UdpAnyBase<cases::UdpFields09SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_09";
    static constexpr std::string_view kSpecSection = "4.6.5.4";
    static constexpr std::string_view kDescription =
        "DUT discards a UDP datagram with Length field == 0 (RFC 768 "
        "'Fields' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        ov.udp.length_field = std::uint16_t{0x0000};
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            ::tc8::sce::udp::kDataPeerPort, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_wrong_receipt:  return "fail:dut_received_udp_with_zero_length_field";
            case State::Fail_timeout:        return "fail:no_ut_confirmation_for_zero_length_discard";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields09SM, udp_fields_09)
