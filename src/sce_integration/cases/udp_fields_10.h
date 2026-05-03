#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_10_sm.h"

namespace tc8::sce::cases {

using UdpFields10SM = ::SCE::Generated::udp_fields_10::udp_fields_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields10SM>
    : UdpAnyBase<cases::UdpFields10SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_10";
    static constexpr std::string_view kSpecSection = "4.6.5.4";
    static constexpr std::string_view kDescription =
        "DUT discards a UDP datagram whose Length field claims more bytes "
        "than the IP payload carries (RFC 768 'Fields' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // (8 + payload + 1) overstates the actual length by one byte.
        constexpr std::uint16_t kPayload = static_cast<std::uint16_t>(
            ::tc8::sce::udp::kUdpDefaultData.size());
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        ov.udp.length_field = static_cast<std::uint16_t>(8U + kPayload + 1U);
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.arp.dut_real_mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            ::tc8::sce::udp::kDataPeerPort, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_wrong_receipt:  return "fail:dut_received_udp_with_length_greater_than_actual";
            case State::Fail_timeout:        return "fail:no_ut_confirmation_for_long_length_discard";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields10SM, udp_fields_10)
