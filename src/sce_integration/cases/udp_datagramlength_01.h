#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_datagramlength_01_sm.h"

namespace tc8::sce::cases {

using UdpDatagramLength01SM = ::SCE::Generated::udp_datagramlength_01::udp_datagramlength_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpDatagramLength01SM>
    : UdpAnyBase<cases::UdpDatagramLength01SM> {
    static constexpr std::string_view kCaseId      = "UDP_DatagramLength_01";
    static constexpr std::string_view kSpecSection = "4.6.5.2";
    static constexpr std::string_view kDescription =
        "DUT discards a truncated UDP datagram (Length field smaller "
        "than actual data) (RFC 768 'Format' + automotive frame integrity)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Wire region carries 8 B header + 8 B payload (16 B total) but
        // Length field reports 8 — Linux's UDP receive path drops on
        // `length < wire_remaining` mismatch before the per-port
        // dispatch.
        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        ov.udp.length_field = std::uint16_t{8U};
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            ::tc8::sce::udp::kDataPeerPort, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_wrong_receipt:  return "fail:dut_received_udp_with_length_smaller_than_actual";
            case State::Fail_timeout:        return "fail:no_ut_confirmation_for_length_short_discard";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpDatagramLength01SM, udp_datagramlength_01)
