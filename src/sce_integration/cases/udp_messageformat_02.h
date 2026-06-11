#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_messageformat_02_sm.h"

namespace tc8::sce::cases {

using UdpMessageFormat02SM = ::SCE::Generated::udp_messageformat_02::udp_messageformat_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpMessageFormat02SM>
    : UdpAnyBase<cases::UdpMessageFormat02SM> {
    static constexpr std::string_view kCaseId      = "UDP_MessageFormat_02";
    static constexpr std::string_view kSpecSection = "4.6.5.1";
    static constexpr std::string_view kDescription =
        "DUT accepts a UDP packet with a well-formed Header (RFC 768 "
        "'Format' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size());
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_wrong_receipt:  return "fail:dut_did_not_accept_well_formed_udp";
            case State::Fail_timeout:        return "fail:no_ut_confirmation_for_well_formed_udp_accept";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpMessageFormat02SM, udp_messageformat_02)
