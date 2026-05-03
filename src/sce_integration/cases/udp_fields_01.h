#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_01_sm.h"

namespace tc8::sce::cases {

using UdpFields01SM = ::SCE::Generated::udp_fields_01::udp_fields_01;

// Tester-side source port used by every UDP_FIELDS / UDP_USER_INTERFACE
// trait when issuing the OpTriggerSendUdp UT request. Disjoint from the
// per-case DUT-side src_port literals so SCXML can attribute observed
// frames to the right side without ambiguity.
inline constexpr std::uint16_t kUdpFieldsTesterSrcPort = 20100;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields01SM>
    : UdpAnyBase<cases::UdpFields01SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_01";
    static constexpr std::string_view kSpecSection = "4.6.5.4";
    static constexpr std::string_view kDescription =
        "DUT-emitted UDP datagram carries the caller-specified Source "
        "Port (RFC 768 'Fields' SHOULD)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface,
            /*req_id=*/1,
            /*dut_src_port=*/20001,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            cases::kUdpFieldsTesterSrcPort,
            cfg.arp.dut_real_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                  return "pass";
            case State::Fail_wrong_src_port:   return "fail:dut_emitted_udp_with_wrong_src_port";
            case State::Fail_timeout:          return "fail:no_dut_originated_udp_within_listen_window";
            default:                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields01SM, udp_fields_01)
