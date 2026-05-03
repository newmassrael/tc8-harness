#pragma once

#include <array>
#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/udp_fields_01.h"  // kUdpFieldsTesterSrcPort
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_14_sm.h"

namespace tc8::sce::cases {

using UdpFields14SM = ::SCE::Generated::udp_fields_14::udp_fields_14;

// 100 B even-size payload — pseudo-header sum needs no pad (the body
// is already 2-byte aligned). Mirror of FIELDS_13's odd-size case.
inline constexpr std::size_t kFields14PayloadLen = 100;

inline std::array<std::uint8_t, kFields14PayloadLen> makeFields14Payload() {
    std::array<std::uint8_t, kFields14PayloadLen> p{};
    for (std::size_t i = 0; i < p.size(); ++i) {
        p[i] = static_cast<std::uint8_t>(0xB0 + (i % 16U));
    }
    return p;
}

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields14SM>
    : UdpAnyBase<cases::UdpFields14SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_14";
    static constexpr std::string_view kSpecSection = "4.6.5.4";
    static constexpr std::string_view kDescription =
        "DUT-emitted UDP with even payload size carries a valid checksum "
        "without pad processing (RFC 768 'Fields' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        const auto p = cases::makeFields14Payload();
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20014,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            p.data(), static_cast<std::uint16_t>(p.size()),
            cases::kUdpFieldsTesterSrcPort,
            cfg.arp.dut_real_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                     return "pass";
            case State::Fail_invalid_checksum:    return "fail:dut_emitted_udp_with_invalid_pseudo_header_checksum_on_unpadded_payload";
            case State::Fail_timeout:             return "fail:no_dut_originated_udp_within_listen_window";
            default:                              return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields14SM, udp_fields_14)
