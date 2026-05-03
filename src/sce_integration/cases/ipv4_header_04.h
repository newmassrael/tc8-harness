#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_header_04_sm.h"

namespace tc8::sce::cases {

using Ipv4Header04SM = ::SCE::Generated::ipv4_header_04::ipv4_header_04;

// 172.16.0.99 in network byte order: bytes AC 10 00 63, little-endian
// uint32 = 0x630010AC. Same-subnet host that is not the DUT's iface IP
// (172.16.0.2) — kernel drops silently at the "dst not local" check.
inline constexpr std::uint32_t kIpv4Header04WrongDstBe = 0x630010ACU;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Header04SM>
    : Ipv4ObservationBase<cases::Ipv4Header04SM> {
    static constexpr std::string_view kCaseId      = "IPV4_HEADER_04";
    static constexpr std::string_view kSpecSection = "4.4.4.1";
    static constexpr std::string_view kDescription =
        "DUT silently discards an IPv4 packet whose Destination "
        "Address is neither the DUT's own address nor a broadcast / "
        "multicast address";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::ipv4::StimulusOverrides ov{};
        ov.dst_ip = cases::kIpv4Header04WrongDstBe;
        ::tc8::sce::ipv4::emitStimulus(cfg, iface, ov);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:              return "pass";
            case State::Fail_dut_replied:  return "fail:dut_replied_despite_non_local_dst_ip";
            default:                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header04SM, ipv4_header_04)
