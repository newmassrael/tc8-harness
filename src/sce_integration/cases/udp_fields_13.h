#pragma once

#include <array>
#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_13_sm.h"

namespace tc8::sce::cases {

using UdpFields13SM = ::SCE::Generated::udp_fields_13::udp_fields_13;

// 7 B odd-size payload — pseudo-header sum requires a trailing zero
// pad to fold cleanly under one's-complement summing. Linux's UDP-tx
// path applies the pad transparently (RFC 768 'Fields'); the test
// pins the resulting wire checksum is non-zero (a zero would signal
// "checksum not computed", off the spec path).
inline constexpr std::array<std::uint8_t, 7> kFields13Payload{
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields13SM>
    : UdpAnyBase<cases::UdpFields13SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_13";
    static constexpr std::string_view kSpecSection = "4.6.5.4";
    static constexpr std::string_view kDescription =
        "DUT-emitted UDP with odd payload size carries a valid checksum "
        "with pseudo-header pad (RFC 768 'Fields' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20013,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            cases::kFields13Payload.data(),
            static_cast<std::uint16_t>(cases::kFields13Payload.size()),
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields13SM, udp_fields_13)
