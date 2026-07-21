#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_02_sm.h"

namespace tc8::sce::cases {

using UdpFields02SM = ::SCE::Generated::udp_fields_02::udp_fields_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields02SM>
    : UdpAnyBase<cases::UdpFields02SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_02";
    static constexpr std::string_view kDescription =
        "DUT-emitted UDP datagram carries the caller-specified "
        "Destination Port (RFC 768 'Fields' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Per-case unique src_port (20002) keeps observation distinct
        // from sibling FIELDS_01 (src_port=20001) under back-to-back
        // smoke-test runs sharing a netns.
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20002,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/20001,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields02SM, udp_fields_02)
