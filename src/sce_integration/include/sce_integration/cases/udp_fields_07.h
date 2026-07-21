#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_07_sm.h"

namespace tc8::sce::cases {

using UdpFields07SM = ::SCE::Generated::udp_fields_07::udp_fields_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields07SM>
    : UdpAnyBase<cases::UdpFields07SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_07";
    static constexpr std::string_view kDescription =
        "DUT-emitted UDP datagram with no payload carries Length field "
        "== 8 (header only) (RFC 768 'Fields' MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Empty payload — DUT kernel emits an 8 B UDP datagram. The
        // packet pipeline tolerates RawPDU absence (post-S15 fix), so
        // the SCXML observes the wire shape via UdpFrame.
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20003,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            /*payload=*/nullptr,
            /*payload_len=*/0,
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields07SM, udp_fields_07)
