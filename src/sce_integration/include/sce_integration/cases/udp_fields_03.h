#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_03_sm.h"

namespace tc8::sce::cases {

using UdpFields03SM = ::SCE::Generated::udp_fields_03::udp_fields_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields03SM>
    : UdpAnyBase<cases::UdpFields03SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_03";
    static constexpr std::string_view kDescription =
        "DUT accepts a UDP datagram with Source Port=0 (RFC 768 'Fields' "
        "MUST — \"If not used, a value of zero is inserted\")";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Inject UDP src_port=0; conformant otherwise. UT confirms
        // received=1.
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            /*src_port=*/0);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields03SM, udp_fields_03)
