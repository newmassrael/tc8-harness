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
    : UdpReceiveDrivenBase<cases::UdpFields03SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_03";
    static constexpr std::string_view kDescription =
        "DUT accepts a UDP datagram with Source Port=0 (RFC 768 'Fields' "
        "MUST — \"If not used, a value of zero is inserted\")";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        // Inject UDP src_port=0; conformant otherwise. The stimulus records the
        // DUT's receive answer in-process (a receive window through the Tier-2
        // seam); the SCXML grades received=1.
        ::tc8::sce::udp::emitIngressProbeAndObserve(
            c, cfg, ctx.iface, ctx.dut,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            /*src_port=*/0);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields03SM, udp_fields_03)
