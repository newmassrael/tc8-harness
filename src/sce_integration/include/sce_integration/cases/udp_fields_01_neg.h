#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_01_neg_sm.h"

namespace tc8::sce::cases {

using UdpFields01NegSM = ::SCE::Generated::udp_fields_01_neg::udp_fields_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields01NegSM>
    : UdpEgressFaultNegBase<cases::UdpFields01NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_01_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_FIELDS_01: the lwIP kUdpFaultSrcPortWrong egress "
        "flavor rewrites the DUT egress Source Port; a conformant DUT emits 20001";
    // Arm the egress src-port fault, then drive the same UT 0x02 egress the positive
    // uses so the lwIP DUT emits a data UDP the hook corrupts.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kUdpFaultSrcPortWrong);
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20001,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields01NegSM, udp_fields_01_neg)
