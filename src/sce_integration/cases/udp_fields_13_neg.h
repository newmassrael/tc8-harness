#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_13_neg_sm.h"

namespace tc8::sce::cases {

using UdpFields13NegSM = ::SCE::Generated::udp_fields_13_neg::udp_fields_13_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields13NegSM>
    : UdpEgressFaultNegBase<cases::UdpFields13NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_13_NEG";
    static constexpr std::string_view kSpecSection = "4.6.5.4";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_FIELDS_13: the lwIP kUdpFaultChecksumWrong egress "
        "flavor invalidates the DUT egress UDP checksum; conformant emits a valid one";
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kUdpFaultChecksumWrong);
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20013,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields13NegSM, udp_fields_13_neg)
