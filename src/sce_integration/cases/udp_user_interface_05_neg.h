#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_05_neg_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface05NegSM =
    ::SCE::Generated::udp_user_interface_05_neg::udp_user_interface_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.6.5.5 UDP_USER_INTERFACE_05: the lwIP kUdpFaultSrcPortWrong egress flavor
// rewrites the DUT-emitted datagram's source port off the caller-specified 20025; a
// conformant DUT emits 20025 (the fault-inert branch). lwIP-only (kCapEgressFault via
// UdpEgressFaultNegBase). Drives the same UT OpTriggerSendUdp with src port 20025 the
// positive uses — the same egress src-port flavor as UDP_FIELDS_01_NEG.
template <>
struct TestCaseTraits<cases::UdpUserInterface05NegSM>
    : UdpEgressFaultNegBase<cases::UdpUserInterface05NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_05_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_USER_INTERFACE_05: the lwIP kUdpFaultSrcPortWrong egress "
        "flavor rewrites the DUT egress Source Port; a conformant DUT emits 20025";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kUdpFaultSrcPortWrong);
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20025,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface05NegSM, udp_user_interface_05_neg)
