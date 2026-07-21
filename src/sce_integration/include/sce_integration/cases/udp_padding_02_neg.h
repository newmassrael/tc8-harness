#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/udp_padding_02.h"  // SSOT for kUdpPadding02DutSrcPort
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_padding_02_neg_sm.h"

namespace tc8::sce::cases {

using UdpPadding02NegSM = ::SCE::Generated::udp_padding_02_neg::udp_padding_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.6.5.3 UDP_Padding_02: a conformant DUT emits a UDP datagram whose Length
// field is exactly 8 + payload (no trailing padding lifts it above 8+N). kUdpFaultLengthWrong is
// the shared UDP-Length egress flavor (one flavor per field; the exact wrong value is immaterial —
// the guard tests the field), so the lwIP netif link-output hook rewrites the DUT egress UDP Length
// to a value != 8 + payload, the same defect a trailing-pad bug would surface at the Length guard.
// Pass = the wrong length observed on the DUT egress frame; fail_compliant = DUT emitted the correct
// length (16) despite the flavor (fault inert). lwIP-only (capability-gated on kCapEgressFault).
// Envelope: udp_field_check.
template <>
struct TestCaseTraits<cases::UdpPadding02NegSM>
    : UdpEgressFaultNegBase<cases::UdpPadding02NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_Padding_02_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_Padding_02: the lwIP kUdpFaultLengthWrong egress flavor rewrites "
        "the DUT egress UDP Length off 8+payload; a conformant DUT emits exactly 16 with no padding";
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kUdpFaultLengthWrong);
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/cases::kUdpPadding02DutSrcPort,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpPadding02NegSM, udp_padding_02_neg)
