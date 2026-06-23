#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_05_neg_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type05NegSM = ::SCE::Generated::icmpv4_type_05_neg::icmpv4_type_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Type05NegSM>
    : Icmpv4IngressFaultNegBase<cases::Icmpv4Type05NegSM, std::uint8_t{0}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_05_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ICMPv4_TYPE_05: the lwIP kIcmpFaultSynthEchoReply ingress "
        "flavor makes the DUT reply to an Echo Request carrying malformed IP options; "
        "a conformant DUT drops it at options parsing and stays silent";

    // Arm the Echo-Reply synthesis fault, then send the same malformed-IP-options Echo
    // Request the positive uses (the frame the DUT must drop without replying). The netif
    // INPUT hook reads the trigger at fixed offsets before lwIP's own option parsing, so
    // the synthesized Echo Reply (type 0) is the only DUT-origin frame.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthEchoReply);
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.dst_mac = cfg.arp.dut_iface_mac;
        ov.ip_options.assign(::tc8::stimulus::kIcmpv4TimestampOptionMalformed.begin(),
                             ::tc8::stimulus::kIcmpv4TimestampOptionMalformed.end());
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type05NegSM, icmpv4_type_05_neg)
