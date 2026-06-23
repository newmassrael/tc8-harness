#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_error_03_neg_sm.h"

namespace tc8::sce::cases {

using Icmpv4Error03NegSM = ::SCE::Generated::icmpv4_error_03_neg::icmpv4_error_03_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Icmpv4Error03NegSM>
    : Icmpv4IngressFaultNegBase<cases::Icmpv4Error03NegSM, std::uint8_t{12}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_ERROR_03_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ICMPv4_ERROR_03: the lwIP kIcmpFaultSynthParamProblem "
        "ingress flavor makes the DUT emit a Parameter Problem for a fragmented "
        "datagram sequence; a conformant DUT stays silent";

    // Arm the Parameter-Problem synthesis fault, then send the same 2-fragment sequence
    // the positive uses (a malformed Timestamp option on a non-zero-offset fragment the
    // conformant options parser skips). The input hook synthesizes the prohibited
    // Parameter Problem on the first ICMP-protocol fragment.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthParamProblem);

        // Frag 0 — MF=1, offset=0, well-formed length-12 Timestamp option.
        ::tc8::sce::icmpv4::StimulusOverrides f0{};
        f0.dst_mac         = cfg.arp.dut_iface_mac;
        f0.more_fragments  = true;
        f0.fragment_offset = 0;
        f0.ip_options.assign(::tc8::stimulus::kIcmpv4TimestampOptionLen12.begin(),
                             ::tc8::stimulus::kIcmpv4TimestampOptionLen12.end());
        f0.raw_ip_payload.assign(
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.begin(),
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.begin() + 8);
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, f0);

        // Frag 1 — MF=0, offset=1, malformed length-10 Timestamp option (skipped by the
        // parser because the fragment offset is non-zero).
        ::tc8::sce::icmpv4::StimulusOverrides f1{};
        f1.dst_mac         = cfg.arp.dut_iface_mac;
        f1.more_fragments  = false;
        f1.fragment_offset = 1;
        f1.ip_options.assign(::tc8::stimulus::kIcmpv4TimestampOptionMalformed.begin(),
                             ::tc8::stimulus::kIcmpv4TimestampOptionMalformed.end());
        f1.raw_ip_payload.assign(
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.begin() + 8,
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.end());
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, f1);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Error03NegSM, icmpv4_error_03_neg)
