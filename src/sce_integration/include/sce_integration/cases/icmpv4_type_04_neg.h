#pragma once

#include <cstdint>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_icmpv4_traits_base.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "icmpv4_type_04_neg_sm.h"

namespace tc8::sce::cases {

using Icmpv4Type04NegSM = ::SCE::Generated::icmpv4_type_04_neg::icmpv4_type_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of ICMPv4_TYPE_04: a conformant DUT must NOT emit an ICMP Time
// Exceeded (type 11) when a datagram's fragment zero never arrives — the reassembly context
// just times out silently. kIcmpFaultSynthTimeExceeded makes the lwIP netif INPUT hook
// synthesize the prohibited Time Exceeded as the lone offset>0 fragment arrives; the hook reads
// only fixed-offset trigger fields, so the fragment offset is irrelevant and the synthesized
// reply is the only DUT-origin frame. The case passes only when that reply is observed.
// lwIP-only (kCapIngressFault). ReplyType 11 (Time Exceeded) narrows the observed variant.
//
// Unlike the positive, this _neg does NOT defer its listen window (no post_send_wait): the
// synthesis fires on the trigger's arrival, not after a real reassembly timeout, so the
// prohibited reply lands inside the icmpv4_synth_neg envelope's window.
template <>
struct TestCaseTraits<cases::Icmpv4Type04NegSM>
    : Icmpv4IngressFaultNegBase<cases::Icmpv4Type04NegSM, std::uint8_t{11}> {
    static constexpr std::string_view kCaseId      = "ICMPv4_TYPE_04_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ICMPv4_TYPE_04: the lwIP kIcmpFaultSynthTimeExceeded ingress flavor "
        "makes the DUT emit a Time Exceeded for an incomplete reassembly (fragment zero never "
        "arrives); a conformant DUT times out silently";

    // Arm the Time-Exceeded synthesis fault, then send the same lone offset>0 fragment the
    // positive uses (fragment zero never sent). No post_send_wait: the synth fires on arrival.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kIcmpFaultSynthTimeExceeded);
        ::tc8::sce::icmpv4::StimulusOverrides ov{};
        ov.dst_mac         = cfg.arp.dut_iface_mac;
        ov.more_fragments  = false;
        ov.fragment_offset = 1;
        ov.raw_ip_payload.assign(
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.begin() + 8,
            ::tc8::stimulus::kIcmpv4FragmentStimulusPacket.end());
        ::tc8::sce::icmpv4::emitStimulus(cfg, iface, ov);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Icmpv4Type04NegSM, icmpv4_type_04_neg)
