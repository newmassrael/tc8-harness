#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "arp_08_neg_sm.h"

namespace tc8::sce::cases {

using Arp08NegSM = ::SCE::Generated::arp_08_neg::arp_08_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp08NegSM>
    : ArpEgressFaultNegBase<cases::Arp08NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_08_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_08: the lwIP ArpFaultHwTypeWrong egress "
        "flavor corrupts the Hardware Type of the DUT's ARP Request "
        "(RFC 826 Ethernet 0x0001); a conformant DUT emits 0x0001";
    // Arm the egress fault, then drive the UT 0x02 egress provocation the
    // positive uses so the lwIP DUT emits a (corrupted) cache-miss Request.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorRequestProvocation(cfg, iface, ::tc8::ut::kArpFaultHwTypeWrong);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp08NegSM, arp_08_neg)
