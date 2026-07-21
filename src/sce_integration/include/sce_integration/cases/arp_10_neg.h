#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "arp_10_neg_sm.h"

namespace tc8::sce::cases {

using Arp10NegSM = ::SCE::Generated::arp_10_neg::arp_10_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp10NegSM>
    : ArpEgressFaultNegBase<cases::Arp10NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_10_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_10: the lwIP ArpFaultHwLenWrong egress "
        "flavor corrupts the Hardware Address Length of the DUT's ARP "
        "Request (RFC 826 Ethernet 6); a conformant DUT emits 6";
    // Arm the egress fault, then drive the UT 0x02 egress provocation the
    // positive uses so the lwIP DUT emits a (corrupted) cache-miss Request.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorRequestProvocation(cfg, iface, ::tc8::ut::kArpFaultHwLenWrong);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp10NegSM, arp_10_neg)
