#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "arp_12_neg_sm.h"

namespace tc8::sce::cases {

using Arp12NegSM = ::SCE::Generated::arp_12_neg::arp_12_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp12NegSM>
    : ArpFaultNegBase<cases::Arp12NegSM> {
    static constexpr std::string_view kCaseId      = "ARP_12_NEG";
    static constexpr std::string_view kSpecSection = "4.2.4.1";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_12: the lwIP ArpFaultOpcodeWrong egress "
        "flavor corrupts the Operation Code field of the DUT's ARP Request "
        "(RFC 826 OPERATION_REQUEST); a conformant DUT emits opcode 1";
    // Arm the egress fault, then drive the UT 0x02 egress provocation the
    // positive uses so the lwIP DUT emits a (corrupted) cache-miss Request.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitArpFlavorRequestProvocation(cfg, iface, ::tc8::ut::kArpFaultOpcodeWrong);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp12NegSM, arp_12_neg)
