#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_15_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection15NegSM =
    ::SCE::Generated::ipv4_autoconf_address_selection_15_neg::ipv4_autoconf_address_selection_15_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Guard 1 (stale re-probe) is detected during the cycle, so the inherited
// base dispatch (no post-silence branch) is exactly right.
template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection15NegSM>
    : LinklocalRepeatedConflictBase<cases::Ipv4AutoconfAddressSelection15NegSM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_15_NEG";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "Self-validation of ADDRESS_SELECTION_15 guard 1: tc8-dut "
        "ReprobeStaleCycle fault-injection re-probes the stale LL on "
        "conflict instead of a fresh address (RFC 3927 §2.2.1)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggyConflict(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kFlavorReprobeStaleCycle);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection15NegSM,
                  ipv4_autoconf_address_selection_15_neg)
