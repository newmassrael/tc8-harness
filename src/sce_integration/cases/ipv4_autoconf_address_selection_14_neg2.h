#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_14_neg2_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection14Neg2SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_14_neg2::ipv4_autoconf_address_selection_14_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection14Neg2SM>
    : LinklocalRepeatedConflictBase<cases::Ipv4AutoconfAddressSelection14Neg2SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_14_NEG2";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "Self-validation of ADDRESS_SELECTION_14 guard 2: tc8-dut "
        "SkipFirstRateLimitSilence fault-injection emits a Probe during "
        "the rate-limit silence window (RFC 3927 §2.2.1)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggyConflict(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kFlavorSkipFirstRateLimitSilence);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection14Neg2SM,
                  ipv4_autoconf_address_selection_14_neg2)
