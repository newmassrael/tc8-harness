#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_14_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection14SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_14::ipv4_autoconf_address_selection_14;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection14SM>
    : LinklocalRepeatedConflictBase<cases::Ipv4AutoconfAddressSelection14SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_14";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "DUT rate-limits Probe emissions to one new address per "
        "RATE_LIMIT_INTERVAL after MAX_CONFLICTS=10 conflicts "
        "(RFC 3927 §2.2.1, MUST)";

    // Fast-conflict envelope (rate_limit_interval = 3 s); the
    // repeated-conflict dispatch is inherited from the base.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFastConflict(
            cfg, iface, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection14SM,
                  ipv4_autoconf_address_selection_14)
