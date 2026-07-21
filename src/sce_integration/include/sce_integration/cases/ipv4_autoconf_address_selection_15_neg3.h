#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_15_neg3_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection15Neg3SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_15_neg3::ipv4_autoconf_address_selection_15_neg3;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// The stale post-silence Probe is the violation; the SCXML's wait_repick
// observes it directly, so no 11th conflict is needed and the inherited
// base dispatch (no post-silence branch) is exactly right.
template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection15Neg3SM>
    : LinklocalRepeatedConflictBase<cases::Ipv4AutoconfAddressSelection15Neg3SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_15_NEG3";
    static constexpr std::string_view kDescription =
        "Self-validation of ADDRESS_SELECTION_15 guard 3: tc8-dut "
        "ReprobeStalePostSilence fault-injection re-probes the previous "
        "LL after the rate-limit silence (RFC 3927 §2.2.1)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggyConflict(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kFlavorReprobeStalePostSilence);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection15Neg3SM,
                  ipv4_autoconf_address_selection_15_neg3)
