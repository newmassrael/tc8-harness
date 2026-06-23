#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_10_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection10NegSM =
    ::SCE::Generated::ipv4_autoconf_address_selection_10_neg::ipv4_autoconf_address_selection_10_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection10NegSM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAddressSelection10NegSM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_10_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of _10: tc8-dut probe_min=probe_max=100 ms "
        "drives Probe interval below RFC 3927 §2.2.1 PROBE_MIN-50ms "
        "tolerance window";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFastCadence(
            cfg, iface, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection10NegSM,
                  ipv4_autoconf_address_selection_10_neg)
