#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_05_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection05NegSM =
    ::SCE::Generated::ipv4_autoconf_address_selection_05_neg::ipv4_autoconf_address_selection_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection05NegSM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAddressSelection05NegSM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_05_NEG";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "Self-validation of _05: tc8-dut SenderHwWrong fault-"
        "injection drives sender_hw to a non-DUT MAC (RFC 826 "
        "ar$sha; RFC 3927 §2.2.1)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kFlavorSenderHwWrong);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection05NegSM,
                  ipv4_autoconf_address_selection_05_neg)
