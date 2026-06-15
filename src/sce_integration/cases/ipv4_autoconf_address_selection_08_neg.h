#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_08_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection08NegSM =
    ::SCE::Generated::ipv4_autoconf_address_selection_08_neg::ipv4_autoconf_address_selection_08_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection08NegSM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAddressSelection08NegSM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_08_NEG";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "Self-validation of _08: tc8-dut TargetOutsidePrefix fault-"
        "injection drives target_proto_ip to 192.168.1.66 "
        "(RFC 3927 §2.1 MUST 169.254/16)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kFlavorTargetOutsidePrefix);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection08NegSM,
                  ipv4_autoconf_address_selection_08_neg)
