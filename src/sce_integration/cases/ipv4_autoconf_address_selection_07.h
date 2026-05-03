#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_07_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection07SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_07::ipv4_autoconf_address_selection_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection07SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAddressSelection07SM> {
    static constexpr std::string_view kCaseId =
        "IPV4_AUTOCONF_ADDRESS_SELECTION_07";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "DUT-emitted ARP Probe carries target_hw = NULL_MAC (six "
        "zero octets) (RFC 3927 §2.2.1, SHOULD)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.arp.dut_real_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_target_hw_not_zero:
                return "fail:probe_target_hw_not_null_mac";
            case State::Fail_timeout:
                return "fail:no_arp_probe_after_ll_start";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection07SM,
                  ipv4_autoconf_address_selection_07)
