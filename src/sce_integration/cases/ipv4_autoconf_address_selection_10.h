#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_10_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection10SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_10::ipv4_autoconf_address_selection_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection10SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAddressSelection10SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_10";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "DUT-emitted ARP Probe inter-frame interval is in "
        "[PROBE_MIN-50 ms, PROBE_MAX+50 ms] (RFC 3927 §2.2.1)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfRfcDefaults(
            cfg, iface, cfg.dut.mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_probes:
                return "fail:no_arp_probe_after_ll_start";
            case State::Fail_too_few_probes:
                return "fail:fewer_than_3_arp_probes_within_deadline";
            case State::Fail_interval_out_of_range:
                return "fail:probe_interval_outside_rfc3927_bounds";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection10SM,
                  ipv4_autoconf_address_selection_10)
