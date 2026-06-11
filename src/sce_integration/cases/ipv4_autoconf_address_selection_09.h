#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_09_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection09SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_09::ipv4_autoconf_address_selection_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection09SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAddressSelection09SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_09";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "DUT emits exactly PROBE_NUM=3 ARP Probes during the LL "
        "probing phase (RFC 3927 §2.2.1)";

    // RFC 3927 cadence defaults: PROBE_WAIT 1 s, PROBE_MIN..MAX
    // 1..2 s. Cadence verification cases (_09/_10) intentionally
    // forgo the fast envelope so the assertion measures the
    // spec-mandated rates.
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
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection09SM,
                  ipv4_autoconf_address_selection_09)
