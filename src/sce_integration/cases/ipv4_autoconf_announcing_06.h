#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_announcing_06_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAnnouncing06SM =
    ::SCE::Generated::ipv4_autoconf_announcing_06::ipv4_autoconf_announcing_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAnnouncing06SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAnnouncing06SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ANNOUNCING_06";
    static constexpr std::string_view kSpecSection = "4.5.6.3";
    static constexpr std::string_view kDescription =
        "Time interval between consecutive ARP Announcements is in "
        "[ANNOUNCE_INTERVAL - 50 ms, ANNOUNCE_INTERVAL + 50 ms] "
        "(RFC 3927 §2.4, MUST)";

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
            case State::Fail_no_announces:
                return "fail:no_arp_announce_after_probes";
            case State::Fail_only_one_announce:
                return "fail:fewer_than_2_arp_announces_within_deadline";
            case State::Fail_interval_out_of_range:
                return "fail:announce_interval_outside_rfc3927_bounds_with_50ms_tolerance";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAnnouncing06SM,
                  ipv4_autoconf_announcing_06)
