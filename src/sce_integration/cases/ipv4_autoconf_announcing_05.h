#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_announcing_05_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAnnouncing05SM =
    ::SCE::Generated::ipv4_autoconf_announcing_05::ipv4_autoconf_announcing_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAnnouncing05SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAnnouncing05SM> {
    static constexpr std::string_view kCaseId =
        "IPV4_AUTOCONF_ANNOUNCING_05";
    static constexpr std::string_view kSpecSection = "4.5.6.3";
    static constexpr std::string_view kDescription =
        "DUT broadcasts ANNOUNCE_NUM (= 2) ARP Announcements after the "
        "Probe phase (RFC 3927 §2.4, MUST)";

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
            case State::Fail_no_announces:
                return "fail:no_arp_announce_after_probes";
            case State::Fail_only_one_announce:
                return "fail:fewer_than_2_arp_announces_within_deadline";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAnnouncing05SM,
                  ipv4_autoconf_announcing_05)
