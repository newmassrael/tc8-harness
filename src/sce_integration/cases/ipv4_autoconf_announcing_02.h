#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_announcing_02_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAnnouncing02SM =
    ::SCE::Generated::ipv4_autoconf_announcing_02::ipv4_autoconf_announcing_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAnnouncing02SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAnnouncing02SM> {
    static constexpr std::string_view kCaseId =
        "IPV4_AUTOCONF_ANNOUNCING_02";
    static constexpr std::string_view kSpecSection = "4.5.6.3";
    static constexpr std::string_view kDescription =
        "DUT-emitted ARP Announcement has sender_proto_ip == "
        "target_proto_ip == announced link-local address (RFC 3927 "
        "§2.4, MUST)";

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
            case State::Fail_announce_sender_target_ip_mismatch:
                return "fail:dut_arp_announce_sender_target_ip_not_announced_ll";
            case State::Fail_no_announce_after_probes:
                return "fail:no_arp_announce_after_probes";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAnnouncing02SM,
                  ipv4_autoconf_announcing_02)
