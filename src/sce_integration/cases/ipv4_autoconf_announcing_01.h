#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_announcing_01_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAnnouncing01SM =
    ::SCE::Generated::ipv4_autoconf_announcing_01::ipv4_autoconf_announcing_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAnnouncing01SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAnnouncing01SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ANNOUNCING_01";
    static constexpr std::string_view kSpecSection = "4.5.6.3";
    static constexpr std::string_view kDescription =
        "DUT-emitted ARP Announcement has Ethernet destination = "
        "broadcast (RFC 3927 §2.4, MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_announce_eth_dst_not_broadcast:
                return "fail:dut_arp_announce_eth_dst_not_broadcast";
            case State::Fail_no_announce_after_probes:
                return "fail:no_arp_announce_after_probes";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAnnouncing01SM,
                  ipv4_autoconf_announcing_01)
