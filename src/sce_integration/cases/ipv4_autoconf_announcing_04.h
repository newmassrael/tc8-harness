#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_announcing_04_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAnnouncing04SM =
    ::SCE::Generated::ipv4_autoconf_announcing_04::ipv4_autoconf_announcing_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAnnouncing04SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAnnouncing04SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ANNOUNCING_04";
    static constexpr std::string_view kDescription =
        "DUT-emitted ARP Announcement has ARP target_hw = all zeroes "
        "(RFC 3927 §2.4, SHOULD)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAnnouncing04SM,
                  ipv4_autoconf_announcing_04)
