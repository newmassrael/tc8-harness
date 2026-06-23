#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_conflict_07_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfConflict07SM =
    ::SCE::Generated::ipv4_autoconf_conflict_07::ipv4_autoconf_conflict_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfConflict07SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfConflict07SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_CONFLICT_07";
    static constexpr std::string_view kDescription =
        "DUT ceases claim and re-probes after two ARP Reply "
        "conflicts on its committed LL (RFC 3927 §2.5, MUST)";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::linklocal::scheduleDefenderCeaseConflicts(
            scheduler,
            static_cast<int>(State::Listening_post_claim),
            iface, cfg, c,
            /*opcode1=*/0x0002,  // ARP Reply
            /*opcode2=*/0x0002); // ARP Reply
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfConflict07SM,
                  ipv4_autoconf_conflict_07)
