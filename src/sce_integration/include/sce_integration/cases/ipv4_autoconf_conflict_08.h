#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_conflict_08_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfConflict08SM =
    ::SCE::Generated::ipv4_autoconf_conflict_08::ipv4_autoconf_conflict_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfConflict08SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfConflict08SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_CONFLICT_08";
    static constexpr std::string_view kDescription =
        "DUT ceases claim and re-probes after Request+Reply "
        "conflicts on its committed LL (RFC 3927 §2.5, MUST)";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(ctx.dut);
        ::tc8::sce::linklocal::scheduleDefenderCeaseConflicts(
            ctx.scheduler,
            static_cast<int>(State::Listening_post_claim),
            ctx.iface, cfg, ctx.dut, c,
            /*opcode1=*/0x0001,  // ARP Request
            /*opcode2=*/0x0002); // ARP Reply
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfConflict08SM,
                  ipv4_autoconf_conflict_08)
