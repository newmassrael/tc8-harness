#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_conflict_11_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfConflict11SM =
    ::SCE::Generated::ipv4_autoconf_conflict_11::ipv4_autoconf_conflict_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfConflict11SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfConflict11SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_CONFLICT_11";
    static constexpr std::string_view kDescription =
        "DUT-emitted ARP Reply carrying a Link-Local sender IP "
        "is sent via link-layer broadcast (RFC 3927 §2.5, MUST)";

    // Identical 4-arg shape to ADDRESS_SELECTION_16: emit
    // OpStartLLAutoconf with the fast envelope, then delegate the
    // post-claim observer (UT-query → snapshot → AIFACE-LL Request)
    // to the shared scheduleClaimConditionTesterRequest helper. The
    // DUT's responder unconditionally broadcasts its Reply per
    // RFC 3927 §2.5 last MUST; the SCXML's pass guard checks eth_dst
    // is broadcast alongside the IP / MAC fields.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::linklocal::scheduleClaimConditionTesterRequest(
            scheduler, static_cast<int>(State::Listening_post_claim),
            cfg, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfConflict11SM,
                  ipv4_autoconf_conflict_11)
