#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_conflict_10_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfConflict10SM =
    ::SCE::Generated::ipv4_autoconf_conflict_10::ipv4_autoconf_conflict_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfConflict10SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfConflict10SM> {
    static constexpr std::string_view kCaseId =
        "IPV4_AUTOCONF_CONFLICT_10";
    static constexpr std::string_view kSpecSection = "4.5.6.4";
    static constexpr std::string_view kDescription =
        "DUT immediately ceases claim and re-probes after a single "
        "ARP Reply conflict on its committed LL (RFC 3927 §2.5, MAY)";

    // _10 differs from _06..09 by injecting a SINGLE conflict (the
    // RFC 3927 §2.5 MAY-immediate-cease branch). opcode2=0 disables
    // the second emit; the always-cease implementation reaches the
    // re-pick verdict identically.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.arp.dut_real_mac);
        ::tc8::sce::linklocal::scheduleDefenderCeaseConflicts(
            scheduler,
            static_cast<int>(State::Listening_post_claim),
            iface, cfg, c,
            /*opcode1=*/0x0002,  // ARP Reply
            /*opcode2=*/0);      // single-shot — disable second emit
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_claim_observed:
                return "fail:dut_did_not_announce_committed_link_local_address";
            case State::Fail_no_reprobe:
                return "fail:dut_did_not_reprobe_after_conflicting_arp";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfConflict10SM,
                  ipv4_autoconf_conflict_10)
