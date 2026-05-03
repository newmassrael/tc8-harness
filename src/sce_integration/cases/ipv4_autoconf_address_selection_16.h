#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_16_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection16SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_16::ipv4_autoconf_address_selection_16;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection16SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAddressSelection16SM> {
    static constexpr std::string_view kCaseId =
        "IPV4_AUTOCONF_ADDRESS_SELECTION_16";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "DUT replies to an ARP Request targeting its claimed IPv4 "
        "Link-Local address (RFC 3927 §2.5, MUST)";

    // Stimulus: kick the LL state machine, then delegate the
    // post-claim observer (UT-query → snapshot → AIFACE-LL Request)
    // to the shared scheduleClaimConditionTesterRequest helper.
    // SCXML transitions pre_claim → post_claim on the first DUT
    // Announce; the observer fires on entry and runs the UT-query +
    // ARP-Request emit. Eliminates the wall-time coupling a
    // `schedule(delay,…)` would carry — SCXML's deadline becomes the
    // sole timing promise to the spec. §4.5.6.4 CONFLICT_11 shares
    // the same helper from the AIFACE-LL Request angle of §2.5.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.arp.dut_real_mac);
        ::tc8::sce::linklocal::scheduleClaimConditionTesterRequest(
            scheduler, static_cast<int>(State::Listening_post_claim),
            cfg, iface, c);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_claim_observed:
                return "fail:dut_did_not_announce_committed_link_local_address";
            case State::Fail_no_responder_reply:
                return "fail:dut_did_not_emit_arp_reply_for_claim_address";
            case State::Fail_reply_wrong_fields:
                return "fail:dut_arp_reply_carried_wrong_sender_or_target_ip";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection16SM,
                  ipv4_autoconf_address_selection_16)
