#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_network_partitions_01_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfNetworkPartitions01SM =
    ::SCE::Generated::ipv4_autoconf_network_partitions_01::ipv4_autoconf_network_partitions_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfNetworkPartitions01SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfNetworkPartitions01SM> {
    static constexpr std::string_view kCaseId =
        "IPV4_AUTOCONF_NETWORK_PARTITIONS_01";
    static constexpr std::string_view kSpecSection = "4.5.6.6";
    static constexpr std::string_view kDescription =
        "DUT does not emit periodic gratuitous ARPs for its claimed "
        "link-local address (RFC 3927 §4, SHOULD)";

    // Stimulus: kick the LL state machine, then schedule the
    // claim-condition AIFACE-LL Request to fire on Listening_post_claim
    // entry (= after Announce 2). The 2-announce gate matches spec
    // step 8's "ANNOUNCE_WAIT+ANNOUNCE_INTERVAL" wait — both Announces
    // must have flown before the absence-of-gratuitous window opens,
    // because Announces share the gratuitous-shape filter and would
    // otherwise false-fail.
    //
    // Reuses scheduleClaimConditionTesterRequest (the §4.5.6.2 _16 /
    // §4.5.6.4 _11 helper) verbatim: UT-query for DUT_LL → snapshot
    // into c.expected_responder_sender_ip_be → emit AIFACE-LL Request
    // targeting DUT_LL. The DUT's responder broadcasts the Reply per
    // RFC 3927 §2.5 last MUST; the SCXML's listening_post_claim guard
    // is the same broadcast-Reply contract _16/_11 assert. Once the
    // Reply lands, the SCXML transitions to listening_no_periodic
    // where the absence window verifies the §4 SHOULD on periodic
    // gratuitous ARPs.
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
            case State::Fail_only_one_announce:
                return "fail:fewer_than_2_arp_announces_within_deadline";
            case State::Fail_no_responder_reply:
                return "fail:dut_did_not_emit_arp_reply_for_claim_address";
            case State::Fail_reply_wrong_fields:
                return "fail:dut_arp_reply_carried_wrong_fields_or_unicast_eth_dst";
            case State::Fail_periodic_gratuitous_arp:
                return "fail:dut_emitted_periodic_gratuitous_arp_for_committed_link_local";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfNetworkPartitions01SM,
                  ipv4_autoconf_network_partitions_01)
