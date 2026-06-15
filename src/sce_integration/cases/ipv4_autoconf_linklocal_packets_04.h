#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_linklocal_packets_04_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfLinklocalPackets04SM =
    ::SCE::Generated::ipv4_autoconf_linklocal_packets_04::ipv4_autoconf_linklocal_packets_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfLinklocalPackets04SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfLinklocalPackets04SM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_LINKLOCAL_PACKETS_04";
    static constexpr std::string_view kSpecSection = "4.5.6.5";
    static constexpr std::string_view kDescription =
        "DUT does not answer ARP Requests for arbitrary 169.254/16 "
        "addresses it has not claimed (RFC 3927 §2.7, MUST)";

    // Stimulus: kick the LL state machine, then schedule the
    // arbitrary-target ARP Request to fire on Listening_post_claim
    // entry (= after Announce 2). The 2-announce gate matches spec
    // step 8's "(PROBE_MAX*2)+ANNOUNCE_WAIT+ANNOUNCE_INTERVAL" wait
    // — the inject lands strictly after the claim phase has produced
    // both Announces, so the post-claim absence window observes only
    // the DUT's defender behaviour for the arbitrary target.
    //
    // Unlike _16/_11/_NETWORK_PARTITIONS_01 (which use
    // scheduleClaimConditionTesterRequest to query DUT_LL via
    // OpQueryLLAddress), this case skips the UT-query: the SCXML's
    // pass criterion is absence of any DUT-emitted Reply, so the
    // committed LL is not referenced by the guard.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::linklocal::scheduleArbitraryTargetTesterRequest(
            scheduler, static_cast<int>(State::Listening_post_claim),
            cfg, iface,
            ::tc8::sce::linklocal::kArbitraryReservedLinkLocalIpBe);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfLinklocalPackets04SM,
                  ipv4_autoconf_linklocal_packets_04)
