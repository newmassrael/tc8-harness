#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_network_partitions_01_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfNetworkPartitions01NegSM =
    ::SCE::Generated::ipv4_autoconf_network_partitions_01_neg::ipv4_autoconf_network_partitions_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfNetworkPartitions01NegSM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfNetworkPartitions01NegSM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_NETWORK_PARTITIONS_01_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of NETWORK_PARTITIONS_01 guard 1 (defending "
        "Reply): tc8-dut ReplyEthDstUnicast fault-injection sends the "
        "Reply to a unicast Ethernet dst instead of broadcast "
        "(RFC 3927 §2.5)";

    // Same claim-condition wiring as the positive NETWORK_PARTITIONS_01
    // (and CONFLICT_11 / ADDRESS_SELECTION_16): the post-claim observer
    // queries the committed LL, snapshots it, and emits the AIFACE-LL
    // Request; only the stimulus opcode changes to the buggy variant
    // carrying ReplyEthDstUnicast. This _neg proves guard 1
    // (fail_reply_wrong_fields) is reachable; NEG2 proves guard 2.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kFlavorReplyEthDstUnicast);
        ::tc8::sce::linklocal::scheduleClaimConditionTesterRequest(
            scheduler, static_cast<int>(State::Listening_post_claim),
            cfg, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfNetworkPartitions01NegSM,
                  ipv4_autoconf_network_partitions_01_neg)
