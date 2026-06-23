#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_conflict_11_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfConflict11NegSM =
    ::SCE::Generated::ipv4_autoconf_conflict_11_neg::ipv4_autoconf_conflict_11_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfConflict11NegSM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfConflict11NegSM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_CONFLICT_11_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of CONFLICT_11: tc8-dut ReplyEthDstUnicast "
        "fault-injection sends the defending ARP Reply to a unicast "
        "Ethernet dst instead of broadcast (RFC 3927 §2.5)";

    // Same two-phase observer as the positive CONFLICT_11 (UT-query →
    // snapshot → AIFACE-LL claim-condition Request); only the stimulus
    // opcode changes to the buggy variant carrying ReplyEthDstUnicast.
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

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfConflict11NegSM,
                  ipv4_autoconf_conflict_11_neg)
