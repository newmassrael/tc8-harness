#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_linklocal_packets_04_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfLinklocalPackets04NegSM =
    ::SCE::Generated::ipv4_autoconf_linklocal_packets_04_neg::ipv4_autoconf_linklocal_packets_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfLinklocalPackets04NegSM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfLinklocalPackets04NegSM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_LINKLOCAL_PACKETS_04_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of _04: tc8-dut ReplyToArbitraryTarget fault-"
        "injection answers an ARP Request for an unclaimed link-local "
        "target (RFC 3927 §2.7)";

    // Same two-Announce gating + arbitrary-target observer as the
    // positive _04; only the stimulus opcode changes to the buggy
    // variant carrying the ReplyToArbitraryTarget flavor.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kFlavorReplyToArbitraryTarget);
        ::tc8::sce::linklocal::scheduleArbitraryTargetTesterRequest(
            scheduler, static_cast<int>(State::Listening_post_claim),
            cfg, iface,
            ::tc8::sce::linklocal::kArbitraryReservedLinkLocalIpBe);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfLinklocalPackets04NegSM,
                  ipv4_autoconf_linklocal_packets_04_neg)
