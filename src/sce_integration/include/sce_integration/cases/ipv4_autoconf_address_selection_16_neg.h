#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_16_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection16NegSM =
    ::SCE::Generated::ipv4_autoconf_address_selection_16_neg::ipv4_autoconf_address_selection_16_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection16NegSM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAddressSelection16NegSM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ADDRESS_SELECTION_16_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of _16: tc8-dut ReplySenderIpWrong fault-"
        "injection drives the defending ARP Reply sender_proto_ip to "
        "the iface IP instead of the committed LL (RFC 3927 §2.5)";

    // Same two-phase observer as the positive _16 (UT-query → snapshot
    // → claim-condition Request); only the stimulus opcode changes to
    // the buggy variant carrying the ReplySenderIpWrong flavor.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kFlavorReplySenderIpWrong);
        ::tc8::sce::linklocal::scheduleClaimConditionTesterRequest(
            scheduler, static_cast<int>(State::Listening_post_claim),
            cfg, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection16NegSM,
                  ipv4_autoconf_address_selection_16_neg)
