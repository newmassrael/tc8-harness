#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_04_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation04NegSM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_04_neg::dhcpv4_client_initialization_allocation_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation04NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientInitializationAllocation04NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_04_NEG";
    static constexpr std::string_view kSpecSection = "4.7.6.9";
    static constexpr std::string_view kDescription =
        "Self-validation of INIT_ALLOC_04: tc8-dut accepts a mismatched-xid "
        "DHCPOFFER and emits a DHCPREQUEST (RFC 2131 §4.4.1 MUST silently "
        "discard) via the AcceptMismatchedXidOffer firmware flavor. A "
        "conformant client (flavor None) stays silent, so the negative's "
        "fail_compliant_silence branch is the live conformant-DUT outcome.";

    // Conformant DISCOVER, then a single OFFER with xid = DISCOVER.xid + 1
    // (xid_offset=1, the positive's mismatched stimulus) injected on
    // Listening_for_request entry; the buggy DUT proceeds to the prohibited
    // REQUEST the guard catches.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorAcceptMismatchedXidOffer);
        ::tc8::sce::dhcpv4::ServerEmulParams mismatched{};
        mismatched.xid_offset = 1;
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2, mismatched);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation04NegSM,
                  dhcpv4_client_initialization_allocation_04_neg)
