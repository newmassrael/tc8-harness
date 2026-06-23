#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_05_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation05NegSM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_05_neg::dhcpv4_client_initialization_allocation_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation05NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientInitializationAllocation05NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_05_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of INIT_ALLOC_05: tc8-dut accepts a lone DHCPACK "
        "(no preceding OFFER) and emits a DHCPREQUEST (RFC 2131 §4.4.1 MUST "
        "silently discard) via the ProceedOnLoneAck firmware flavor. A "
        "conformant client (flavor None) stays silent, so the negative's "
        "fail_compliant_silence branch is the live conformant-DUT outcome.";

    // Conformant DISCOVER, then a single lone ACK (message_type=5, no
    // preceding OFFER) injected on Listening_for_request entry; the buggy DUT
    // proceeds to the prohibited REQUEST the guard catches.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorProceedOnLoneAck);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/5);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation05NegSM,
                  dhcpv4_client_initialization_allocation_05_neg)
