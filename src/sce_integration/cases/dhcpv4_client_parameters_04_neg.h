#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_parameters_04_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientParameters04NegSM =
    ::SCE::Generated::dhcpv4_client_parameters_04_neg::dhcpv4_client_parameters_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientParameters04NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientParameters04NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_PARAMETERS_04_NEG";
    static constexpr std::string_view kSpecSection = "4.7.6.5";
    static constexpr std::string_view kDescription =
        "Self-validation of PARAMETERS_04: tc8-dut corrupts one Option 55 "
        "byte in the post-OFFER DHCPREQUEST (RFC 2131 §4.3.6 MUST repeat the "
        "DISCOVER's Parameter Request List) via the RequestParamListMismatch "
        "firmware flavor. A conformant client (flavor None) repeats the list, "
        "so the negative's fail_compliant branch is the live conformant-DUT "
        "outcome.";

    // Conformant DISCOVER (the flavor is gated to the SELECTING REQUEST),
    // DISCOVER snapshot on Listening_for_request entry, tester OFFER, then
    // the DUT emits the Option-55-corrupted REQUEST the guard catches.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorRequestParamListMismatch);
        ::tc8::sce::dhcpv4::scheduleDiscoverSnapshotOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request), c);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientParameters04NegSM,
                  dhcpv4_client_parameters_04_neg)
