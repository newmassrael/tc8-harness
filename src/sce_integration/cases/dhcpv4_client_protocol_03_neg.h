#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_protocol_03_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientProtocol03NegSM =
    ::SCE::Generated::dhcpv4_client_protocol_03_neg::dhcpv4_client_protocol_03_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientProtocol03NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientProtocol03NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_PROTOCOL_03_NEG";
    static constexpr std::string_view kSpecSection = "4.7.6.2";
    static constexpr std::string_view kDescription =
        "Self-validation of PROTOCOL_03: tc8-dut drops Option 53 from the "
        "post-OFFER DHCPREQUEST (RFC 2131 §3 MUST carry the Message Type) via "
        "the RequestOmitMessageType firmware flavor. A conformant client "
        "(flavor None) emits Option 53, so the negative's fail_compliant "
        "branch is the live conformant-DUT outcome.";

    // Conformant DISCOVER (the flavor is gated to the SELECTING REQUEST),
    // tester OFFER on Listening_for_request entry, then the DUT emits the
    // Option-53-less REQUEST the guard catches.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorRequestOmitMessageType);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientProtocol03NegSM,
                  dhcpv4_client_protocol_03_neg)
