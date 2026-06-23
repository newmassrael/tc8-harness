#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_04_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages04NegSM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_04_neg::dhcpv4_client_constructing_messages_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages04NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientConstructingMessages04NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_04_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of CONSTRUCTING_MESSAGES_04: tc8-dut sources the "
        "post-OFFER DHCPREQUEST from a non-zero IP (RFC 2131 §4.1 requires "
        "src=0 in REQUESTING state) via the RequestSrcNonzero firmware "
        "flavor. A conformant client (flavor None) uses src=0, so the "
        "negative's fail_compliant branch is the live conformant-DUT "
        "outcome.";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorRequestSrcNonzero);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages04NegSM,
                  dhcpv4_client_constructing_messages_04_neg)
