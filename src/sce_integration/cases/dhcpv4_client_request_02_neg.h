#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_request_02_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientRequest02NegSM =
    ::SCE::Generated::dhcpv4_client_request_02_neg::dhcpv4_client_request_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientRequest02NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientRequest02NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REQUEST_02_NEG";
    static constexpr std::string_view kSpecSection = "4.7.6.8";
    static constexpr std::string_view kDescription =
        "Self-validation of REQUEST_02: tc8-dut writes a WRONG Option 50 "
        "requested-IP in the post-OFFER DHCPREQUEST (RFC 2131 §4.3.2 MUST "
        "carry the offered IP) via the RequestRequestedIpCorrupt firmware "
        "flavor. A conformant client (flavor None) echoes the offered IP, "
        "so the negative's fail_compliant branch is the live conformant-DUT "
        "outcome.";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorRequestRequestedIpCorrupt);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientRequest02NegSM,
                  dhcpv4_client_request_02_neg)
