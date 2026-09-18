#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/cases/dhcpv4_router_option_egress_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_06_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages06SM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_06::
        dhcpv4_client_constructing_messages_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages06SM>
    : Dhcpv4UdpBase<cases::Dhcpv4ClientConstructingMessages06SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_06";
    // Step 9 asks the DUT to originate a UDP datagram to the unused routed
    // address, over the Tier-2 seam — not measurable without UDP control. As
    // CM_05: the DHCP bit is restated because this declaration SHADOWS
    // Dhcpv4AnyBase's rather than extending it, and the shared stimulus starts
    // the DUT's DHCP client long before step 9.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapUdpControl | ::tc8::sce::kCapDhcpClientControl;
    static constexpr std::string_view kDescription =
        "DUT parses Option Overload value=1 (file holds options) and "
        "applies Option 3 (Router) so post-BOUND UDP egress to "
        "IP-UNUSED-ADDRESS uses the gateway as L2 next-hop "
        "(RFC 2132 §9.3 + RFC 2131 §3.5/§4.1, MUST)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        // CM_06: Option 52 = 1 → file holds options. Wire envelope
        // identical to CM_05 except for which BOOTP fixed region
        // carries the Option 3 (Router) TLV.
        cases::router_option_egress::wireRouterOverloadStimulus<SM>(
            c, cfg, iface, dut, scheduler,
            /*option_52_overload=*/1U,
            /*sname_payload=*/{},
            /*file_payload=*/cases::router_option_egress::buildOption3RouterPayload());
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages06SM,
                  dhcpv4_client_constructing_messages_06)
