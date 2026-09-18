#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/cases/dhcpv4_router_option_egress_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_05_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages05SM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_05::
        dhcpv4_client_constructing_messages_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages05SM>
    : Dhcpv4UdpBase<cases::Dhcpv4ClientConstructingMessages05SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_05";
    // Step 9 asks the DUT to originate a UDP datagram to the unused routed
    // address, over the Tier-2 seam — not measurable without UDP control. The
    // DHCP bit is restated because this declaration SHADOWS the one inherited
    // from Dhcpv4AnyBase rather than extending it, and the shared stimulus
    // (`wireRouterOverloadStimulus`) starts the DUT's DHCP client before it ever
    // reaches step 9. Naming only the UDP half made the gate look satisfied on a
    // backend with UDP control and no DHCP client control, which is worse than
    // declaring nothing: the case ran and could never get a Discover.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapUdpControl | ::tc8::sce::kCapDhcpClientControl;
    static constexpr std::string_view kDescription =
        "DUT parses Option Overload value=2 (sname holds options) and "
        "applies Option 3 (Router) so post-BOUND UDP egress to "
        "IP-UNUSED-ADDRESS uses the gateway as L2 next-hop "
        "(RFC 2132 §9.3 + RFC 2131 §3.5/§4.1, MUST)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        // CM_05: Option 52 = 2 → sname holds options. The same
        // Option 3 (Router) TLV mirrors onto OFFER and ACK so the
        // DUT extracts Router from whichever lifecycle reply it
        // sees first.
        cases::router_option_egress::wireRouterOverloadStimulus<SM>(
            c, cfg, iface, dut, scheduler,
            /*option_52_overload=*/2U,
            /*sname_payload=*/cases::router_option_egress::buildOption3RouterPayload(),
            /*file_payload=*/{});
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages05SM,
                  dhcpv4_client_constructing_messages_05)
