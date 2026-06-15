#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "arp_07_sm.h"

namespace tc8::sce::cases {

using Arp07SM = ::SCE::Generated::arp_07::arp_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp07SM>
    : ArpAnyBase<cases::Arp07SM> {
    static constexpr std::string_view kCaseId       = "ARP_07";
    static constexpr std::string_view kSpecSection  = "4.2.4.1";
    static constexpr std::string_view kDescription  =
        "ARP request sending — DUT broadcasts an ARP Request when its cache "
        "lacks the destination's entry";
    // Provoke a unicast UDP egress from the DUT — UT 0x02
    // OpTriggerSendUdp is the literal rendering of the spec's "DUT
    // CONFIGURE: Configure DUT to send a UDP Message from <DIface-0>
    // (src=<DIface-0-IP>, dst=<HOST-1-IP>)" step shared by every
    // §4.2.4 egress bucket. (Until 2026-06 this was a SubscribeEventgroup
    // → Nack substitute that predated the UT UDP opcodes.) With
    // setup-netns.sh having flushed the DUT's neigh table, the UT
    // response + triggered datagram's unicast reply path forces an ARP
    // Request before any UDP egress.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp07SM, arp_07)
