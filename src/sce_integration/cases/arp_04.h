#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_04_sm.h"

namespace tc8::sce::cases {

using Arp04SM = ::SCE::Generated::arp_04::arp_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp04SM>
    : ArpAndUdpBase<cases::Arp04SM> {
    static constexpr std::string_view kCaseId = "ARP_04";
    static constexpr std::string_view kSpecSection = "4.2.4.1";
    static constexpr std::string_view kDescription =
        "ARP entry used for UDP egress after ARP Request learning — DUT must "
        "emit UDP to tester_ip carrying Ethernet destination = tester_mac";
    // Same two-phase stimulus as ARP_03 — the only difference is the pass
    // criterion: ARP_03 checks absence of DUT ARP Request, ARP_04 also
    // verifies the subsequent UDP's Ethernet destination.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::emitArpLearningBoot(iface, cfg.arp.tester_ip, cfg.dut.ip,
                                             ::tc8::stimulus::ArpLearningVariant::Request);
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp04SM, arp_04)
