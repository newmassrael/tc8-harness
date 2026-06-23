#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_05_sm.h"

namespace tc8::sce::cases {

using Arp05SM = ::SCE::Generated::arp_05::arp_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp05SM>
    : ArpAnyBase<cases::Arp05SM> {
    static constexpr ::tc8::BpfGroup kBpfGroup = ::tc8::BpfGroup::ArpAndUdp;

    static constexpr std::string_view kCaseId = "ARP_05";
    static constexpr std::string_view kDescription =
        "ARP entry learned on gratuitous ARP Response — DUT must NOT emit an "
        "ARP Request after tester pre-populates the cache via gratuitous Response";
    // Variant of ARP_03's stimulus using a gratuitous ARP Response
    // (opcode 2, sender==target==<tester_ip, kTesterInjectedMac>). Requires
    // `net.ipv4.conf.<dut_iface>.arp_accept=1` on DUT for the kernel to
    // learn from the gratuitous announcement — setup-netns.sh enables it.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::emitArpLearningBoot(iface, cfg.arp.tester_ip, cfg.dut.ip,
                                             ::tc8::stimulus::ArpLearningVariant::GratuitousResponse);
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp05SM, arp_05)
