#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_45_sm.h"

namespace tc8::sce::cases {

using Arp45SM = ::SCE::Generated::arp_45::arp_45;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp45SM>
    : ArpAnyBase<cases::Arp45SM> {
    static constexpr std::string_view kCaseId = "ARP_45";
    static constexpr std::string_view kDescription =
        "ARP Response target_hw sequential check — DUT Reply to each "
        "Request must echo that Request's sender_hw as its target_hw";
    // Two tester ARP Requests with different sender_hw (MAC1, MAC2) for
    // the same tester_ip. `emitArpFromTester`'s default 200 ms settle
    // wait between calls gives Linux ample time to emit the first Reply
    // before the second Request hits — order of wire events is therefore
    // deterministic: Req1 → Resp1 → Req2 → Resp2. SCXML walks the two
    // Response events sequentially.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec1;
        spec1.opcode = 0x0001;  // Request
        spec1.sender_hw = ::tc8::stimulus::kTesterInjectedMac;
        spec1.eth_src = ::tc8::stimulus::kTesterInjectedMac;
        spec1.sender_ip_be = cfg.arp.tester_ip;
        spec1.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec1);

        ::tc8::stimulus::ArpFrameSpec spec2;
        spec2.opcode = 0x0001;  // Request
        spec2.sender_hw = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.eth_src = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.sender_ip_be = cfg.arp.tester_ip;
        spec2.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp45SM, arp_45)
