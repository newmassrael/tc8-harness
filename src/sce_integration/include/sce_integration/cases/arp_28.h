#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_28_sm.h"

namespace tc8::sce::cases {

using Arp28SM = ::SCE::Generated::arp_28::arp_28;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp28SM>
    : ArpAndUdpBase<cases::Arp28SM> {
    static constexpr std::string_view kCaseId = "ARP_28";
    static constexpr std::string_view kDescription =
        "Gratuitous ARP Response with unknown proto_type — DUT must drop "
        "and emit its own ARP Request on subsequent UDP egress";
    // Variant of ARP_22: RFC 826 §2.3 step 2 ("Do I speak the protocol in
    // ar$pro?") drops the frame when proto_type is 0xFFFF.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.proto_type = 0xFFFF;  // ARP_PROTOCOL_UNKNOWN
        spec.opcode = 0x0002;      // Response
        spec.target_hw = ::tc8::stimulus::kEthBroadcast;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.arp.tester_ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec);
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp28SM, arp_28)
