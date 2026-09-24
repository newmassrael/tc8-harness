#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_32_neg2_sm.h"

namespace tc8::sce::cases {

using Arp32Neg2SM = ::SCE::Generated::arp_32_neg2::arp_32_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// UDP-only dispatch, unlike its ARP_32_NEG sibling: this case's envelope listens for
// the egress MAC alone, so its generated Event enum carries no Arp_observed and the
// ArpAnyBase dispatch would not compile against it. ArpIngressFaultNegUdpBase exists
// for exactly that shape and declares the same two seam bits.
template <>
struct TestCaseTraits<cases::Arp32Neg2SM>
    : ArpIngressFaultNegUdpBase<cases::Arp32Neg2SM> {
    static constexpr std::string_view kCaseId      = "ARP_32_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_32's stale-MAC guard: kArpFaultIgnoreUpdate swallows "
        "only the SECOND teaching Request, so the first MAC survives and the DUT "
        "addresses its egress to it; a conformant DUT uses the second";
    // Same two teachings as the positive. The flavor is gated on the sender IP being
    // ALREADY held, so the first Request lands and only the second is swallowed —
    // which is why this proves a different final from its ARP_32_NEG sibling.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         std::string_view iface, ::tc8::sce::IDutControl &dut) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kArpFaultIgnoreUpdate);
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

        emitArpEgressProvocation(dut, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp32Neg2SM, arp_32_neg2)
