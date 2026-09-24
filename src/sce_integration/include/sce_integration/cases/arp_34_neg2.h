#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"

#include "arp_34_neg2_sm.h"

namespace tc8::sce::cases {

using Arp34Neg2SM = ::SCE::Generated::arp_34_neg2::arp_34_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// UDP-only dispatch, for the same reason as the Request/Request stale-MAC negative: the
// stale-MAC envelope listens for the egress MAC alone, so the generated Event enum carries
// no Arp_observed and the ArpAnyBase dispatch would not compile against it.
template <>
struct TestCaseTraits<cases::Arp34Neg2SM>
    : ArpFaultNegUdpBase<cases::Arp34Neg2SM, ::tc8::sce::kCapIngressFault> {
    static constexpr std::string_view kCaseId      = "ARP_34_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_34's stale-MAC guard: kArpFaultIgnoreGratuitous swallows "
        "the gratuitous Response that would have carried the second MAC, so the first "
        "survives and the DUT addresses its egress to it; a conformant DUT uses the second";
    // The positive's stimulus, unchanged: a teaching Request then a gratuitous Response.
    // The Request lands (this flavour is opcode-2 gated, the mirror of the Request/Request
    // stale-MAC negative's) and only the Response is swallowed, which is why this proves a
    // different final from its ARP_34_NEG sibling.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         std::string_view iface, ::tc8::sce::IDutControl &dut) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kArpFaultIgnoreGratuitous);
        ::tc8::stimulus::ArpFrameSpec spec1;
        spec1.opcode = 0x0001;  // Request
        spec1.sender_hw = ::tc8::stimulus::kTesterInjectedMac;
        spec1.eth_src = ::tc8::stimulus::kTesterInjectedMac;
        spec1.sender_ip_be = cfg.arp.tester_ip;
        spec1.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec1);

        ::tc8::stimulus::ArpFrameSpec spec2;
        spec2.opcode = 0x0002;  // gratuitous Response
        spec2.sender_hw = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.eth_src = ::tc8::stimulus::kTesterInjectedMac2;
        spec2.target_hw = ::tc8::stimulus::kEthBroadcast;
        spec2.sender_ip_be = cfg.arp.tester_ip;
        spec2.target_ip_be = cfg.arp.tester_ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec2);

        emitArpEgressProvocation(dut, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp34Neg2SM, arp_34_neg2)
