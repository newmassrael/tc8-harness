#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "arp_13_sm.h"

namespace tc8::sce::cases {

using Arp13SM = ::SCE::Generated::arp_13::arp_13;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp13SM>
    : ArpAnyBase<cases::Arp13SM> {
    static constexpr std::string_view kCaseId       = "ARP_13";
    static constexpr std::string_view kSpecSection  = "4.2.4.1";
    static constexpr std::string_view kDescription  =
        "ARP request Sender Hardware Address shall carry the configured DIface-0 MAC";
    // UT 0x02 egress-provocation stimulus — see arp_07.h.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitArpEgressProvocation(cfg, iface, cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:            return "pass";
            case State::Fail_sender_hw:  return "fail:sender_hw_addr_not_dut_iface";
            case State::Fail_timeout:    return "fail:no_arp_request_within_listen_window";
            default:                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp13SM, arp_13)
