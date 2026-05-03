#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "arp_12_sm.h"

namespace tc8::sce::cases {

using Arp12SM = ::SCE::Generated::arp_12::arp_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp12SM>
    : ArpAnyBase<cases::Arp12SM> {
    static constexpr std::string_view kCaseId       = "ARP_12";
    static constexpr std::string_view kSpecSection  = "4.2.4.1";
    static constexpr std::string_view kDescription  =
        "ARP request Operation Code field shall carry OPERATION_REQUEST (1)";
    // Subscribe-Nack stimulus to provoke DUT unicast egress — see arp_07.h.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface,
            ::tc8::stimulus::SubscribeEventgroupTarget{},
            cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:         return "pass";
            case State::Fail_opcode:  return "fail:opcode_not_request";
            case State::Fail_timeout: return "fail:no_arp_request_within_listen_window";
            default:                  return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp12SM, arp_12)
