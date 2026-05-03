#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

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
    // Provoke a unicast UDP egress from the DUT — a SubscribeEventgroup
    // gets unicast-Nacked back to the tester (tc8-dut has no matching
    // eventgroups) and that Nack is the smallest, most reliable trigger
    // available without a new builder. We deliberately do NOT use the
    // FindService stimulus: vsomeip drops SD messages with non-30490
    // source ports ("Ignored SD message from unknown port") and the
    // FindService emitter binds an ephemeral port, so the DUT never
    // schedules a solicited reply. The Subscribe emitter binds to port
    // 30490 and is therefore accepted; with setup-netns.sh having
    // flushed the DUT's neigh table, the Nack's unicast reply path
    // forces an ARP Request before any UDP egress.
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
            case State::Fail_opcode:  return "fail:first_arp_was_not_request";
            case State::Fail_timeout: return "fail:no_arp_request_within_listen_window";
            default:                  return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp07SM, arp_07)
