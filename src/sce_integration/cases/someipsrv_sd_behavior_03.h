#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_behavior_03_sm.h"

namespace tc8::sce::cases {

using SdBehavior03SM =
    ::SCE::Generated::someipsrv_sd_behavior_03::someipsrv_sd_behavior_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.4.3 SOMEIPSRV_SD_BEHAVIOR_03: Server Answer Behavior —
// when more than ½ CYCLIC_OFFER_DELAY has elapsed since the last
// emitted OfferService, a unicast FindService (Unicast Flag = 1) shall
// be answered with a multicast OfferService. Stimulus schedules the
// unicast Find emit at +4500 ms (TOTAL_REP_INTV + 1 cyclic + ½ cyclic
// against the vsomeip default config), satisfying the "last Offer >
// ½ CYCLIC ago" precondition before the Find lands.
//
// Uses the 4-arg `IStimulusScheduler` overload to defer the emit until
// after `kickStimulus` returns; running synchronously inside
// `kickStimulus` would block the harness for ~4.5 s before the SCXML
// is initialized and the listen window has begun.
template <>
struct TestCaseTraits<cases::SdBehavior03SM>
    : SomeIpSdOnlyBase<cases::SdBehavior03SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_BEHAVIOR_03";
    static constexpr std::string_view kSpecSection = "5.1.5.4.3";
    static constexpr std::string_view kDescription =
        "Unicast Find after >1/2 cyclic_offer_delay → DUT replies with multicast OfferService";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        // Emit at +4500 ms = TOTAL_REP_INTV (~1.5 s) + 1× CYCLIC (~2 s)
        // + ½× CYCLIC (~1 s). Captures the iface name + DUT IP by value
        // because the scheduler runs the action on the poll-loop thread
        // long after this function returns.
        const std::string iface_owned(iface);
        const std::uint32_t dut_ip_be = cfg.someip.dut_iface_ip;
        scheduler.schedule(std::chrono::milliseconds(4500),
                           [iface_owned, dut_ip_be]() {
            // Unicast FindService (Unicast Flag = 1, the default 0xC0
            // sd_flags value carrying Reboot=1 + Unicast=1) addressed to
            // the DUT's SD endpoint.
            ::tc8::stimulus::FindServiceParams p{};
            p.session_id = 0x0001;
            p.sd_flags = 0xC0;
            const auto bytes = ::tc8::stimulus::buildFindService(p);
            ::tc8::stimulus::sendSdUnicast(bytes, iface_owned, dut_ip_be);
        });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                  return "pass";
            case State::Fail_offer_not_multicast:              return "fail:offer_dst_ip_not_multicast_after_unicast_find";
            case State::Fail_no_offer_after_unicast_find:      return "fail:no_offer_within_listen_window_after_unicast_find";
            default:                                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdBehavior03SM, someipsrv_sd_behavior_03)
