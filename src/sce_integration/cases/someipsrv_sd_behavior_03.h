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
// be answered with a multicast OfferService.
//
// Timing: vsomeip's `last_offer_shorter_half_offer_delay_ago()` reads
// the position within the current main_phase_timer cycle (period =
// cyclic_offer_delay = 2000 ms, anchored at SD startup T_sd). Replies
// multicast iff position ≥ 1000 ms. Stimulus emits the unicast Find at
// kickStimulus+4040 ms; empirical T_sd-T_kick ≈ 440 ms so the Find
// lands at ≈ T_sd+3500 ms = position 1500 ms in cycle 1 (well past
// the 1000 ms threshold). Robust against ±400 ms T_sd jitter — the
// safe Δ range is (-60, 940) ms, and the post-repetition Offer at
// ~T_sd+3075 ms (rep4) is absorbed by Phase 1 for Δ < 765 ms.
//
// Uses the 4-arg `IStimulusScheduler` overload to defer the emit until
// after `kickStimulus` returns; running synchronously inside
// `kickStimulus` would block the harness for ~4 s before the SCXML
// is initialized and the listen window has begun.
template <>
struct TestCaseTraits<cases::SdBehavior03SM>
    : SomeIpSdOnlyBase<cases::SdBehavior03SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_BEHAVIOR_03";
    static constexpr std::string_view kDescription =
        "Unicast Find after >1/2 cyclic_offer_delay → DUT replies with multicast OfferService";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        // Emit at +4040 ms (lands at ~position 1500 ms within
        // cyclic_offer_delay cycle, so vsomeip's
        // last_offer_shorter_half_offer_delay_ago() returns false →
        // multicast reply per SOMEIPSD §6.7.5.2 / SIP_SD_90).
        // Captures iface name + DUT IP by value because the scheduler
        // runs the action on the poll-loop thread long after this
        // function returns.
        const std::string iface_owned(iface);
        const std::uint32_t dut_ip_be = cfg.someip.dut_iface_ip;
        scheduler.schedule(std::chrono::milliseconds(4040),
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
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdBehavior03SM, someipsrv_sd_behavior_03)
