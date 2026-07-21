#pragma once

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
// multicast iff position ≥ 1000 ms. A fixed wall-clock emit offset lands
// at an unknown cycle position once the DUT's SD timer skews under CPU
// contention, drawing a (correct-for-that-input) unicast reply — a
// harness-timing false fail. So the emit is CADENCE-RELATIVE: the SCXML
// waits into the main phase, observes one cyclic OfferService (the
// anchor), holds ½ cyclic + 300 ms, and only then enters
// `listening_offer_reply`. This trait emits the unicast Find on entry to
// that state — so the Find lands >½ cyclic after the DUT's own last
// offer and before its next one, whatever the timer skew.
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
        // Fire the Find on entry to `listening_offer_reply`, which the SCXML
        // reaches exactly 1300 ms (½ cyclic + margin) after it observes the
        // anchor cyclic offer — so the anchor delay is a real SCXML timing
        // promise, not a magic constant this trait measures. Captures iface
        // name + DUT IP by value because the observer runs on the poll-loop
        // thread long after this function returns.
        const std::string iface_owned(iface);
        const std::uint32_t dut_ip_be = cfg.someip.dut_iface_ip;
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_offer_reply),
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
