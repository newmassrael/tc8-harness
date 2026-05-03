#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_behavior_04_sm.h"

namespace tc8::sce::cases {

using SdBehavior04SM =
    ::SCE::Generated::someipsrv_sd_behavior_04::someipsrv_sd_behavior_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.4.4 SOMEIPSRV_SD_BEHAVIOR_04: a multicast FindService
// with Unicast Flag = 0 shall be answered with multicast OfferService.
// Stimulus schedules the multicast Find emit at +2500 ms — past
// TOTAL_REP_INTV (~1.5 s) so the DUT is in Main Phase when the Find
// arrives. The Find carries sd_flags = 0x80 (Reboot=1, Unicast=0).
template <>
struct TestCaseTraits<cases::SdBehavior04SM>
    : SomeIpSdOnlyBase<cases::SdBehavior04SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_BEHAVIOR_04";
    static constexpr std::string_view kSpecSection = "5.1.5.4.4";
    static constexpr std::string_view kDescription =
        "Multicast Find (Unicast Flag = 0) → DUT replies with multicast OfferService";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        const std::string iface_owned(iface);
        scheduler.schedule(std::chrono::milliseconds(2500),
                           [iface_owned]() {
            // Multicast FindService with Unicast Flag = 0
            // (sd_flags = 0x80 — Reboot bit set, Unicast bit clear).
            ::tc8::stimulus::FindServiceParams p{};
            p.session_id = 0x0001;
            p.sd_flags = 0x80;
            const auto bytes = ::tc8::stimulus::buildFindService(p);
            ::tc8::stimulus::sendSdMulticast(bytes, iface_owned);
        });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                    return "pass";
            case State::Fail_offer_not_multicast:                return "fail:offer_dst_ip_not_multicast_after_multicast_find";
            case State::Fail_no_offer_after_multicast_find:      return "fail:no_offer_within_listen_window_after_multicast_find";
            default:                                             return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdBehavior04SM, someipsrv_sd_behavior_04)
