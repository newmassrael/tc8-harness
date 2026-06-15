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
// Stimulus schedules the multicast Find emit at +4040 ms — well past
// TOTAL_REP_INTV (~1.5 s) and the post-repetition rep4 emission at
// ~T_sd+3075 ms, so the DUT is fully in Main Phase when the Find
// arrives. The Find carries sd_flags = 0x80 (Reboot=1, Unicast=0).
//
// Note: vsomeip 3.7.1 IGNORES multicast Finds (per its own comment at
// `service_discovery_impl.cpp::send_uni_or_multicast_offerservice`,
// citing SIP_SD_91); a strict-spec DUT would emit a multicast solicited
// reply per SOMEIPSD §6.7.5.2 / TR_SOMEIP_00423 page 73. Tightened
// Phase 2 deadline (1500 ms) excludes the next Main-Phase cyclic at
// ~T_sd+6000 ms, so on vsomeip this test lands `fail_no_offer_after_
// multicast_find` (run-and-fail-by-design). CI grep filter handles
// the known deviation.
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
        scheduler.schedule(std::chrono::milliseconds(4040),
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
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdBehavior04SM, someipsrv_sd_behavior_04)
