#pragma once

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
// with Unicast Flag = 0 shall be answered with a multicast OfferService.
// A fixed wall-clock emit offset leaves the reply window at an unknown
// cycle position, so under CPU contention a cyclic Offer can drift into it
// and be counted as a solicited reply — a false PASS. So the emit is
// CADENCE-RELATIVE (same as SD_BEHAVIOR_03): the SCXML waits into the main
// phase, observes one cyclic OfferService (the anchor), and enters
// `listening_offer_reply` on it; this trait emits the multicast Find
// (sd_flags 0x80, Reboot=1/Unicast=0) on that entry, and the reply window
// ends before the DUT's next cyclic (+2000 ms) — so the window sits between
// two cyclics and the verdict is deterministic. Unlike SD_BEHAVIOR_03 a
// multicast Find has no ½-cyclic rule, so the Find fires right on the anchor.
//
// Reference-stack note: upstream vsomeip 3.7.x IGNORES multicast Finds (per
// its own `service_discovery_impl.cpp::send_uni_or_multicast_offerservice`,
// citing SIP_SD_91), which left this case at
// `inconclusive_no_offer_after_multicast_find`. `patches/vsomeip/0002` answers
// such a Find with a multicast OfferService — the reading SOMEIPSD §6.7.5.2 /
// TR_SOMEIP_00423 carries, which TC8's Reference row for this case marks
// SHOULD — so the reference DUT now passes on the solicited reply. The Unicast
// Flag = 1 path is untouched by that patch.
//
// AUTOSAR reads the flag the other way and says so with a SHALL: in the current
// PRS the same requirement number is scoped to Unicast Flag = 1
// (PRS_SOMEIPSD_00423), and PRS_SOMEIPSD_00843 requires that entries with the
// flag set to 0 "shall not be answered with unicast but ignored". This case
// therefore asserts a TC8 requirement, not a universally agreed one.
//
// That branch is compile-gated on `ENABLE_TC8_ANSWER_MULTICAST_FIND`, default
// ON. A DUT built with it OFF keeps the upstream drop and lands this case back
// on its inconclusive terminal — expected for a consumer whose own
// specification mandates ignoring such a Find, not a harness regression (see
// README, "Declining a base-patch behaviour").
template <>
struct TestCaseTraits<cases::SdBehavior04SM>
    : SomeIpSdOnlyBase<cases::SdBehavior04SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_BEHAVIOR_04";
    static constexpr std::string_view kDescription =
        "Multicast Find (Unicast Flag = 0) → DUT replies with multicast OfferService";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        // Fire the multicast Find on entry to `listening_offer_reply`, which
        // the SCXML reaches on the observed anchor cyclic offer — so the whole
        // Find/reply window sits between two of the DUT's own offers. Captures
        // iface by value (the observer runs on the poll-loop thread long after
        // this returns).
        const std::string iface_owned(iface);
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_offer_reply),
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
